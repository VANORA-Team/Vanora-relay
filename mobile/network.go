package mobile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"sync"
	"time"

	"vanora-relay/adapter/account"
	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/pairnet"
	"vanora-relay/protocol"
)

type childDialBackoff struct {
	failures int
	until    time.Time
}

type childOpenAttempt struct {
	done  chan struct{}
	child *Client
	err   error
}

type phoneNetwork struct {
	mu       sync.Mutex
	wake     chan struct{}
	children map[string]*Client
	opening  map[string]*childOpenAttempt
	synced   map[string]pairnet.Roster
	backoff  map[string]childDialBackoff
}

func (c *Client) startNetwork() {
	c.mesh = &phoneNetwork{
		wake:     make(chan struct{}, 1),
		children: make(map[string]*Client),
		opening:  make(map[string]*childOpenAttempt),
		synced:   make(map[string]pairnet.Roster),
		backoff:  make(map[string]childDialBackoff),
	}
	switch {
	case c.identity != nil:
		c.group, _ = c.identity.PairingIdentity(c.url, "mobile")
	case c.lanKey != "":
		c.group = c.book.Group("lan", lan.ClientID(c.lanKey))
	case c.selfKey != "":
		profile := c.book.Profile()
		key, _ := selfrelay.ClientIdentity(c.selfKey)
		if profile.Service != "" {
			c.group = c.book.Group(profile.Service, key)
		}
	}
	go c.maintainNetwork()
}

func (c *Client) desktopBinding(id string) (account.PeerBinding, bool) {
	group, _ := c.identity.PairingIdentity(c.url, "mobile")
	if group != nil {
		if member, known := group.Get(id); known {
			return account.PeerBinding{Owner: member.Owner, Pin: member.Pin}, member.Role == "desktop" && group.Allows(id)
		}
	}
	return c.identity.PairedPeer(id)
}

func (c *Client) networkBinding(id string) (*pairnet.Group, pairnet.Member, pairnet.Member, bool) {
	var group *pairnet.Group
	var local pairnet.Member
	remote := pairnet.Member{ID: id, Pin: id, Role: "desktop"}
	invited := false
	c.mu.Lock()
	lanTarget, lanName := c.lanTarget, c.lanName
	selfTarget, selfName := c.selfTarget, c.selfName
	officialInvite, deviceName := c.officialInvite, c.deviceName
	c.mu.Unlock()
	switch {
	case lanTarget != nil:
		key := lan.ClientID(c.lanKey)
		local = pairnet.Member{ID: key, Pin: key, Role: "mobile", Name: lanName}
		group = c.book.Group("lan", key)
		remote.Address = lanTarget.Address
		invited = lanTarget.Token != ""
	case selfTarget != nil:
		key, pin := selfrelay.ClientIdentity(c.selfKey)
		local = pairnet.Member{ID: key, Pin: pin, Role: "mobile", Name: selfName}
		group = c.book.Group(selfTarget.SignalURL, key)
		invited = selfTarget.Pair != ""
	case c.identity != nil:
		group, local = c.identity.PairingIdentity(c.url, "mobile")
		local.Name = deviceName
		if officialInvite != nil {
			remote.Owner, remote.Pin = officialInvite.Owner, base64.RawURLEncoding.EncodeToString(officialInvite.Pin)
		} else {
			peer, _ := c.desktopBinding(id)
			remote.Owner, remote.Pin = peer.Owner, peer.Pin
		}
	}
	return group, local, remote, invited
}

func (c *Client) syncPeer(p transport.Peer, g *pairnet.Group) error {
	snap := g.Snapshot()
	c.mu.Lock()
	if c.peer == p && maps.Equal(c.lastSynced, snap) {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()
	if err := p.Send(protocol.Encode(transport.NetworkFrame{Type: "pairnet.sync", Members: snap}), true); err != nil {
		return err
	}
	c.mu.Lock()
	if c.peer == p {
		c.lastSynced = snap
	}
	device := c.device
	c.mu.Unlock()
	if c.mesh != nil && device != "" {
		c.mesh.mu.Lock()
		c.mesh.synced[device] = snap
		c.mesh.mu.Unlock()
	}
	return nil
}

func (c *Client) tellRemovedDesktop(p transport.Peer, group *pairnet.Group, id string) {
	roster := group.Snapshot()
	_ = p.Send(protocol.Encode(transport.NetworkFrame{Type: "pairnet.sync", Members: pairnet.Roster{group.Self(): roster[group.Self()], id: roster[id]}}), true)
}

func (c *Client) closeChild(id string) {
	c.mesh.mu.Lock()
	child := c.mesh.children[id]
	delete(c.mesh.children, id)
	c.mesh.mu.Unlock()
	if child != nil {
		child.Close()
	}
}

func (c *Client) closeChildren() {
	c.mesh.mu.Lock()
	children := make([]*Client, 0, len(c.mesh.children))
	for id, child := range c.mesh.children {
		children = append(children, child)
		delete(c.mesh.children, id)
	}
	c.mesh.mu.Unlock()
	for _, child := range children {
		child.Close()
	}
}

func (c *Client) maintainNetwork() {
	ticker := time.NewTicker(12 * time.Second)
	defer ticker.Stop()
	for {
		fromWake := false
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if c.background.Load() {
				continue
			}
		case <-c.mesh.wake:
			fromWake = true
		}
		c.mu.Lock()
		group, primary, current := c.group, c.device, c.peer
		c.mu.Unlock()
		if group == nil {
			continue
		}
		c.mesh.mu.Lock()
		hasChildren := len(c.mesh.children) != 0
		c.mesh.mu.Unlock()
		if primary == "" && !hasChildren {
			continue
		}
		snap := group.Snapshot()
		if current != nil {
			if !group.Allows(primary) {
				c.tellRemovedDesktop(current, group, primary)
			} else {
				_ = c.syncPeer(current, group)
			}
		}

		c.mesh.mu.Lock()
		children := make(map[string]*Client, len(c.mesh.children))
		for id, child := range c.mesh.children {
			children[id] = child
		}
		c.mesh.mu.Unlock()

		for id, child := range children {
			if child.ctx.Err() != nil {
				c.closeChild(id)
				continue
			}
			child.mu.Lock()
			p := child.peer
			child.mu.Unlock()
			if !group.Allows(id) {
				if p != nil {
					c.tellRemovedDesktop(p, group, id)
				} else {
					c.closeChild(id)
				}
				continue
			}
			if p != nil {
				_ = child.syncPeer(p, group)
			}
		}

		// Propagate unsynced roster updates to other desktops off c.op.Lock so
		// unreachable desktops never block primary user operations and back off
		// exponentially instead of re-dialing every 12 seconds.
		now := time.Now()
		for _, member := range snap.Members() {
			if member.Role != "desktop" || member.ID == primary || !group.Allows(member.ID) {
				continue
			}
			c.mesh.mu.Lock()
			alreadyOpen := c.mesh.children[member.ID] != nil
			inFlight := c.mesh.opening[member.ID] != nil
			synced := maps.Equal(c.mesh.synced[member.ID], snap)
			bo := c.mesh.backoff[member.ID]
			if alreadyOpen || inFlight || synced || (!fromWake && now.Before(bo.until)) {
				c.mesh.mu.Unlock()
				continue
			}
			c.mesh.mu.Unlock()
			go func(m pairnet.Member, targetSnap pairnet.Roster) {
				_, err := c.openDesktop(group, m)
				c.mesh.mu.Lock()
				if err == nil {
					delete(c.mesh.backoff, m.ID)
					c.mesh.synced[m.ID] = targetSnap
				} else {
					prev := c.mesh.backoff[m.ID]
					failures := min(prev.failures+1, 6)
					delay := min(5*time.Minute, 15*time.Second*time.Duration(1<<(failures-1)))
					c.mesh.backoff[m.ID] = childDialBackoff{failures: failures, until: time.Now().Add(delay)}
				}
				c.mesh.mu.Unlock()
			}(member, snap)
		}
	}
}

func (c *Client) openDesktop(group *pairnet.Group, member pairnet.Member) (*Client, error) {
	c.mesh.mu.Lock()
	if existing := c.mesh.children[member.ID]; existing != nil && existing.ctx.Err() == nil {
		c.mesh.mu.Unlock()
		return existing, nil
	}
	if attempt := c.mesh.opening[member.ID]; attempt != nil {
		c.mesh.mu.Unlock()
		select {
		case <-attempt.done:
			return attempt.child, attempt.err
		case <-c.ctx.Done():
			return nil, c.ctx.Err()
		}
	}
	attempt := &childOpenAttempt{done: make(chan struct{})}
	c.mesh.opening[member.ID] = attempt
	c.mesh.mu.Unlock()

	child := newClient(c.url, c.source)
	child.child, child.mesh, child.scopeTarget = true, c.mesh, member.ID
	child.identity, child.book, child.lanKey, child.selfKey = c.identity, c.book, c.lanKey, c.selfKey
	c.mu.Lock()
	name, channel := c.deviceName, c.channel
	c.mu.Unlock()
	child.mu.Lock()
	child.deviceName = name
	child.channel = channel
	child.tunnel = c.tunnel
	child.mu.Unlock()

	var err error
	switch {
	case c.lanKey != "":
		target := lan.Target{Pin: member.Pin, Address: member.Address}
		err = child.ConnectLAN(target.Link(), c.book.Profile().Name)
	case c.selfKey != "":
		profile := c.book.Profile()
		target := selfrelay.Target{Pin: member.Pin, SignalURL: profile.Service, Token: profile.Token}
		err = child.ConnectSelfRelay(target.Link(), profile.Name)
	default:
		err = child.Connect(member.ID, member.Owner)
	}
	if err == nil && !group.Allows(member.ID) {
		err = pairnet.ErrRemoved
	}
	if err == nil && c.ctx.Err() != nil {
		err = c.ctx.Err()
	}

	var closeChild bool
	c.mesh.mu.Lock()
	delete(c.mesh.opening, member.ID)
	if err != nil {
		closeChild = true
		attempt.err = err
	} else {
		c.mu.Lock()
		isPrimary := c.device == member.ID
		c.mu.Unlock()
		if isPrimary {
			closeChild = true
			attempt.child = c
		} else if existing := c.mesh.children[member.ID]; existing != nil && existing.ctx.Err() == nil {
			closeChild = true
			attempt.child = existing
		} else {
			c.mesh.children[member.ID] = child
			attempt.child = child
		}
	}
	close(attempt.done)
	c.mesh.mu.Unlock()
	if closeChild {
		child.Close()
	}
	return attempt.child, attempt.err
}

func (c *Client) PairingNetwork() (string, error) {
	c.mu.Lock()
	group := c.group
	c.mu.Unlock()
	if group == nil || !group.Allows(group.Self()) {
		return "[]", nil
	}
	raw, err := json.Marshal(group.Snapshot().Members())
	return string(raw), err
}

func (c *Client) RemoveNetworkDevice(id string) error {
	c.mu.Lock()
	group, p, desktop := c.group, c.peer, c.device
	c.mu.Unlock()
	if group == nil {
		return errors.New("no pairing network")
	}
	if err := group.Remove(id); err != nil {
		return err
	}
	if p != nil {
		if group.Allows(desktop) {
			_ = c.syncPeer(p, group)
		} else {
			c.tellRemovedDesktop(p, group, desktop)
		}
	}
	if !c.child {
		c.mesh.mu.Lock()
		children := make([]*Client, 0, len(c.mesh.children))
		for _, child := range c.mesh.children {
			children = append(children, child)
		}
		c.mesh.mu.Unlock()
		for _, child := range children {
			child.mu.Lock()
			other := child.peer
			child.mu.Unlock()
			if other != nil {
				if group.Allows(child.scopeTarget) {
					_ = child.syncPeer(other, group)
				} else {
					child.tellRemovedDesktop(other, group, child.scopeTarget)
				}
			}
		}
	}
	signal(c.mesh.wake)
	return nil
}

func (c *Client) OpenNetworkDesktop(id string) (*Client, error) {
	c.mu.Lock()
	group, primary := c.group, c.device
	c.mu.Unlock()
	if group == nil || !group.Allows(id) {
		return nil, pairnet.ErrRemoved
	}
	member, _ := group.Get(id)
	if member.Role != "desktop" {
		return nil, errors.New("desktop required")
	}
	if id == primary {
		return c, nil
	}
	if c.child {
		return nil, errors.New("open desktops on the main client")
	}
	c.mesh.mu.Lock()
	child := c.mesh.children[id]
	c.mesh.mu.Unlock()
	if child != nil && child.ctx.Err() != context.Canceled {
		return child, nil
	}
	return c.openDesktop(group, member)
}
