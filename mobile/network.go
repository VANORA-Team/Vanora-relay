package mobile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"vanora-relay/adapter/account"
	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/pairnet"
	"vanora-relay/protocol"
)

type phoneNetwork struct {
	wake     chan struct{}
	children map[string]*Client
}

func (c *Client) startNetwork() {
	c.mesh = &phoneNetwork{make(chan struct{}, 1), make(map[string]*Client)}
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
	return p.Send(protocol.Encode(transport.NetworkFrame{Type: "pairnet.sync", Members: g.Snapshot()}), true)
}

func (c *Client) tellRemovedDesktop(p transport.Peer, group *pairnet.Group, id string) {
	roster := group.Snapshot()
	_ = p.Send(protocol.Encode(transport.NetworkFrame{Type: "pairnet.sync", Members: pairnet.Roster{group.Self(): roster[group.Self()], id: roster[id]}}), true)
}

func (c *Client) closeChild(id string) {
	if child := c.mesh.children[id]; child != nil {
		delete(c.mesh.children, id)
		child.Close()
	}
}

func (c *Client) closeChildren() {
	for id := range c.mesh.children {
		c.closeChild(id)
	}
}

func (c *Client) maintainNetwork() {
	ticker := time.NewTicker(12 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		case <-c.mesh.wake:
		}
		c.op.Lock()
		c.mu.Lock()
		group, primary, current := c.group, c.device, c.peer
		c.mu.Unlock()
		if (primary != "" || len(c.mesh.children) != 0) && group != nil {
			if current != nil {
				if !group.Allows(primary) {
					c.tellRemovedDesktop(current, group, primary)
				} else {
					_ = c.syncPeer(current, group)
				}
			}
			for id, child := range c.mesh.children {
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
					_ = c.syncPeer(p, group)
				}
			}
			for _, member := range group.Snapshot().Members() {
				if member.Role == "desktop" && member.ID != primary && c.mesh.children[member.ID] == nil && group.Allows(member.ID) {
					_, _ = c.openDesktop(group, member)
				}
			}
		}
		c.op.Unlock()
	}
}

func (c *Client) openDesktop(group *pairnet.Group, member pairnet.Member) (*Client, error) {
	child := newClient(c.url, c.source)
	child.child, child.mesh, child.scopeTarget = true, c.mesh, member.ID
	child.identity, child.book, child.lanKey, child.selfKey = c.identity, c.book, c.lanKey, c.selfKey
	c.mu.Lock()
	name := c.deviceName
	c.mu.Unlock()
	child.mu.Lock()
	child.deviceName = name
	child.mu.Unlock()
	c.mesh.children[member.ID] = child
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
	if err != nil || !group.Allows(member.ID) {
		c.closeChild(member.ID)
		if err == nil {
			err = pairnet.ErrRemoved
		}
		return nil, err
	}
	return child, nil
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
		c.op.Lock()
		for _, child := range c.mesh.children {
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
		c.op.Unlock()
	}
	signal(c.mesh.wake)
	return nil
}

func (c *Client) OpenNetworkDesktop(id string) (*Client, error) {
	c.op.Lock()
	defer c.op.Unlock()
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
	if child := c.mesh.children[id]; child != nil && child.ctx.Err() != context.Canceled {
		return child, nil
	}
	return c.openDesktop(group, member)
}
