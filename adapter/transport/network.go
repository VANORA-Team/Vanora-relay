package transport

import (
	"encoding/json"
	"sync"
	"time"

	"vanora-relay/internal/pairnet"
	"vanora-relay/protocol"
)

type NetworkFrame struct {
	Type    string         `json:"type"`
	Members pairnet.Roster `json:"members"`
}

type Removal struct {
	Type     string `json:"type"`
	Receiver bool   `json:"receiver,omitempty"`
	Epoch    uint64 `json:"epoch"`
}

type networkPeerSync struct {
	id   string
	wake chan struct{}
	done chan struct{}
}

type NetworkHandler struct {
	Handler
	Group      func() *pairnet.Group
	Device     func(Peer) string
	mu         sync.Mutex
	subscribed map[Peer]*networkPeerSync
	Changed    func()
}

func (h *NetworkHandler) AuthorityLost() {
	if observer, ok := h.Handler.(AuthorityObserver); ok {
		observer.AuthorityLost()
	}
}

func (h *NetworkHandler) AuthorityRestored() {
	if observer, ok := h.Handler.(AuthorityObserver); ok {
		observer.AuthorityRestored()
	}
}

func (h *NetworkHandler) Closed(p Peer) {
	h.mu.Lock()
	ps := h.subscribed[p]
	delete(h.subscribed, p)
	h.mu.Unlock()
	if ps != nil {
		close(ps.done)
	}
	h.Handler.Closed(p)
}

func (h *NetworkHandler) Message(p Peer, data []byte) {
	var header struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &header) != nil || header.Type != "pairnet.sync" {
		h.Handler.Message(p, data)
		return
	}
	group := h.Group()
	id := h.Device(p)
	var frame NetworkFrame
	if group == nil || !p.Allows(true) || len(data) > 2<<20 || json.Unmarshal(data, &frame) != nil {
		go p.Close()
		return
	}
	changed, err := group.Merge(id, frame.Members)
	if err != nil {
		go p.Close()
		return
	}
	h.mu.Lock()
	if h.subscribed == nil {
		h.subscribed = make(map[Peer]*networkPeerSync)
	}
	ps, subscribed := h.subscribed[p]
	if !subscribed {
		ps = &networkPeerSync{
			id:   id,
			wake: make(chan struct{}, 1),
			done: make(chan struct{}),
		}
		h.subscribed[p] = ps
		go h.peerLoop(p, ps)
	} else {
		ps.id = id
	}
	h.mu.Unlock()
	if changed || !subscribed {
		h.Broadcast()
	} else {
		select {
		case ps.wake <- struct{}{}:
		default:
		}
	}
}

func (h *NetworkHandler) peerLoop(p Peer, ps *networkPeerSync) {
	for {
		select {
		case <-ps.done:
			return
		case <-ps.wake:
			group := h.Group()
			if group == nil {
				continue
			}
			if !group.Allows(ps.id) {
				h.sendRemoval(group, p, ps.id)
				return
			}
			if err := p.Send(protocol.Encode(NetworkFrame{"pairnet.state", group.Snapshot()}), true); err != nil {
				go p.Close()
				return
			}
		}
	}
}

func (h *NetworkHandler) sendRemoval(group *pairnet.Group, p Peer, id string) {
	if sender, ok := p.(interface{ SendRemoval(Removal) error }); ok {
		target, _ := group.Get(id)
		receiver := !target.Active()
		if !receiver {
			target, _ = group.Get(group.Self())
		}
		_ = sender.SendRemoval(Removal{Type: "pairnet.removed", Receiver: receiver, Epoch: target.Epoch})
	}
	go p.Close()
}

func (h *NetworkHandler) Broadcast() {
	group := h.Group()
	if group == nil {
		return
	}
	h.mu.Lock()
	type target struct {
		peer Peer
		ps   *networkPeerSync
	}
	peers := make([]target, 0, len(h.subscribed))
	for p, ps := range h.subscribed {
		peers = append(peers, target{peer: p, ps: ps})
	}
	h.mu.Unlock()

	var removedWG sync.WaitGroup
	for _, t := range peers {
		if !group.Allows(t.ps.id) {
			removedWG.Add(1)
			go func(p Peer, id string) {
				defer removedWG.Done()
				h.sendRemoval(group, p, id)
			}(t.peer, t.ps.id)
			continue
		}
		select {
		case t.ps.wake <- struct{}{}:
		default:
		}
	}
	// Give revoked peers a brief bounded window to receive pairnet.removed
	// before Changed() tears down their transport, without letting a stalled
	// peer block Broadcast for seconds.
	done := make(chan struct{})
	go func() {
		removedWG.Wait()
		close(done)
	}()
	timer := time.NewTimer(500 * time.Millisecond)
	select {
	case <-done:
	case <-timer.C:
	}
	timer.Stop()
	if h.Changed != nil {
		h.Changed()
	}
}
