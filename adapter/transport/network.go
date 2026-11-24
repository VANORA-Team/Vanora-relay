package transport

import (
	"encoding/json"
	"sync"

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

type NetworkHandler struct {
	Handler
	Group      func() *pairnet.Group
	Device     func(Peer) string
	mu         sync.Mutex
	subscribed map[Peer]string
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
	delete(h.subscribed, p)
	h.mu.Unlock()
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
		h.subscribed = make(map[Peer]string)
	}
	_, subscribed := h.subscribed[p]
	h.subscribed[p] = id
	h.mu.Unlock()
	if changed || !subscribed {
		h.Broadcast()
	} else {
		h.send(group, p, id)
	}
}

func (h *NetworkHandler) send(group *pairnet.Group, p Peer, id string) {
	if !group.Allows(id) {
		if sender, ok := p.(interface{ SendRemoval(Removal) error }); ok {
			target, _ := group.Get(id)
			receiver := !target.Active()
			if !receiver {
				target, _ = group.Get(group.Self())
			}
			_ = sender.SendRemoval(Removal{Type: "pairnet.removed", Receiver: receiver, Epoch: target.Epoch})
		}
		go p.Close()
		return
	}
	if err := p.Send(protocol.Encode(NetworkFrame{"pairnet.state", group.Snapshot()}), true); err != nil {
		go p.Close()
	}
}

func (h *NetworkHandler) Broadcast() {
	group := h.Group()
	if group == nil {
		return
	}
	h.mu.Lock()
	peers := make(map[Peer]string, len(h.subscribed))
	for p, id := range h.subscribed {
		peers[p] = id
	}
	h.mu.Unlock()
	for p, id := range peers {
		h.send(group, p, id)
	}
	if h.Changed != nil {
		h.Changed()
	}
}
