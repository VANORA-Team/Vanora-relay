// Package transport defines the small contract between the relay's WebRTC
// endpoint and the local desktop integration.
//
// A transport implementation owns connections and access policy. The desktop
// handler only ever sees an opaque Peer: it cannot discover addresses, store
// credentials, or create connections of its own.
package transport

// Peer is one authenticated remote device connection.
//
// UserID returns the stable identity verified by the relay. Allows reports
// whether the supplied access class is currently authorized for this peer.
// requiresOnline is true for tool-capable work and false for read-only
// delivery. Send must reject delivery when the same check would fail; both
// checks are deliberately repeated at the transport boundary.
//
// Send may be called from different goroutines, but a Handler serializes
// messages for each Peer, so implementations may also assume ordered calls for
// one peer. Close is called by the handler when it revokes a peer.
type Peer interface {
	UserID() string
	Allows(requiresOnline bool) bool
	Send(data []byte, requiresOnline bool) error
	Close()
}

// Handler receives lifecycle and business messages for connected peers.
//
// Open, Message, and Closed for one peer are serialized by the caller. They
// may run concurrently with calls for other peers. Implementations must not
// retain the Peer after Closed.
type Handler interface {
	Open(peer Peer)
	Message(peer Peer, data []byte)
	Closed(peer Peer)
}
