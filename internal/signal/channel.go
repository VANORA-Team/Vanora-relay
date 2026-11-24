package signal

import (
	"fmt"
	"strings"
)

// Channel identifies whether a relay node is an official Vanora node or a
// user-hosted one. Official nodes verify relay entitlement with the site the
// account signed in on; a self-hosted channel belongs to the operator and skips
// that check.
type Channel string

const (
	// ChannelCN is an official node in the CN region.
	ChannelCN Channel = "cn"
	// ChannelGlobal is an official node in the GLOBAL region.
	ChannelGlobal Channel = "global"
	// ChannelSelf is a user-hosted relay that does not check relay
	// entitlement.
	ChannelSelf Channel = "self"
)

// ParseChannel validates a RELAY_CHANNEL value. An empty value selects
// ChannelCN so existing CN deployments keep working unchanged.
func ParseChannel(value string) (Channel, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "cn":
		return ChannelCN, nil
	case "global":
		return ChannelGlobal, nil
	case "self":
		return ChannelSelf, nil
	default:
		return "", fmt.Errorf("unknown relay channel %q (want cn, global or self)", value)
	}
}

// ChecksEntitlement reports whether a node on this channel verifies relay
// entitlement. Self-hosted nodes do not.
func (c Channel) ChecksEntitlement() bool {
	return c == ChannelCN || c == ChannelGlobal
}
