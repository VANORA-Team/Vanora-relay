package signal

import (
	"fmt"
	"strings"
)

// Channel identifies which Vanora site a relay node serves. The CN and global
// channels check relay entitlement against the site the account signed in on;
// a self-hosted channel belongs to the operator and skips that check.
type Channel string

const (
	// ChannelCN serves accounts signed in on the CN site.
	ChannelCN Channel = "cn"
	// ChannelGlobal serves accounts signed in on the global site.
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
// entitlement with a Vanora site. Self-hosted nodes do not.
func (c Channel) ChecksEntitlement() bool {
	return c == ChannelCN || c == ChannelGlobal
}
