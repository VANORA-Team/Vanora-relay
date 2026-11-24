package signal

import (
	"fmt"
	"strings"
)

// Channel identifies whether a relay node is an official Vanora site node or a
// user-hosted one. Official nodes accept identities and verify TURN entitlement
// exclusively for their own site; a self-hosted channel manages authentication
// locally with a node token and device pairing without official accounts.
type Channel string

const (
	// ChannelCN is an official node in the CN site.
	ChannelCN Channel = "cn"
	// ChannelGlobal is an official node in the GLOBAL site.
	ChannelGlobal Channel = "global"
	// ChannelSelf is a user-hosted relay that does not use official accounts
	// or site entitlement checks.
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

// ChecksEntitlement reports whether a node on this channel verifies site relay
// entitlement. Self-hosted nodes do not.
func (c Channel) ChecksEntitlement() bool {
	return c == ChannelCN || c == ChannelGlobal
}

// IsSelfHosted reports whether a node on this channel runs in account-free
// self-hosted pairing mode.
func (c Channel) IsSelfHosted() bool {
	return c == ChannelSelf
}
