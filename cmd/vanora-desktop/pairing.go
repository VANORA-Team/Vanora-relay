package main

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"vanora-relay/adapter/account"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/pairing"
	"vanora-relay/internal/pairnet"
	"vanora-relay/protocol"
)

type inviteInfo struct {
	ID      string    `json:"id"`
	Expires time.Time `json:"expires_at"`
}

type officialInvite struct {
	inviteInfo
	target pairing.Official
	retire func()
}

func (s *officialSlot) pruneLocked() {
	now := time.Now()
	for id, inv := range s.invites {
		if !now.Before(inv.Expires) {
			delete(s.invites, id)
		}
	}
}

func (s *officialSlot) invitations() []inviteInfo {
	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	s.pruneLocked()
	out := make([]inviteInfo, 0, len(s.invites))
	for _, inv := range s.invites {
		out = append(out, inv.inviteInfo)
	}
	return out
}

func (s *officialSlot) invite(ctx context.Context) (inviteInfo, pairing.Display, error) {
	socket := s.socket.Load()
	if socket == nil || !s.online.Load() {
		return inviteInfo{}, pairing.Display{}, errors.New("official relay is offline")
	}
	creds, _, err := s.account.Current(ctx)
	if err != nil {
		return inviteInfo{}, pairing.Display{}, err
	}
	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	s.pruneLocked()
	if len(s.invites) >= 32 || len(s.account.Pairings()) >= 128 {
		return inviteInfo{}, pairing.Display{}, errors.New("pairing limit reached")
	}
	target := pairing.NewOfficial(s.name, s.url, creds.DeviceID(), creds.UserID(), creds.PublicKey())
	info := inviteInfo{protocol.NewID(), time.Now().UTC().Add(pairing.Lifetime)}
	display, retire, err := pairing.Present(ctx, s.url, target.Device, socket.PairingTicket(), target.Link(), info.Expires)
	if err != nil {
		return inviteInfo{}, pairing.Display{}, err
	}
	if s.invites == nil {
		s.invites = make(map[string]officialInvite)
	}
	s.invites[info.ID] = officialInvite{info, target, retire}
	return info, display, nil
}

func (s *officialSlot) authorize(connection string, remote identity.Principal, role, name string, proof []byte) bool {
	if remote.DeviceID == s.account.DeviceID() {
		return false
	}
	peer := account.PeerBinding{Owner: remote.RemoteUserID(), Pin: base64.RawURLEncoding.EncodeToString(remote.PublicKey)}
	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	s.pruneLocked()
	group, local := s.account.PairingIdentity(s.url, "desktop")
	if group == nil {
		return false
	}
	local.Name = s.desktopName
	effectiveRole := role
	if effectiveRole == "" {
		if known, ok := group.Get(remote.DeviceID); ok && (known.Role == "mobile" || known.Role == "desktop") {
			effectiveRole = known.Role
		} else {
			effectiveRole = "mobile"
		}
	}
	if effectiveRole != "mobile" && effectiveRole != "desktop" {
		return false
	}
	member := pairnet.Member{ID: remote.DeviceID, Pin: peer.Pin, Owner: peer.Owner, Role: effectiveRole, Name: name}
	if len(proof) != 0 {
		for id, inv := range s.invites {
			expected, err := identity.SelfPairProof(inv.target.Token, connection, remote.PublicKey, inv.target.Pin)
			if err == nil && hmac.Equal(expected, proof) {
				if group.Admit(local, member, true) != nil {
					return false
				}
				if s.account.BindNetworkPeer(group, remote.DeviceID, peer) != nil {
					_ = group.Remove(remote.DeviceID)
					return false
				}
				delete(s.invites, id)
				inv.retire()
				return true
			}
		}
		return false
	}
	if known, ok := group.Get(member.ID); ok {
		return known.Pin == member.Pin && known.Owner == member.Owner &&
			(known.Role == "mobile" || known.Role == "desktop") &&
			(role == "" || known.Role == role) && group.Allows(member.ID)
	}
	bound, ok := s.account.PairedPeer(remote.DeviceID)
	self, _ := group.Get(local.ID)
	return ok && bound == peer && self.Epoch <= 1 && group.Admit(local, member, false) == nil
}

func (s *officialSlot) authorizeTunnel(_ string, remote identity.Principal, role, _ string, proof []byte) bool {
	if len(proof) != 0 || remote.DeviceID == s.account.DeviceID() {
		return false
	}
	group, local := s.account.PairingIdentity(s.url, "desktop")
	if group == nil {
		return false
	}
	pin := base64.RawURLEncoding.EncodeToString(remote.PublicKey)
	owner := remote.RemoteUserID()
	if known, ok := group.Get(remote.DeviceID); ok {
		return known.Pin == pin && known.Owner == owner && (role == "" || known.Role == role) && group.Allows(known.ID)
	}
	bound, ok := s.account.PairedPeer(remote.DeviceID)
	self, _ := group.Get(local.ID)
	return ok && bound.Pin == pin && bound.Owner == owner && self.Epoch <= 1 && (role == "" || role == "mobile")
}

func (s *officialSlot) revokeInvite(id string) error {
	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	inv, ok := s.invites[id]
	if !ok {
		return pairing.ErrInvalid
	}
	delete(s.invites, id)
	inv.retire()
	return nil
}

func (s *officialSlot) clearInvites() {
	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	clear(s.invites)
}

func (s *officialSlot) revokeClients(id string, all bool) error {
	if !all && id == "" {
		return errors.New("client ID required")
	}
	if all {
		id = ""
	}
	s.pairMu.Lock()
	var err error
	group, _ := s.account.PairingIdentity(s.url, "desktop")
	var ids []string
	if group != nil {
		for key, member := range group.Snapshot() {
			if key != group.Self() && (member.Role == "mobile" || member.Role == "desktop") && member.Active() && (all || key == id) {
				ids = append(ids, key)
			}
		}
		if len(ids) > 0 {
			err = group.Remove(ids...)
		}
	}
	if _, direct := s.account.PairedPeer(id); err == nil && (all || direct || len(ids) == 0) {
		err = s.account.UnbindPeer(id)
	}
	if err == nil && all {
		for key, inv := range s.invites {
			delete(s.invites, key)
			inv.retire()
		}
	}
	s.pairMu.Unlock()
	if err == nil {
		if socket := s.socket.Load(); socket != nil {
			socket.RevokeDevice(id)
			socket.NetworkChanged()
		}
	}
	return err
}

func (m *accessManager) createRelayInvite(cmd accessCommand, result map[string]any) error {
	if (cmd.Channel != "" && cmd.Channel != m.activeChannel) || (strings.HasPrefix(cmd.Type, "access.self.") && m.activeChannel != "self") {
		return errors.New("inactive relay channel")
	}
	var display pairing.Display
	var err error
	if m.activeChannel == "self" && m.selfServer != nil {
		level := cmd.Access
		if level == "" {
			level = selfrelay.Read
		}
		result["invitation"], display, err = m.selfServer.InvitePairing(m.ctx, level, cmd.IncludeToken == nil || *cmd.IncludeToken)
	} else if slot := m.activeSlot; slot != nil {
		if cmd.Access != "" {
			return errors.New("official relay permissions are configured by the desktop resource ACL")
		}
		result["invitation"], display, err = slot.invite(m.ctx)
	} else {
		return errors.New("relay is disabled")
	}
	if err != nil {
		return err
	}
	result["type"] = strings.TrimSuffix(cmd.Type, ".create") + ".created"
	result["channel"] = m.activeChannel
	result["link"], result["pairing_code"], result["qr_code"] = display.Link, display.Code, display.QR
	return nil
}
