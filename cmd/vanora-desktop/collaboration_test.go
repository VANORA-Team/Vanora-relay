package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"vanora-relay/adapter/desktop"
	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/remote"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/internal/signal"
	"vanora-relay/mobile"
)

func TestSidecarCollaborationCommandsAndPairnetStatusVisibility(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	sessionFile := filepath.Join(dir, "sess.jsonl")
	header, _ := json.Marshal(map[string]any{
		"type":      "session",
		"version":   3,
		"id":        "sidecar-sess",
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"cwd":       work,
	})
	if err := os.WriteFile(sessionFile, append(header, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	svc, err := desktop.New(&desktop.Config{
		Executable: exe,
		Sessions: []desktop.SessionConfig{{
			ID:                 "shared",
			Title:              "Shared Room",
			WorkingDir:         work,
			SessionFile:        sessionFile,
			Owner:              desktop.LocalOwner,
			LANAccess:          true,
			SelfAccess:         true,
			Tools:              []string{"read"},
			AllowGuestRequests: true,
		}},
	}, filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	// Start LAN server wired to real desktop.Adapter and sidecar accessManager.
	lanSrv := requireNetwork(lan.OpenServer(&memVault{}, svc))
	defer lanSrv.Stop()
	svc.SetLANAuthority(lanSrv.Allows)
	if err := lanSrv.Listen(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	am := &accessManager{
		ctx:     ctx,
		name:    "HostPC",
		service: svc,
		local:   lanSrv,
		emitter: &jsonEmitter{out: &stdout},
		slots:   make(map[string]*officialSlot),
	}
	am.initRemote()

	// Connect a read-only mobile LAN client, open session, watch presence, and submit a guest request.
	_, readInv, err := lanSrv.InvitePairing(lan.Read)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := mobile.NewLANClient(&memVault{})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := reader.Pair(readInv.Code, "", "", "GuestPhone"); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.OpenSession("shared"); err != nil {
		t.Fatal(err)
	}
	presJSON, err := reader.SessionPresence("shared", true)
	if err != nil || !strings.Contains(presJSON, `"role":"viewer"`) {
		t.Fatalf("mobile SessionPresence = (%s, %v)", presJSON, err)
	}
	gRes, err := reader.SubmitGuestRequest("shared", mobile.NewRequestID(), "Can we refactor this?")
	if err != nil || !strings.Contains(gRes, `"status":"pending"`) {
		t.Fatalf("mobile SubmitGuestRequest = (%s, %v)", gRes, err)
	}

	// Sidecar session.guest.list returns the pending guest request.
	stdout.Reset()
	am.command(accessCommand{Type: "session.guest.list", RequestID: "gl-1", SessionID: "shared"})
	var glResp struct {
		Type     string                     `json:"type"`
		Requests []desktop.GuestRequestInfo `json:"requests"`
	}
	if err := json.NewDecoder(&stdout).Decode(&glResp); err != nil || glResp.Type != "session.guest.list" || len(glResp.Requests) != 1 {
		t.Fatalf("session.guest.list = %+v (%v) raw=%s", glResp, err, stdout.String())
	}

	// Sidecar session.collaborators returns active participants and pending guests.
	stdout.Reset()
	am.command(accessCommand{Type: "session.collaborators", RequestID: "sc-1", SessionID: "shared"})
	var scResp struct {
		Type     string                         `json:"type"`
		Sessions []desktop.SessionCollaboration `json:"sessions"`
	}
	if err := json.NewDecoder(&stdout).Decode(&scResp); err != nil || scResp.Type != "session.collaborators" || len(scResp.Sessions) != 1 {
		t.Fatalf("session.collaborators = %+v (%v) raw=%s", scResp, err, stdout.String())
	}
	if len(scResp.Sessions[0].Participants) != 1 || len(scResp.Sessions[0].PendingGuest) != 1 {
		t.Fatalf("unexpected collaboration snapshot: %+v", scResp.Sessions[0])
	}

	// Sidecar dismisses the guest request.
	stdout.Reset()
	am.command(accessCommand{
		Type:           "session.guest.respond",
		RequestID:      "gr-1",
		SessionID:      "shared",
		GuestRequestID: glResp.Requests[0].GuestRequestID,
		Action:         "dismiss",
	})
	var grResp map[string]any
	if err := json.NewDecoder(&stdout).Decode(&grResp); err != nil || grResp["type"] != "session.guest.responded" || grResp["status"] != "dismissed" {
		t.Fatalf("session.guest.respond = %+v (%v)", grResp, err)
	}

	// Mobile CloseSession cleanly removes reader from participants.
	if err := reader.CloseSession("shared"); err != nil {
		t.Fatal(err)
	}
	if snap := svc.CollaborationSnapshot("shared"); len(snap[0].Participants) != 0 {
		t.Fatalf("expected 0 participants after CloseSession, got %+v", snap[0].Participants)
	}

	// Verify indirect pairnet members appear in LAN and Self-Relay Status().Clients!
	t.Run("indirect pairnet member visible in lan and self Status", func(t *testing.T) {
		for _, ch := range []string{"lan", "self"} {
			t.Run(ch, func(t *testing.T) {
				var sigURL string
				selfTok := strings.Repeat("status-pair-", 4)
				if ch == "self" {
					hub := signal.NewSelfHosted(selfTok, directICE{})
					go hub.Run(ctx)
					srv := httptest.NewServer(hub)
					t.Cleanup(srv.Close)
					sigURL = "ws" + strings.TrimPrefix(srv.URL, "http")
				}
				alpha := newPCNode(t, ctx, ch, "Alpha", sigURL, selfTok, "", "", "", &memVault{})
				beta := newPCNode(t, ctx, ch, "Beta", sigURL, selfTok, "", "", "", &memVault{})

				invA := alpha.invite("control")
				_, err := beta.manager.remoteManager().Pair(ctx, remote.PairOptions{
					Channel:   ch,
					Input:     invA.Code,
					SignalURL: sigURL,
				})
				if err != nil {
					t.Fatalf("Beta pair Alpha: %v", err)
				}
				awaitNetwork(t, func() bool {
					if ch == "lan" {
						return slices.ContainsFunc(beta.manager.local.Status().Clients, func(c lan.ClientInfo) bool {
							return c.ID == alpha.selfID() && c.Access == lan.Read
						})
					}
					return slices.ContainsFunc(beta.manager.selfServer.Status().Clients, func(c selfrelay.ClientInfo) bool {
						return c.ID == alpha.selfID() && c.Access == selfrelay.Read
					})
				})
			})
		}
	})
}
