package mobile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vanora-relay/adapter/desktop"
	"vanora-relay/adapter/lan"
)

func TestMobileCollaborationPresenceQueueAndGuestWorkflow(t *testing.T) {
	t.Setenv("VANORA_MOBILE_FAKE_CLI", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dir := t.TempDir()
	executable, err := os.Executable()
	must(t, err)
	sessionFile := filepath.Join(dir, "collab.jsonl")
	writeJSON(t, sessionFile, map[string]any{
		"type":      "session",
		"version":   3,
		"id":        "collab-sess",
		"timestamp": "2026-01-01T00:00:00Z",
		"cwd":       dir,
	})
	service, err := desktop.New(&desktop.Config{
		Executable: executable,
		Sessions: []desktop.SessionConfig{{
			ID:                 "collab",
			Title:              "Team Room",
			WorkingDir:         dir,
			SessionFile:        sessionFile,
			Owner:              "local",
			LANAccess:          true,
			Tools:              []string{"read", "bash"},
			ShowThinking:       true,
			ShowTools:          true,
			ApprovalPolicy:     "remote",
			AllowGuestRequests: true,
		}},
	}, filepath.Join(dir, "state"))
	must(t, err)
	defer service.Close()

	lanSrv, err := lan.OpenServer(&lanTestStore{}, service)
	must(t, err)
	must(t, lanSrv.Listen(ctx, "127.0.0.1:0"))
	defer lanSrv.Stop()
	service.SetLANAuthority(lanSrv.Allows)

	_, ctrlLink, err := lanSrv.Invite(lan.Control)
	must(t, err)
	_, viewLink, err := lanSrv.Invite(lan.Read)
	must(t, err)

	ctrl, err := NewLANClient(&lanTestStore{})
	must(t, err)
	defer ctrl.Close()
	must(t, ctrl.Pair(ctrlLink, "", "", "ControllerPhone"))

	viewer, err := NewLANClient(&lanTestStore{})
	must(t, err)
	defer viewer.Close()
	must(t, viewer.Pair(viewLink, "", "", "ViewerPhone"))

	// Controller opens session and watches presence.
	openJSON, err := ctrl.OpenSession("collab")
	must(t, err)
	var snap struct {
		LastSeq      int64 `json:"last_seq"`
		Participants []struct {
			UserID string `json:"user_id"`
			Role   string `json:"role"`
		} `json:"participants"`
	}
	must(t, json.Unmarshal([]byte(openJSON), &snap))
	if len(snap.Participants) != 1 || snap.Participants[0].Role != "controller" {
		t.Fatalf("unexpected initial participants: %s", openJSON)
	}
	presJSON, err := ctrl.SessionPresence("collab", true)
	must(t, err)
	if !strings.Contains(presJSON, `"watching":true`) {
		t.Fatalf("expected watching=true from SessionPresence: %s", presJSON)
	}

	// Viewer opens session -> Controller receives ephemeral presence.updated (seq=0) with 2 participants.
	_, err = viewer.OpenSession("collab")
	must(t, err)
	waitForEvent := func(c *Client, pred func(ev map[string]any) bool) map[string]any {
		t.Helper()
		for {
			if ctx.Err() != nil {
				t.Fatal("timed out waiting for expected mobile event")
			}
			raw, err := c.NextEvent(150)
			must(t, err)
			if raw == "" {
				continue
			}
			var ev map[string]any
			must(t, json.Unmarshal([]byte(raw), &ev))
			if seqF, ok := ev["seq"].(float64); ok && int64(seqF) > 0 {
				if sid, _ := ev["session_id"].(string); sid != "" {
					must(t, c.Acknowledge(sid, int64(seqF)))
				}
			}
			if pred(ev) {
				return ev
			}
		}
	}
	presEv := waitForEvent(ctrl, func(ev map[string]any) bool {
		if ev["kind"] != "presence.updated" {
			return false
		}
		data, _ := ev["data"].(map[string]any)
		parts, _ := data["participants"].([]any)
		return len(parts) == 2
	})
	if seqF, _ := presEv["seq"].(float64); seqF != 0 {
		t.Fatalf("presence.updated should be ephemeral (seq=0), got %v", presEv)
	}

	// Start run 1 -> fake CLI pauses at approval dialog.
	run1JSON, err := ctrl.StartRun("collab", NewRequestID(), "first task")
	must(t, err)
	var run1 struct {
		RunID string `json:"run_id"`
	}
	must(t, json.Unmarshal([]byte(run1JSON), &run1))
	ui1Ev := waitForEvent(ctrl, func(ev map[string]any) bool {
		return ev["kind"] == "ui.request" && ev["run_id"] == run1.RunID
	})
	ui1Data, _ := ui1Ev["data"].(map[string]any)
	ui1ID, _ := ui1Data["ui_id"].(string)

	// StartRunWithPolicy("reject") while busy returns session_busy.
	if _, err := ctrl.StartRunWithPolicy("collab", NewRequestID(), "reject me", "reject"); err == nil || err.Error() != "session_busy" {
		t.Fatalf("StartRunWithPolicy(reject) = %v, want session_busy", err)
	}

	// StartRunWithPolicy("enqueue") queues run 2 behind run 1.
	run2JSON, err := ctrl.StartRunWithPolicy("collab", NewRequestID(), "second queued task", "enqueue")
	must(t, err)
	var run2 struct {
		RunID         string `json:"run_id"`
		Queued        bool   `json:"queued"`
		QueuePosition int    `json:"queue_position"`
	}
	must(t, json.Unmarshal([]byte(run2JSON), &run2))
	if !run2.Queued || run2.QueuePosition != 1 {
		t.Fatalf("expected queued position 1, got %s", run2JSON)
	}

	// Viewer submits guest request 1 and cancels it self-service.
	g1JSON, err := viewer.SubmitGuestRequest("collab", NewRequestID(), "draft question")
	must(t, err)
	var g1 struct {
		GuestRequestID string `json:"guest_request_id"`
	}
	must(t, json.Unmarshal([]byte(g1JSON), &g1))
	cancelG1, err := viewer.RespondGuestRequestWithOptions("collab", g1.GuestRequestID, "cancel", "", "")
	must(t, err)
	if !strings.Contains(cancelG1, `"status":"cancelled"`) {
		t.Fatalf("expected guest self-cancel, got %s", cancelG1)
	}

	// Viewer submits guest request 2; Controller approves with refined prompt while run 1 is busy -> queues behind run 2.
	g2JSON, err := viewer.SubmitGuestRequest("collab", NewRequestID(), "rough guest prompt")
	must(t, err)
	var g2 struct {
		GuestRequestID string `json:"guest_request_id"`
	}
	must(t, json.Unmarshal([]byte(g2JSON), &g2))
	approveG2, err := ctrl.RespondGuestRequestWithOptions("collab", g2.GuestRequestID, "approve", "refined guest prompt", `{"tools":["read","bash"]}`)
	must(t, err)
	var g2Resp struct {
		Status        string `json:"status"`
		RunID         string `json:"run_id"`
		Queued        bool   `json:"queued"`
		QueuePosition int    `json:"queue_position"`
	}
	must(t, json.Unmarshal([]byte(approveG2), &g2Resp))
	if g2Resp.Status != "approved" || !g2Resp.Queued || g2Resp.QueuePosition != 2 {
		t.Fatalf("expected approved queued at position 2, got %s", approveG2)
	}

	// Cancel run 2 while queued, approve run 1's UI, then approve guest run's UI so it completes.
	cancelR2, err := ctrl.CancelRun("collab", run2.RunID)
	must(t, err)
	if !strings.Contains(cancelR2, `"status":"cancelled"`) {
		t.Fatalf("expected queued run 2 cancelled, got %s", cancelR2)
	}
	_, err = ctrl.RespondUI("collab", run1.RunID, ui1ID, `{"confirmed":true}`)
	must(t, err)

	// Wait for guest run to start with refined text and approve its UI.
	g2StartEv := waitForEvent(ctrl, func(ev map[string]any) bool {
		return ev["kind"] == "run.started" && ev["run_id"] == g2Resp.RunID
	})
	g2StartData, _ := g2StartEv["data"].(map[string]any)
	if g2StartData["text"] != "refined guest prompt" {
		t.Fatalf("expected refined prompt in run.started, got %v", g2StartData)
	}
	uiG2Ev := waitForEvent(ctrl, func(ev map[string]any) bool {
		return ev["kind"] == "ui.request" && ev["run_id"] == g2Resp.RunID
	})
	uiG2Data, _ := uiG2Ev["data"].(map[string]any)
	uiG2ID, _ := uiG2Data["ui_id"].(string)
	_, err = ctrl.RespondUI("collab", g2Resp.RunID, uiG2ID, `{"confirmed":true}`)
	must(t, err)
	_ = waitForEvent(ctrl, func(ev map[string]any) bool {
		return ev["kind"] == "run.completed" && ev["run_id"] == g2Resp.RunID
	})

	// Viewer explicitly closes session -> Controller sees presence drop back to 1.
	must(t, viewer.CloseSession("collab"))
	_ = waitForEvent(ctrl, func(ev map[string]any) bool {
		if ev["kind"] != "presence.updated" {
			return false
		}
		data, _ := ev["data"].(map[string]any)
		parts, _ := data["participants"].([]any)
		return len(parts) == 1
	})
}
