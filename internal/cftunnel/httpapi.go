package cftunnel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vanora-relay/internal/identity"
	"vanora-relay/internal/strictjson"
	"vanora-relay/protocol"
)

const managementPrefix = "/v1/tunnels/"

type httpHandler struct {
	s         *Service
	caKey     ed25519.PublicKey
	hasToken  bool
	selfToken [sha256.Size]byte
	limit     httpLimit
}

func NewHTTPHandler(service *Service, caKey ed25519.PublicKey, selfToken string) http.Handler {
	return &httpHandler{s: service, caKey: append(ed25519.PublicKey(nil), caKey...),
		hasToken: selfToken != "", selfToken: sha256.Sum256([]byte(selfToken)),
		limit: httpLimit{entries: make(map[string]*httpLimitEntry)}}
}

type AllocationView struct {
	DeviceID             string          `json:"device_id"`
	State                AllocationState `json:"state"`
	Generation           int64           `json:"generation"`
	Incarnation          int64           `json:"incarnation"`
	Hostname             string          `json:"hostname,omitempty"`
	ManualResumeRequired bool            `json:"manual_resume_required"`
}

type OperationView struct {
	ID          string        `json:"operation_id"`
	Type        OperationType `json:"type"`
	Generation  int64         `json:"generation"`
	CreatedAt   time.Time     `json:"created_at"`
	CompletedAt *time.Time    `json:"completed_at,omitempty"`
	Error       ErrorCode     `json:"error,omitempty"`
}

func allocationView(a Allocation) AllocationView {
	return AllocationView{a.DeviceID, a.State, a.Generation, a.Incarnation, a.Hostname, a.ManualResumeRequired}
}

func operationView(op Operation) OperationView {
	view := OperationView{ID: op.ID, Type: op.Type, Generation: op.Generation, CreatedAt: op.CreatedAt, Error: op.ErrorCode}
	if !op.CompletedAt.IsZero() {
		completed := op.CompletedAt.UTC()
		view.CompletedAt = &completed
	}
	return view
}

type managementAction struct {
	op           OperationType
	runtime      bool
	ownerManaged bool
}

var managementActions = map[string]managementAction{
	"status":      {ownerManaged: true},
	"register":    {op: OpProvision, runtime: true},
	"origin":      {op: OpReconcile, runtime: true},
	"recover":     {op: OpRecover, runtime: true},
	"token":       {runtime: true},
	"release":     {op: OpRelease},
	"disconnect":  {op: OpDisconnect, ownerManaged: true},
	"resume":      {op: OpResume, runtime: true},
	"deprovision": {op: OpDeprovision, ownerManaged: true},
	"operations":  {ownerManaged: true},
}

type originRequest struct {
	Origin       string `json:"origin"`
	RuntimeID    string `json:"runtime_id"`
	IfGeneration *int64 `json:"if_generation"`
}

type generationRequest struct {
	IfGeneration *int64 `json:"if_generation"`
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	requestID := protocol.NewID()
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeHTTPError(w, http.StatusMethodNotAllowed, "method_not_allowed", requestID, 0, "")
		return
	}
	path, underPrefix := strings.CutPrefix(r.URL.Path, managementPrefix)
	if !underPrefix || r.URL.RawPath != "" || r.URL.ForceQuery || r.URL.RawQuery != "" || r.URL.Fragment != "" {
		writeHTTPError(w, http.StatusNotFound, CodeNotFound, requestID, 0, "")
		return
	}
	device, action, operation := "", "challenge", ""
	if path != "challenge" {
		device, action, operation = managementPath(path)
		if action == "" {
			writeHTTPError(w, http.StatusNotFound, CodeNotFound, requestID, 0, "")
			return
		}
	}
	now := h.s.now()
	self := h.s.cfg.Channel.IsSelfHosted()
	if !validAuthHeaders(r.Header, self) {
		writeHTTPError(w, http.StatusBadRequest, "invalid_headers", requestID, 0, "")
		return
	}
	badBearer := self && !h.validBearer(r.Header.Get("Authorization"))
	if retry := h.limit.check(h.s.cfg.ClientIP(r), now, action == "challenge", badBearer); retry > 0 {
		writeHTTPError(w, http.StatusTooManyRequests, "rate_limited", requestID, retry, "")
		return
	}
	if badBearer {
		w.Header().Set("WWW-Authenticate", `Bearer realm="vanora-relay"`)
		writeHTTPError(w, http.StatusUnauthorized, CodeInvalidProof, requestID, 0, "")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
	if err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			writeHTTPError(w, http.StatusRequestEntityTooLarge, "body_too_large", requestID, 0, "")
		} else {
			writeHTTPError(w, http.StatusBadRequest, "invalid_json", requestID, 0, "")
		}
		return
	}
	if action == "challenge" {
		h.challenge(w, raw, now, requestID)
		return
	}
	bodyHash := hashHex(raw)
	principal, proof, err := h.authenticate(r, action, bodyHash, now)
	if err != nil {
		writeHTTPError(w, http.StatusUnauthorized, CodeInvalidProof, requestID, 0, "")
		return
	}
	status, response, consumed, err := h.dispatch(r, principal, proof, device, action, operation, raw, bodyHash, now)
	if !consumed {
		if consumeErr := h.s.store.ConsumeProof(r.Context(), proof, h.s.now()); consumeErr != nil {
			err = consumeErr
		}
	}
	if err != nil {
		writeManagementError(w, requestID, err)
		return
	}
	writeJSON(w, status, response)
}

func managementPath(path string) (device, action, operation string) {
	parts := strings.Split(path, "/")
	if len(parts) < 2 || !ticketJTIPattern.MatchString(parts[0]) {
		return "", "", ""
	}
	if _, ok := managementActions[parts[1]]; !ok {
		return "", "", ""
	}
	if parts[1] == "operations" {
		if len(parts) != 3 || !ticketJTIPattern.MatchString(parts[2]) {
			return "", "", ""
		}
		return parts[0], parts[1], parts[2]
	}
	if len(parts) != 2 {
		return "", "", ""
	}
	return parts[0], parts[1], ""
}

func (h *httpHandler) challenge(w http.ResponseWriter, raw []byte, now time.Time, requestID string) {
	var body struct {
		Action   string `json:"action"`
		DeviceID string `json:"device_id"`
	}
	err := strictjson.Decode(raw, &body)
	_, validAction := managementActions[body.Action]
	validDevice := ticketJTIPattern.MatchString(body.DeviceID)
	if h.s.cfg.Channel.IsSelfHosted() {
		validDevice = identity.ValidSelfDeviceID(body.DeviceID)
	}
	if err != nil || !validAction || !validDevice {
		writeHTTPError(w, http.StatusBadRequest, CodeInvalidClaim, requestID, 0, "")
		return
	}
	token, proof, err := h.s.crypto.MintChallenge(h.s.scope.ID, body.Action, body.DeviceID, now)
	if err != nil {
		writeManagementError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Challenge string    `json:"challenge"`
		ExpiresAt time.Time `json:"expires_at"`
	}{token, proof.ExpiresAt})
}

func (h *httpHandler) dispatch(r *http.Request, principal identity.Principal, proof ProofUse, device, action, operation string,
	raw []byte, bodyHash string, now time.Time) (status int, response any, consumed bool, err error) {
	ctx := r.Context()
	self := h.s.cfg.Channel.IsSelfHosted()
	owner := principal.RemoteUserID()
	if self {
		owner = principal.DeviceID
	}
	spec := managementActions[action]
	binding := DeviceBinding{DeviceID: device, OwnerID: owner, DeviceKeyHash: hashHex(principal.PublicKey)}
	if device != principal.DeviceID {
		if self || !spec.ownerManaged {
			return 0, nil, false, ErrDeviceBinding
		}
		binding.OwnerManaged = true
	}
	if action == "status" || action == "operations" {
		if err := strictjson.Decode(raw, &struct{}{}); err != nil {
			return 0, nil, false, ErrInvalidClaim
		}
		if err := h.s.store.ConsumeProof(ctx, proof, h.s.now()); err != nil {
			return 0, nil, true, err
		}
		if action == "status" {
			a, err := h.s.Status(ctx, binding)
			return http.StatusOK, allocationView(a), true, err
		}
		op, err := h.s.GetOperation(ctx, binding, operation)
		return http.StatusOK, operationView(op), true, err
	}
	req := ManagementRequest{DeviceBinding: binding, Proof: &proof, AllowNoop: true}
	if spec.op != "" {
		idempotencyKey := r.Header.Get("Idempotency-Key")
		if !visibleValue(idempotencyKey) {
			return 0, nil, false, ErrInvalidClaim
		}
		req.IdempotencyKey = principal.DeviceID + "\x00" + idempotencyKey
		req.BodyHash = hashHex([]byte("POST\x00" + r.URL.Path + "\x00" + bodyHash))
	}
	if spec.runtime {
		var body originRequest
		if strictjson.Decode(raw, &body) != nil || body.IfGeneration == nil || *body.IfGeneration < 0 || !visibleValue(body.RuntimeID) {
			return 0, nil, false, ErrInvalidClaim
		}
		req.IfGeneration, req.RuntimeID = *body.IfGeneration, body.RuntimeID
		req.Origin, err = ParseOrigin(body.Origin)
		if err != nil {
			return 0, nil, false, err
		}
		if h.s.cfg.Mode != ModeManaged {
			return 0, nil, false, ErrEntitlementDenied
		}
		req.Policy, err = h.s.ownerPolicy(ctx, principal, now)
		if err != nil {
			return 0, nil, false, err
		}
		if action == "token" {
			token, consumed, err := h.s.issueConnectorToken(ctx, req)
			return http.StatusOK, token, consumed, err
		}
	} else {
		var body generationRequest
		if strictjson.Decode(raw, &body) != nil || body.IfGeneration == nil || *body.IfGeneration < 0 {
			return 0, nil, false, ErrInvalidClaim
		}
		req.IfGeneration = *body.IfGeneration
	}
	op, err := h.s.claim(ctx, req, spec.op)
	if err != nil {
		return 0, nil, false, err
	}
	if op.ID == "" || op.Type == OpDeprovision && op.PreviousState == StateReleased && !op.CompletedAt.IsZero() {
		a, err := h.s.Status(ctx, binding)
		if err == nil && a.Generation != op.Generation {
			err = ErrGenerationConflict
		}
		return http.StatusOK, allocationView(a), true, err
	}
	return http.StatusAccepted, operationView(op), true, nil
}

func visibleValue(value string) bool {
	return len(value) >= 1 && len(value) <= 128 &&
		!strings.ContainsFunc(value, func(char rune) bool { return char < '!' || char > '~' })
}

func writeManagementError(w http.ResponseWriter, requestID string, err error) {
	code := CodeOf(err)
	status, delay := http.StatusInternalServerError, time.Duration(0)
	var inProgress OperationInProgressError
	errors.As(err, &inProgress)
	switch code {
	case CodeInvalidClaim, CodeInvalidOrigin:
		status = http.StatusBadRequest
	case CodeInvalidProof:
		status = http.StatusUnauthorized
	case CodeDeviceBinding, CodeEntitlementDenied:
		status = http.StatusForbidden
	case CodeNotFound:
		status = http.StatusNotFound
	case CodeGenerationConflict, CodeOperationInProgress, CodeIdempotencyConflict, CodeReplayDetected,
		CodeOwnerQuotaExhausted, CodeAccountCapacity, CodeTunnelSuspended, CodeRecoveryRequired,
		CodeInvalidTransition, CodeDNSConflict, CodePresenceActive, ErrCFConflict:
		status = http.StatusConflict
	case ErrCFRateLimited:
		status = http.StatusTooManyRequests
		delay, _ = cfRateDelay(err)
	case errMembershipUnavailable, ErrCFTransient, ErrCFAuthorization, ErrCFRejected, ErrCFConfigNotFound, ErrCFNotFound:
		status, delay = http.StatusServiceUnavailable, time.Second
	}
	writeHTTPError(w, status, code, requestID, delay, inProgress.OperationID)
}

func writeHTTPError(w http.ResponseWriter, status int, code ErrorCode, requestID string, retry time.Duration, operationID string) {
	var seconds int64
	if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
		seconds = int64(retry / time.Second)
		if retry%time.Second > 0 {
			seconds++
		}
		seconds = max(1, seconds)
		w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	}
	writeJSON(w, status, struct {
		Error       ErrorCode `json:"error"`
		RequestID   string    `json:"request_id"`
		RetryAfter  int64     `json:"retry_after,omitempty"`
		OperationID string    `json:"operation_id,omitempty"`
	}{code, requestID, seconds, operationID})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
