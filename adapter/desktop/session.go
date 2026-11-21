package desktop

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxToolArgsBytes   = 8 << 10
	maxToolResultBytes = 16 << 10
)

// ToolCallSummary is the compact representation of a model tool invocation.
type ToolCallSummary struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name"`
	Arguments string `json:"arguments,omitempty"`
}

// Message is one conversation item returned in session.open snapshots.
// Thinking, ToolCalls and toolResult entries are stripped unless the viewer's
// ACL permits them.
type Message struct {
	Role       string            `json:"role"`
	Text       string            `json:"text,omitempty"`
	Thinking   string            `json:"thinking,omitempty"`
	ToolCalls  []ToolCallSummary `json:"tool_calls,omitempty"`
	ToolCallID string            `json:"tool_call_id,omitempty"`
	ToolName   string            `json:"tool_name,omitempty"`
	IsError    bool              `json:"is_error,omitempty"`
	Timestamp  int64             `json:"timestamp,omitempty"`
}

type sessionHeader struct {
	Type      string `json:"type"`
	Version   int    `json:"version"`
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	CWD       string `json:"cwd"`
}

type sessionEntry struct {
	Type      string          `json:"type"`
	ID        string          `json:"id"`
	ParentID  *string         `json:"parentId"`
	Timestamp string          `json:"timestamp"`
	Message   json.RawMessage `json:"message"`
}

type messageEnvelope struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	ToolCallID string          `json:"toolCallId"`
	ToolName   string          `json:"toolName"`
	IsError    bool            `json:"isError"`
	Timestamp  int64           `json:"timestamp"`
	StopReason string          `json:"stopReason"`
}

type contentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	Thinking  string          `json:"thinking"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type fileStamp struct {
	size    int64
	modTime time.Time
}

func readSessionHeader(path string) (*sessionHeader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := r.ReadString('\n')
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" {
			if err == io.EOF {
				return nil, errors.New("empty session file")
			}
			if err != nil {
				return nil, err
			}
			continue
		}
		if len(line) > 1<<20 {
			return nil, errors.New("session header is too large")
		}
		var h sessionHeader
		if err := json.Unmarshal([]byte(line), &h); err != nil {
			return nil, fmt.Errorf("invalid session header: %w", err)
		}
		if h.Type != "session" {
			return nil, fmt.Errorf("first session record has type %q, want \"session\"", h.Type)
		}
		if h.CWD == "" {
			return nil, errors.New("session header has no cwd")
		}
		return &h, nil
	}
}

// loadSessionMessages follows Vanora's append-only entry tree from the last
// entry back to the root and returns only user and assistant text.
func loadSessionMessages(path string) ([]Message, fileStamp, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fileStamp{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fileStamp{}, err
	}
	stamp := fileStamp{size: st.Size(), modTime: st.ModTime()}

	r := bufio.NewReaderSize(f, 256<<10)
	var (
		headerSeen bool
		entries    []sessionEntry
	)
	for {
		line, readErr := r.ReadString('\n')
		terminated := strings.HasSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) != "" {
			if !headerSeen {
				var h sessionHeader
				if err := json.Unmarshal([]byte(line), &h); err != nil {
					return nil, fileStamp{}, fmt.Errorf("invalid session header: %w", err)
				}
				if h.Type != "session" {
					return nil, fileStamp{}, fmt.Errorf("first session record has type %q, want \"session\"", h.Type)
				}
				headerSeen = true
			} else {
				var entry sessionEntry
				if err := json.Unmarshal([]byte(line), &entry); err != nil {
					// Vanora appends with a single write per line. A reader can
					// still observe the tail of an in-flight append; ignore only
					// that unterminated trailing fragment.
					if readErr == io.EOF && !terminated {
						break
					}
					return nil, fileStamp{}, fmt.Errorf("invalid session entry: %w", err)
				}
				if entry.ID == "" {
					return nil, fileStamp{}, errors.New("session entry without id")
				}
				entries = append(entries, entry)
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return nil, fileStamp{}, readErr
		}
	}
	if !headerSeen {
		return nil, fileStamp{}, errors.New("empty session file")
	}
	return activeMessages(entries), stamp, nil
}

func activeMessages(entries []sessionEntry) []Message {
	if len(entries) == 0 {
		return []Message{}
	}
	index := make(map[string]int, len(entries))
	for i, e := range entries {
		index[e.ID] = i
	}
	// The newest record is the leaf. Walking parents yields only the active
	// branch, so abandoned branches and compaction summaries stay hidden.
	path := make([]int, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	idx, ok := index[entries[len(entries)-1].ID]
	if !ok {
		return []Message{}
	}
	for ok {
		if _, dup := seen[entries[idx].ID]; dup {
			break
		}
		seen[entries[idx].ID] = struct{}{}
		path = append(path, idx)
		parent := entries[idx].ParentID
		if parent == nil || *parent == "" {
			break
		}
		idx, ok = index[*parent]
	}
	out := make([]Message, 0, len(path))
	for i := len(path) - 1; i >= 0; i-- {
		e := entries[path[i]]
		if e.Type != "message" || len(e.Message) == 0 || string(e.Message) == "null" {
			continue
		}
		if m, ok := decodeDisplayMessage(e.Message, e.Timestamp); ok {
			out = append(out, m)
		}
	}
	return out
}

func decodeDisplayMessage(raw json.RawMessage, entryTimestamp string) (Message, bool) {
	var env messageEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return Message{}, false
	}
	ts := env.Timestamp
	if ts == 0 && entryTimestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, entryTimestamp); err == nil {
			ts = parsed.UnixMilli()
		}
	}
	switch env.Role {
	case "user":
		text := extractText(env.Content)
		if text == "" {
			return Message{}, false
		}
		return Message{Role: "user", Text: text, Timestamp: ts}, true
	case "assistant":
		text, thinking, toolCalls := extractAssistantParts(env.Content)
		if text == "" && thinking == "" && len(toolCalls) == 0 {
			return Message{}, false
		}
		return Message{
			Role:      "assistant",
			Text:      text,
			Thinking:  thinking,
			ToolCalls: toolCalls,
			Timestamp: ts,
		}, true
	case "toolResult":
		text := truncateUTF8(extractText(env.Content), maxToolResultBytes)
		if text == "" && env.ToolName == "" && env.ToolCallID == "" {
			return Message{}, false
		}
		return Message{
			Role:       "toolResult",
			Text:       text,
			ToolCallID: env.ToolCallID,
			ToolName:   env.ToolName,
			IsError:    env.IsError,
			Timestamp:  ts,
		}, true
	default:
		return Message{}, false
	}
}

func extractAssistantParts(raw json.RawMessage) (string, string, []ToolCallSummary) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", "", nil
	}
	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil {
		return plain, "", nil
	}
	var blocks []contentBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return "", "", nil
	}
	var textBuf, thinkBuf strings.Builder
	var calls []ToolCallSummary
	for _, block := range blocks {
		switch block.Type {
		case "text":
			if block.Text == "" {
				continue
			}
			if textBuf.Len() > 0 {
				textBuf.WriteString("\n")
			}
			textBuf.WriteString(block.Text)
		case "thinking":
			if block.Thinking == "" {
				continue
			}
			if thinkBuf.Len() > 0 {
				thinkBuf.WriteString("\n")
			}
			thinkBuf.WriteString(block.Thinking)
		case "toolCall":
			if block.Name == "" {
				continue
			}
			calls = append(calls, ToolCallSummary{
				ID:        block.ID,
				Name:      block.Name,
				Arguments: truncateJSON(block.Arguments, maxToolArgsBytes),
			})
		}
	}
	return textBuf.String(), thinkBuf.String(), calls
}

func filterMessagesForViewer(messages []Message, showThinking, showTools bool) []Message {
	out := make([]Message, 0, len(messages))
	for _, m := range messages {
		switch m.Role {
		case "user":
			out = append(out, Message{Role: "user", Text: m.Text, Timestamp: m.Timestamp})
		case "assistant":
			copyMsg := Message{Role: "assistant", Text: m.Text, Timestamp: m.Timestamp}
			if showThinking {
				copyMsg.Thinking = m.Thinking
			}
			if showTools && len(m.ToolCalls) > 0 {
				copyMsg.ToolCalls = append([]ToolCallSummary(nil), m.ToolCalls...)
			}
			if copyMsg.Text == "" && copyMsg.Thinking == "" && len(copyMsg.ToolCalls) == 0 {
				continue
			}
			out = append(out, copyMsg)
		case "toolResult":
			if !showTools {
				continue
			}
			out = append(out, m)
		}
	}
	return out
}

func createVanoraSessionFile(sessionDir, workingDir, sessionID string, now time.Time) (string, error) {
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		return "", fmt.Errorf("create session dir: %w", err)
	}
	ts := now.UTC()
	stamp := strings.NewReplacer(":", "-", ".", "-").Replace(ts.Format("2006-01-02T15:04:05.000Z"))
	name := fmt.Sprintf("%s_%s.jsonl", stamp, sessionID)
	fullPath := filepath.Join(sessionDir, name)
	header, err := json.Marshal(sessionHeader{
		Type:      "session",
		Version:   3,
		ID:        sessionID,
		Timestamp: ts.Format(time.RFC3339Nano),
		CWD:       workingDir,
	})
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(append(header, '\n')); err != nil {
		f.Close()
		os.Remove(fullPath)
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(fullPath)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(fullPath)
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(fullPath); err == nil {
		return resolved, nil
	}
	return fullPath, nil
}

func newSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	hx := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hx[0:8], hx[8:12], hx[12:16], hx[16:20], hx[20:32]), nil
}

func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	const suffix = "\n...(truncated)"
	limit := maxBytes - len(suffix)
	if limit <= 0 {
		return s[:maxBytes]
	}
	end := 0
	for end < len(s) && end < limit {
		_, size := utf8.DecodeRuneInString(s[end:])
		if end+size > limit {
			break
		}
		end += size
	}
	return s[:end] + suffix
}

func truncateJSON(raw json.RawMessage, maxBytes int) string {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" || s == "{}" {
		return ""
	}
	return truncateUTF8(s, maxBytes)
}

func extractText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil {
		return plain
	}
	var blocks []contentBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return ""
	}
	var b strings.Builder
	for _, block := range blocks {
		if block.Type != "text" || block.Text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(block.Text)
	}
	return b.String()
}
