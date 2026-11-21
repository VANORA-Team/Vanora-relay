package desktop

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Message is the only conversation data exposed to a remote client. Tool
// calls, tool results, thinking blocks, bash output, custom entries, and
// upstream error strings are never included.
type Message struct {
	Role      string `json:"role"`
	Text      string `json:"text"`
	Timestamp int64  `json:"timestamp,omitempty"`
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
	Timestamp  int64           `json:"timestamp"`
	StopReason string          `json:"stopReason"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
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
	if env.Role != "user" && env.Role != "assistant" {
		return Message{}, false
	}
	text := extractText(env.Content)
	if text == "" {
		return Message{}, false
	}
	ts := env.Timestamp
	if ts == 0 && entryTimestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, entryTimestamp); err == nil {
			ts = parsed.UnixMilli()
		}
	}
	return Message{Role: env.Role, Text: text, Timestamp: ts}, true
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
