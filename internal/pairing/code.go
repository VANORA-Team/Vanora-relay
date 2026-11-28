package pairing

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const Lifetime = 5 * time.Minute

var ErrInvalid = errors.New("invalid or expired pairing code")

type Record struct {
	Locator string    `json:"locator"`
	Box     string    `json:"box"`
	Expires time.Time `json:"expires_at"`
}

var alphabet = base32.NewEncoding("23456789ABCDEFGHJKLMNPQRSTUVWXYZ").WithPadding(base32.NoPadding)

func codeKeys(code string) (string, cipher.AEAD, error) {
	compact := strings.NewReplacer("-", "", " ", "").Replace(strings.ToUpper(strings.TrimSpace(code)))
	if len(compact) != 16 {
		return "", nil, ErrInvalid
	}
	secret, err := alphabet.DecodeString(compact)
	if err != nil {
		return "", nil, ErrInvalid
	}
	locator := sha256.Sum256(append([]byte("vanora/lookup/v1\x00"), secret...))
	key := sha256.Sum256(append([]byte("vanora/invite/v1\x00"), secret...))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", nil, err
	}
	box, err := cipher.NewGCMWithRandomNonce(block)
	return base64.RawURLEncoding.EncodeToString(locator[:]), box, err
}

func Seal(link string, expires time.Time) (string, Record, error) {
	var secret [10]byte
	rand.Read(secret[:])
	raw := alphabet.EncodeToString(secret[:])
	code := strings.Join([]string{raw[:4], raw[4:8], raw[8:12], raw[12:]}, "-")
	locator, box, err := codeKeys(code)
	if err != nil {
		return "", Record{}, err
	}
	sealed := box.Seal(nil, nil, []byte(link), []byte(locator))
	return code, Record{locator, base64.RawURLEncoding.EncodeToString(sealed), expires}, nil
}

func httpEndpoint(signalURL string) (*url.URL, error) {
	u, err := url.Parse(signalURL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("invalid pairing service URL")
	}
	switch u.Scheme {
	case "wss", "https":
		u.Scheme = "https"
	case "ws", "http":
		if !strings.EqualFold(u.Hostname(), "localhost") && !net.ParseIP(u.Hostname()).IsLoopback() {
			return nil, errors.New("pairing service requires TLS")
		}
		u.Scheme = "http"
	default:
		return nil, errors.New("invalid pairing service scheme")
	}
	return u, nil
}

var client = http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}}

func Publish(ctx context.Context, signalURL, device, ticket string, record Record) error {
	if ticket == "" {
		return errors.New("relay does not support pairing codes or desktop is offline")
	}
	u, err := httpEndpoint(signalURL)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+ticket)
	req.Header.Set("Vanora-Desktop", device)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("pairing publication failed (HTTP %d)", resp.StatusCode)
	}
	return nil
}

func Resolve(ctx context.Context, signalURL, code string) (string, error) {
	u, err := httpEndpoint(signalURL)
	if err != nil {
		return "", err
	}
	return ResolveAt(ctx, &client, u, code)
}

func ResolveAt(ctx context.Context, client *http.Client, u *url.URL, code string) (string, error) {
	locator, box, err := codeKeys(code)
	if err != nil {
		return "", err
	}
	target := *u
	query := target.Query()
	query.Set("pairing", locator)
	target.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return "", err
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(string(raw))
	if err != nil || len(sealed) < box.Overhead() {
		return "", ErrInvalid
	}
	link, err := box.Open(nil, nil, sealed, []byte(locator))
	if err != nil {
		return "", ErrInvalid
	}
	return string(link), nil
}
