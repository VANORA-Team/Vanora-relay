package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/zalando/go-keyring"
)

// Store only the small encryption key in the OS vault. Provider refresh handles
// may exceed platform credential size limits, especially Windows' blob limit.
type vault struct {
	file, id string
	mu       sync.Mutex
	cached   cipher.AEAD
}

func openVault(dir, authority, ca string) *vault {
	return namedVault(dir, "account.enc", authority+"\x00"+ca)
}

func openChannelVault(dir, channel, authority, ca string) *vault {
	switch channel {
	case "cn", "global":
		return namedVault(dir, "account-"+channel+".enc", channel+"\x00"+authority+"\x00"+ca)
	default:
		return openVault(dir, authority, ca)
	}
}

func namedVault(dir, name, scope string) *vault {
	file := filepath.Join(dir, name)
	hash := sha256.Sum256([]byte(file + "\x00" + scope))
	return &vault{file: file, id: hex.EncodeToString(hash[:])}
}
func (v *vault) cipher(create bool) (cipher.AEAD, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.cached != nil {
		return v.cached, nil
	}
	const service = "Vanora Desktop Relay"
	encoded, err := keyring.Get(service, v.id)
	if errors.Is(err, keyring.ErrNotFound) && create {
		key := make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		encoded = base64.RawStdEncoding.EncodeToString(key)
		err = keyring.Set(service, v.id, encoded)
	}
	if err != nil {
		return nil, fmt.Errorf("system credential store: %w", err)
	}
	key, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid desktop vault key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	v.cached = gcm
	return gcm, nil
}
func (v *vault) Load() (string, error) {
	b, err := os.ReadFile(v.file)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	a, err := v.cipher(false)
	if err != nil {
		return "", err
	}
	if len(b) < a.NonceSize() {
		return "", errors.New("invalid desktop vault")
	}
	plain, err := a.Open(nil, b[:a.NonceSize()], b[a.NonceSize():], []byte(v.id))
	return string(plain), err
}
func (v *vault) Save(value string) error {
	_, err := os.Stat(v.file)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	a, err := v.cipher(errors.Is(err, os.ErrNotExist))
	if err != nil {
		return err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	b := a.Seal(nonce, nonce, []byte(value), []byte(v.id))
	f, err := os.CreateTemp(filepath.Dir(v.file), ".account-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), v.file)
}
