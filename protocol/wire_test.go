package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestVerifyRequiresCanonicalProofAndBody(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := Message{Type: "test"}
	body := []byte{0}
	if err := message.Sign(private, body); err != nil {
		t.Fatal(err)
	}
	if got, err := message.Verify(public); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("valid Verify = %x, %v", got, err)
	}

	for _, proof := range []string{
		message.Proof + "=",
		message.Proof[:10] + "\n" + message.Proof[10:],
		withTrailingBase64Bit(message.Proof),
	} {
		modified := message
		modified.Proof = proof
		if _, err := modified.Verify(public); err == nil {
			t.Fatalf("non-canonical proof accepted: %q", proof)
		}
	}

	message.Body = withTrailingBase64Bit(message.Body)
	signingInput, err := message.bytes()
	if err != nil {
		t.Fatal(err)
	}
	message.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, signingInput))
	if _, err := message.Verify(public); err == nil {
		t.Fatal("non-canonical body accepted with a valid signature")
	}
}

func withTrailingBase64Bit(value string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for index := range len(alphabet) {
		if value[len(value)-1] == alphabet[index] {
			return value[:len(value)-1] + string(alphabet[index|1])
		}
	}
	panic("invalid test base64")
}
