package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSelfDeviceIDAndPairProof(t *testing.T) {
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id1, err := SelfDeviceID(pub1)
	if err != nil {
		t.Fatal(err)
	}
	id1Again, err := SelfDeviceID(pub1)
	if err != nil || id1 != id1Again {
		t.Fatalf("SelfDeviceID not deterministic: %q vs %q (%v)", id1, id1Again, err)
	}
	id2, err := SelfDeviceID(pub2)
	if err != nil || id1 == id2 {
		t.Fatalf("distinct keys collided: %q vs %q (%v)", id1, id2, err)
	}
	if !ValidSelfDeviceID(id1) || ValidSelfDeviceID("dev_"+id1[len(SelfDeviceIDPrefix):]) || ValidSelfDeviceID("sdev_SHORT") {
		t.Fatalf("ValidSelfDeviceID mismatch for %q", id1)
	}
	if _, err := SelfDeviceID(ed25519.PublicKey("short")); err == nil {
		t.Fatal("accepted short public key")
	}

	token := []byte("0123456789abcdef0123456789abcdef")
	proofA, err := SelfPairProof(token, "0123456789abcdef0123456789abcdef", pub1, pub2)
	if err != nil {
		t.Fatal(err)
	}
	proofB, err := SelfPairProof(token, "0123456789abcdef0123456789abcdef", pub1, pub2)
	if err != nil || !bytes.Equal(proofA, proofB) {
		t.Fatalf("SelfPairProof not deterministic")
	}
	proofDiffConn, err := SelfPairProof(token, "fedcba9876543210fedcba9876543210", pub1, pub2)
	if err != nil || bytes.Equal(proofA, proofDiffConn) {
		t.Fatalf("SelfPairProof ignored connection id")
	}
	proofSwapped, err := SelfPairProof(token, "0123456789abcdef0123456789abcdef", pub2, pub1)
	if err != nil || bytes.Equal(proofA, proofSwapped) {
		t.Fatalf("SelfPairProof ignored peer direction")
	}
	if _, err := SelfPairProof(nil, "0123456789abcdef0123456789abcdef", pub1, pub2); err == nil {
		t.Fatal("accepted empty pair token")
	}
}
