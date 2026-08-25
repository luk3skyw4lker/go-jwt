package rsa

import (
	"crypto"
	"testing"

	"github.com/luk3skyw4lker/go-jwt/v2/utils"
)

const (
	header  = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	payload = "eyJzdWIiOiJhbGljZSJ9"
)

func signer(t *testing.T) *RSASigning {
	t.Helper()

	private, public := utils.GenerateRSAKeyPair(false)
	s, err := New(crypto.SHA256, private, public)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestRoundTrip(t *testing.T) {
	s := signer(t)
	if s.Name() != "RS256" {
		t.Fatalf("Name() = %q, want RS256", s.Name())
	}

	signature, err := s.Sign([]byte(header), []byte(payload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := s.Verify([]byte(header), []byte(payload), signature)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("a freshly produced signature did not verify")
	}
}

// TestVerifyReportsAFailureRatherThanAnError keeps a token that simply does not
// verify from looking like a fault in the service: only a missing key or an
// unusable hash is an error.
func TestVerifyReportsAFailureRatherThanAnError(t *testing.T) {
	s := signer(t)

	signature, err := s.Sign([]byte(header), []byte(payload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := s.Verify([]byte(header), []byte("eyJzdWIiOiJhZG1pbiJ9"), signature)
	if ok {
		t.Fatal("a signature verified over a payload it was not made for")
	}
	if err != nil {
		t.Fatalf("a mismatched signature was reported as an error: %v", err)
	}
}

func TestAnotherKeysSignatureIsRefused(t *testing.T) {
	first, second := signer(t), signer(t)

	signature, err := first.Sign([]byte(header), []byte(payload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := second.Verify([]byte(header), []byte(payload), signature)
	if ok {
		t.Fatal("a signature verified under a key pair that did not produce it")
	}
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSigningInputIsUnambiguous(t *testing.T) {
	s := signer(t)

	if string(s.HashData([]byte("ab"), []byte("cd"))) == string(s.HashData([]byte("abc"), []byte("d"))) {
		t.Fatal("header|payload and header|payload split differently hashed to the same value")
	}
}

// TestUnsetKeyPairIsAnErrorNotAPanic covers the package-level RS256 template,
// which has no keys until SetKeyPair is called. Verify used to dereference a
// nil public key.
func TestUnsetKeyPairIsAnErrorNotAPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked with no key pair set: %v", r)
		}
	}()

	unset := &RSASigning{name: "RS256", hash: crypto.SHA256}

	if _, err := unset.Sign([]byte(header), []byte(payload)); err != ErrKeyPairNotSet {
		t.Fatalf("Sign error = %v, want ErrKeyPairNotSet", err)
	}
	if _, err := unset.Verify([]byte(header), []byte(payload), []byte("x")); err != ErrKeyPairNotSet {
		t.Fatalf("Verify error = %v, want ErrKeyPairNotSet", err)
	}
}

func TestSetKeyPair(t *testing.T) {
	private, public := utils.GenerateRSAKeyPair(false)

	s := &RSASigning{name: "RS256", hash: crypto.SHA256}
	if err := s.SetKeyPair(private, public); err != nil {
		t.Fatalf("SetKeyPair: %v", err)
	}

	signature, err := s.Sign([]byte(header), []byte(payload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := s.Verify([]byte(header), []byte(payload), signature)
	if err != nil || !ok {
		t.Fatalf("Verify = %v, %v", ok, err)
	}
}

func TestSetKeyPairRejectsGarbage(t *testing.T) {
	s := &RSASigning{name: "RS256", hash: crypto.SHA256}

	if err := s.SetKeyPair("not a pem block", "nor is this"); err == nil {
		t.Fatal("garbage was accepted as a key pair")
	}
}
