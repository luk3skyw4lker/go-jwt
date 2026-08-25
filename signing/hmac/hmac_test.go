package hmac

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"testing"
)

// The header and payload as a JWT presents them: already base64url encoded.
const (
	header  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	payload = "eyJzdWIiOiJhbGljZSJ9"
)

// TestSignUsesTheKey is the regression test for the defect this file was
// written to fix: Sign hashed the header and payload with a plain SHA-256 and
// never mixed in the secret, so the signature was a function of public data
// and anyone could compute it.
func TestSignUsesTheKey(t *testing.T) {
	signer := New(crypto.SHA256, "super-secret-key")

	got, err := signer.Sign([]byte(header), []byte(payload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	forged := sha256.Sum256([]byte(header + payload))
	if string(got) == string(forged[:]) {
		t.Fatal("the signature is a plain digest of the signing input: anyone can forge a token without the key")
	}

	ok, err := signer.Verify([]byte(header), []byte(payload), forged[:])
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("a keyless digest verified as a signature")
	}
}

func TestDifferentKeysProduceDifferentSignatures(t *testing.T) {
	first, err := New(crypto.SHA256, "key-one").Sign([]byte(header), []byte(payload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	second, err := New(crypto.SHA256, "key-two").Sign([]byte(header), []byte(payload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if string(first) == string(second) {
		t.Fatal("two different keys produced the same signature")
	}
}

func TestVerifyRejectsAnotherKeysSignature(t *testing.T) {
	signature, err := New(crypto.SHA256, "the-real-key").Sign([]byte(header), []byte(payload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := New(crypto.SHA256, "some-other-key").Verify([]byte(header), []byte(payload), signature)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("a signature verified under a key that did not produce it")
	}
}

// TestSigningInputIsUnambiguous covers the missing separator. Without the
// period between the two segments these two splits hash identically, so a
// signature over one is a valid signature over the other.
func TestSigningInputIsUnambiguous(t *testing.T) {
	signer := New(crypto.SHA256, "secret")

	first, err := signer.Sign([]byte("ab"), []byte("cd"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	second, err := signer.Sign([]byte("abc"), []byte("d"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if string(first) == string(second) {
		t.Fatal("header|payload and header|payload split differently signed to the same value")
	}
}

func TestRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		hash crypto.Hash
		alg  string
	}{
		{"HS224", crypto.SHA224, "HS224"},
		{"HS256", crypto.SHA256, "HS256"},
		{"HS512", crypto.SHA512, "HS512"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer := New(tc.hash, "secret")
			if signer.Name() != tc.alg {
				t.Fatalf("Name() = %q, want %q", signer.Name(), tc.alg)
			}

			signature, err := signer.Sign([]byte(header), []byte(payload))
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			ok, err := signer.Verify([]byte(header), []byte(payload), signature)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !ok {
				t.Fatal("a freshly produced signature did not verify")
			}
		})
	}
}

func TestVerifyRejectsATamperedPayload(t *testing.T) {
	signer := New(crypto.SHA256, "secret")

	signature, err := signer.Sign([]byte(header), []byte(payload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := signer.Verify([]byte(header), []byte("eyJzdWIiOiJhZG1pbiJ9"), signature)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("a signature verified over a payload it was not made for")
	}
}

// TestEmptyKeyIsRefused matters because an empty HMAC key is valid input to
// the primitive: without this check an unconfigured signer would happily
// produce tokens anybody could reproduce.
func TestEmptyKeyIsRefused(t *testing.T) {
	for _, name := range []string{"unset", "empty string"} {
		t.Run(name, func(t *testing.T) {
			signer := New(crypto.SHA256, "")
			if name == "unset" {
				signer.SetKey(nil)
			}

			if _, err := signer.Sign([]byte(header), []byte(payload)); !errors.Is(err, ErrKeyNotSet) {
				t.Fatalf("Sign error = %v, want ErrKeyNotSet", err)
			}
			if _, err := signer.Verify([]byte(header), []byte(payload), []byte("x")); !errors.Is(err, ErrKeyNotSet) {
				t.Fatalf("Verify error = %v, want ErrKeyNotSet", err)
			}
		})
	}
}

func TestSetKey(t *testing.T) {
	signer := New(crypto.SHA256, "")
	signer.SetKey([]byte("installed-later"))

	signature, err := signer.Sign([]byte(header), []byte(payload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	expected, err := New(crypto.SHA256, "installed-later").Sign([]byte(header), []byte(payload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if string(signature) != string(expected) {
		t.Fatal("SetKey and New disagree about the same key")
	}
}
