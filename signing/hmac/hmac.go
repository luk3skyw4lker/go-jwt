// Package hmac signs JWTs with a shared secret, using the HS224, HS256 and
// HS512 algorithms of RFC 7518.
package hmac

import (
	"crypto"
	// Registering the hashes this package names, so that a signer built
	// for one is usable rather than merely constructible: crypto.Hash
	// resolves to an implementation only if something has imported it.
	"crypto/hmac"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"errors"
	"fmt"
)

// HMACSigning signs and verifies with one hash function and one secret.
//
// A value is safe for concurrent use once its key is set: signing derives a
// fresh MAC per call and never mutates the receiver.
type HMACSigning struct {
	name string
	hash crypto.Hash
	key  []byte
}

var (
	// HS256, HS224 and HS512 are keyless templates: pass one to SetKey before
	// signing with it.
	//
	// Deprecated: these are package-level singletons, so SetKey on one is
	// visible to every other user of the package in the same process. Prefer
	// New, which returns a signer nobody else holds.
	HS256 = New(crypto.SHA256, "")
	HS224 = New(crypto.SHA224, "")
	HS512 = New(crypto.SHA512, "")

	// ErrKeyNotSet reports an attempt to sign or verify with no secret. It is
	// returned rather than treated as an empty key, because an empty HMAC key
	// is valid input to the primitive and would silently produce forgeable
	// tokens.
	ErrKeyNotSet = errors.New("key not set, use SetKey or instantiate a new signing method setting the keys")

	// ErrHashUnavailable reports a hash whose implementation is not linked
	// into the binary.
	ErrHashUnavailable = errors.New("hash unavailable")
)

// New builds a signer for the given hash and secret.
func New(hash crypto.Hash, key string) *HMACSigning {
	var name string
	switch hash.String() {
	case "SHA-256":
		name = "HS256"
	case "SHA-224":
		name = "HS224"
	case "SHA-512":
		name = "HS512"
	default:
		name = fmt.Sprintf("HS%s", hash.String())
	}

	return &HMACSigning{name: name, hash: hash, key: []byte(key)}
}

// SetKey installs the secret this signer uses.
func (s *HMACSigning) SetKey(key []byte) {
	s.key = append([]byte(nil), key...)
}

// Name returns the value this algorithm writes into the token's alg header.
func (s *HMACSigning) Name() string {
	return s.name
}

// Sign returns the MAC over the signing input RFC 7515 §5.1 defines: the
// encoded header, an ASCII period, and the encoded payload.
//
// The separator is part of the signed bytes and not decoration. Without it
// header "ab" + payload "cd" and header "abc" + payload "d" produce the same
// input, so a signature over one is a valid signature over the other.
func (s *HMACSigning) Sign(header []byte, payload []byte) ([]byte, error) {
	if len(s.key) == 0 {
		return nil, ErrKeyNotSet
	}
	if !s.hash.Available() {
		return nil, ErrHashUnavailable
	}

	mac := hmac.New(s.hash.New, s.key)
	mac.Write(header)
	mac.Write([]byte{'.'})
	mac.Write(payload)

	return mac.Sum(nil), nil
}

// Verify reports whether decodedSignature is the MAC of this header and
// payload under this key.
//
// A signature that simply does not match is (false, nil): a token presented by
// a client failing to verify is an ordinary outcome, not a fault. Only a
// missing key or unusable hash produces an error.
//
// The comparison is constant time. A byte-by-byte comparison that returns
// early leaks, through timing, how many leading bytes of a guess were correct,
// which is enough to recover a signature one byte at a time.
func (s *HMACSigning) Verify(header, payload, decodedSignature []byte) (bool, error) {
	expected, err := s.Sign(header, payload)
	if err != nil {
		return false, err
	}

	return hmac.Equal(expected, decodedSignature), nil
}
