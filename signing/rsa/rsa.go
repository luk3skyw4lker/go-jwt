package rsa

import (
	"crypto"
	// Registering the hashes this package names, so that a signer built
	// for one is usable rather than merely constructible: crypto.Hash
	// resolves to an implementation only if something has imported it.
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"errors"
	"fmt"

	"github.com/luk3skyw4lker/go-jwt/v2/utils"
)

var (
	ErrHashUnavailable = errors.New("hash unavailable")
	ErrKeyPairNotSet   = errors.New("key pair was not set, use SetKeyPair to set the keys or instantiate a new signing method setting the keys")
)

type RSASigning struct {
	name string
	hash crypto.Hash

	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// RS256, RS224 and RS512 are keyless templates: pass one to SetKeyPair before
// signing with it.
//
// Deprecated: these are package-level singletons, so SetKeyPair on one is
// visible to every other user of the package in the same process. Prefer New,
// which returns a signer nobody else holds.
var RS256 = &RSASigning{name: "RS256", hash: crypto.SHA256}
var RS224 = &RSASigning{name: "RS224", hash: crypto.SHA224}
var RS512 = &RSASigning{name: "RS512", hash: crypto.SHA512}

func New(hash crypto.Hash, privateKey, publicKey string) (*RSASigning, error) {
	parsedPrivateKey, parsedPublicKey, err := utils.ParseKeyPair(privateKey, publicKey)
	if err != nil {
		return nil, err
	}

	var name string
	switch hash.String() {
	case "SHA-256":
		name = "RS256"
	case "SHA-224":
		name = "RS224"
	case "SHA-512":
		name = "RS512"
	default:
		name = fmt.Sprintf("RS%s", hash.String())
	}

	return &RSASigning{name, hash, parsedPrivateKey, parsedPublicKey}, nil
}

func (s *RSASigning) SetKeyPair(privateKey, publicKey string) error {
	parsedPrivateKey, parsedPublicKey, err := utils.ParseKeyPair(privateKey, publicKey)
	if err != nil {
		return err
	}

	s.privateKey = parsedPrivateKey
	s.publicKey = parsedPublicKey

	return nil
}

func (s *RSASigning) Name() string {
	return s.name
}

func (s *RSASigning) Sign(header []byte, payload []byte) ([]byte, error) {
	if s.privateKey == nil || s.publicKey == nil {
		return nil, ErrKeyPairNotSet
	}

	if !s.hash.Available() {
		return nil, ErrHashUnavailable
	}

	return rsa.SignPKCS1v15(rand.Reader, s.privateKey, s.hash, s.HashData(header, payload))
}

// Verify reports whether decodedSignature is a valid signature over this
// header and payload under the public key.
//
// A signature that simply does not match is (false, nil), matching the HMAC
// signer: a token failing to verify is an ordinary outcome and should not be
// logged as a fault. Only a missing key or unusable hash is an error.
func (s *RSASigning) Verify(header, payload, decodedSignature []byte) (bool, error) {
	if s.publicKey == nil {
		return false, ErrKeyPairNotSet
	}

	if !s.hash.Available() {
		return false, ErrHashUnavailable
	}

	err := rsa.VerifyPKCS1v15(s.publicKey, s.hash, s.HashData(header, payload), decodedSignature)
	if errors.Is(err, rsa.ErrVerification) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// HashData digests the signing input RFC 7515 §5.1 defines: the encoded
// header, an ASCII period, and the encoded payload.
//
// The separator is signed data, not formatting — see the note on the HMAC
// signer for what its absence allows.
func (s *RSASigning) HashData(header []byte, payload []byte) []byte {
	generator := s.hash.New()

	generator.Write(header)
	generator.Write([]byte{'.'})
	generator.Write(payload)

	return generator.Sum(nil)
}
