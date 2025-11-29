package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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

func (s *RSASigning) Verify(header, payload, decodedSignature []byte) (bool, error) {
	err := rsa.VerifyPKCS1v15(s.publicKey, s.hash, s.HashData(header, payload), decodedSignature)

	return err == nil, err
}

func (s *RSASigning) HashData(header []byte, payload []byte) []byte {
	generator := s.hash.New()

	generator.Write(header)
	generator.Write(payload)

	return generator.Sum(nil)
}
