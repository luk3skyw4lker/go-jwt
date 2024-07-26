package rs256

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
)

type RS256 struct {
	key string
}

func New(key string) *RS256 {
	return &RS256{
		key: key,
	}
}

func (RS256) Name() string {
	return "RS256"
}

func (r *RS256) Generate(header []byte, payload []byte) ([]byte, error) {
	if r.key == "" {
		return nil, errors.New("cannot generate RSA256 hash with no key")
	}

	block, _ := pem.Decode([]byte(r.key))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: %s", err.Error())
	}

	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub.(*rsa.PublicKey), slices.Concat(header, payload), nil)
}
