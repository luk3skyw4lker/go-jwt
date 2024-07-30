package rs256

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/luk3skyw4lker/go-jwt/utils"
)

type RS256 struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	hash       crypto.Hash
}

func New(privateKey string, publicKey string) (*RS256, error) {
	parsedPrivateKey, err := utils.ParseKey(privateKey, utils.PrivateKey)
	if err != nil {
		return nil, err
	}

	parsedPublicKey, err := utils.ParseKey(publicKey, utils.PublicKey)
	if err != nil {
		return nil, err
	}

	return &RS256{
		privateKey: parsedPrivateKey.(*rsa.PrivateKey),
		publicKey:  parsedPublicKey.(*rsa.PublicKey),
		hash:       crypto.SHA256,
	}, nil
}

func (RS256) Name() string {
	return "RS256"
}

func (r *RS256) Generate(header []byte, payload []byte) ([]byte, error) {
	if !r.hash.Available() {
		return nil, errors.New("hash unavailable")
	}

	return rsa.SignPKCS1v15(rand.Reader, r.privateKey, r.hash, r.HashData(header, payload))
}

func (r *RS256) Verify(header, payload, decodedSignature []byte) (bool, error) {
	err := rsa.VerifyPKCS1v15(r.publicKey, r.hash, r.HashData(header, payload), decodedSignature)

	return err == nil, err
}

func (r *RS256) HashData(header []byte, payload []byte) []byte {
	generator := r.hash.New()

	generator.Write(header)
	generator.Write(payload)

	return generator.Sum(nil)
}
