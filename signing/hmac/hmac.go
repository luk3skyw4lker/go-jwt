package hmac

import (
	"crypto"
	"errors"
	"fmt"
	"slices"
)

type HMACSigning struct {
	name string
	hash crypto.Hash
	key  []byte
}

var (
	HS256        = New(crypto.SHA256, "")
	HS224        = New(crypto.SHA224, "")
	HS512        = New(crypto.SHA512, "")
	ErrKeyNotSet = errors.New("key not set, use SetKey or instantiate a new signing method setting the keys")
)

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

func (s *HMACSigning) SetKey(key []byte) {
	s.key = key
}

func (s *HMACSigning) Name() string {
	return s.name
}

func (s *HMACSigning) Sign(header []byte, payload []byte) ([]byte, error) {
	if s.key == nil {
		return nil, ErrKeyNotSet
	}

	mac := s.hash.New()

	mac.Write(header)
	mac.Write(payload)

	return mac.Sum(nil), nil
}

func (s *HMACSigning) Verify(header, payload, decodedSignature []byte) (bool, error) {
	hmac, err := s.Sign(header, payload)
	if err != nil {
		return false, err
	}

	return slices.Compare(hmac, decodedSignature) == 0, nil
}
