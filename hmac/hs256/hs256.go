package hs256

import (
	"crypto/hmac"
	"crypto/sha256"
	"slices"
)

type HS256 struct {
	key []byte
}

func New(key string) *HS256 {
	return &HS256{
		key: []byte(key),
	}
}

func (HS256) Name() string {
	return "HS256"
}

// This function generates a
func (h *HS256) Generate(header []byte, payload []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, []byte(h.key))

	mac.Write(header)
	mac.Write(payload)

	return mac.Sum(nil), nil
}

func (h *HS256) Verify(header, payload, decodedSignature []byte) (bool, error) {
	hmac, err := h.Generate(header, payload)
	if err != nil {
		return false, err
	}

	return slices.Compare(hmac, decodedSignature) == 0, nil
}
