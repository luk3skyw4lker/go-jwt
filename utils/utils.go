package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
)

const (
	PublicKey  = "public"
	PrivateKey = "private"
)

func GenerateRSAKeyPair(writeOut bool) (string, string) {
	// Generate RSA key.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Extract public component.
	pub := key.Public()

	// Encode private key to PKCS#1 ASN.1 PEM.
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	// Encode public key to PKCS#1 ASN.1 PEM.
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub.(*rsa.PublicKey)),
		},
	)

	if writeOut {
		// Write private key to file.
		if err := os.WriteFile("key.rsa", keyPEM, 0700); err != nil {
			panic(err)
		}

		// Write public key to file.
		if err := os.WriteFile("key.rsa.pub", pubPEM, 0755); err != nil {
			panic(err)
		}
	}

	return string(keyPEM), string(pubPEM)
}

func SplitToken(token string) (string, string, string) {
	parts := strings.Split(token, ".")

	if len(parts) < 3 {
		panic(errors.New("invalid token sent to split"))
	}

	return parts[0], parts[1], parts[2]
}

func ParseKey(key string, keyType string) (any, error) {
	if keyType == "" {
		return nil, errors.New("cannot parse key without a type")
	}

	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	switch keyType {
	case "private":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "public":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, errors.New("invalid key type, it can only be 'public' or 'private'")
	}
}

func Must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}

	return value
}
