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

var (
	ErrInvalidToken                    = errors.New("invalid token sent to split")
	ErrFailedToParsePEMBlockPrivateKey = errors.New("failed to parse PEM block containing the private key")
	ErrFailedToParsePEMBlockPublicKey  = errors.New("failed to parse PEM block containing the public key")
	ErrFailedToParsePrivateKey         = errors.New("failed to parse private key")
	ErrFailedToParsePublicKey          = errors.New("failed to parse public key")
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
		panic(ErrInvalidToken)
	}

	return parts[0], parts[1], parts[2]
}

func ParseKeyPair(privateKey string, publicKey string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateBlock, _ := pem.Decode([]byte(privateKey))
	if privateBlock == nil {
		return nil, nil, ErrFailedToParsePEMBlockPrivateKey
	}

	publicBlock, _ := pem.Decode([]byte(publicKey))
	if publicBlock == nil {
		return nil, nil, ErrFailedToParsePEMBlockPublicKey
	}

	parsedPrivateKey, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
	if err != nil {
		return nil, nil, ErrFailedToParsePrivateKey
	}

	parsedPublicKey, err := x509.ParsePKCS1PublicKey(publicBlock.Bytes)
	if err != nil {
		return nil, nil, ErrFailedToParsePublicKey
	}

	return parsedPrivateKey, parsedPublicKey, nil
}

func Must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}

	return value
}
