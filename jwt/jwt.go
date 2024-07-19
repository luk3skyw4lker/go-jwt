package jwt

import (
	"fmt"

	"github.com/luk3skyw4lker/go-jwt/encoder"
)

type Hmac interface {
	Generate([]byte, []byte) ([]byte, error)
	Name() string
}

var Base64URLEncoder *encoder.Encoder = encoder.MustNewEncoder("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

func Generate(headerInfo []byte, payloadInfo []byte, hmacAlgorithm Hmac) (string, error) {
	header, err := Base64URLEncoder.EncodeBase64Url(headerInfo)
	if err != nil {
		return "", err
	}

	payload, err := Base64URLEncoder.EncodeBase64Url(payloadInfo)
	if err != nil {
		return "", err
	}

	hmac, err := hmacAlgorithm.Generate([]byte(header), []byte(payload))
	if err != nil {
		return "", err
	}

	signature, err := Base64URLEncoder.EncodeBase64Url(hmac)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s.%s", header, payload, signature), nil
}
