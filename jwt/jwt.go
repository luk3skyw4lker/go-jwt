package jwt

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/luk3skyw4lker/go-jwt/encoder"
	"github.com/luk3skyw4lker/go-jwt/utils"
)

var Base64URLEncoder *encoder.Encoder = encoder.MustNewEncoder(encoder.Base64URLAlphabet)

type Hmac interface {
	Generate([]byte, []byte) ([]byte, error)
	Name() string
}

type Options struct {
	ShouldPad bool
}

type JWTGenerator struct {
	hmac          Hmac
	options       Options
	defaultHeader []byte
}

func NewGenerator(algorithm Hmac, options ...Options) *JWTGenerator {
	var opt Options
	if len(options) > 0 {
		opt.ShouldPad = options[0].ShouldPad
	}

	generator := JWTGenerator{
		hmac:    algorithm,
		options: opt,
		defaultHeader: utils.Must(
			json.Marshal(map[string]string{
				"alg": algorithm.Name(),
				"typ": "JWT",
			}),
		),
	}

	return &generator
}

func (g *JWTGenerator) GenerateWithCustomHeader(headerInfo []byte, payloadInfo []byte) (string, error) {
	header, err := Base64URLEncoder.EncodeBase64Url(headerInfo, g.options.ShouldPad)
	if err != nil {
		return "", err
	}

	payload, err := Base64URLEncoder.EncodeBase64Url(payloadInfo, g.options.ShouldPad)
	if err != nil {
		return "", err
	}

	hmac, err := g.hmac.Generate([]byte(header), []byte(payload))
	if err != nil {
		return "", err
	}

	signature, err := Base64URLEncoder.EncodeBase64Url(hmac, g.options.ShouldPad)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s.%s", header, payload, signature), nil
}

func (g *JWTGenerator) Generate(payload []byte) (string, error) {
	return g.GenerateWithCustomHeader(g.defaultHeader, payload)
}

func (g *JWTGenerator) Verify(jwt string) (bool, error) {
	parts := strings.Split(jwt, ".")

	hmac, err := g.hmac.Generate([]byte(parts[0]), []byte(parts[1]))
	if err != nil {
		return false, err
	}

	encodedHmac, err := Base64URLEncoder.EncodeBase64Url(hmac, g.options.ShouldPad)
	if err != nil {
		return false, err
	}

	return encodedHmac == parts[2], nil
}
