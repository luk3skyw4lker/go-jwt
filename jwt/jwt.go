package jwt

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luk3skyw4lker/go-jwt/v2/encoder"
	"github.com/luk3skyw4lker/go-jwt/v2/utils"
)

var Base64URLEncoder *encoder.Encoder = encoder.MustNewEncoder(encoder.Base64URLAlphabet)

var (
	// ErrAlgorithmMismatch reports a token whose header names an algorithm
	// this generator does not sign with.
	ErrAlgorithmMismatch = errors.New("token algorithm does not match the verifier")

	// ErrUnreadableHeader reports a first segment that does not decode to a
	// JSON object.
	ErrUnreadableHeader = errors.New("token header is not readable JSON")
)

type Hmac interface {
	Sign([]byte, []byte) ([]byte, error)
	Name() string
	Verify([]byte, []byte, []byte) (bool, error)
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

	hmac, err := g.hmac.Sign([]byte(header), []byte(payload))
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

// Verify reports whether a token was signed by this generator's algorithm and
// key, and whether it names that algorithm in its header.
//
// A token that fails signature verification is (false, nil). Malformed tokens
// or configuration problems are reported as (false, err). Nothing about a
// presented token is trusted before it verifies.
func (g *JWTGenerator) Verify(jwt string) (bool, error) {
	header, payload, signature, err := utils.SplitToken(jwt)
	if err != nil {
		return false, err
	}

	if err := g.checkAlgorithm(header); err != nil {
		return false, err
	}

	decodedSignature, err := Base64URLEncoder.DecodeBase64Url(signature, g.options.ShouldPad)
	if err != nil {
		return false, err
	}

	return g.hmac.Verify([]byte(header), []byte(payload), decodedSignature)
}

// checkAlgorithm refuses a token whose header names an algorithm other than
// the one this generator holds.
//
// The header is attacker-controlled, so it can never be allowed to select the
// verifier: that is the "alg" substitution attack, whose worst form is a token
// claiming "none". Here the algorithm is fixed by whoever constructed the
// generator, and the header is checked against it rather than consulted.
func (g *JWTGenerator) checkAlgorithm(encodedHeader string) error {
	raw, err := Base64URLEncoder.DecodeBase64Url(encodedHeader, g.options.ShouldPad)
	if err != nil {
		return err
	}

	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return fmt.Errorf("%w: %w", ErrUnreadableHeader, err)
	}

	if header.Alg != g.hmac.Name() {
		return fmt.Errorf("%w: token says %q, verifier is %q",
			ErrAlgorithmMismatch, header.Alg, g.hmac.Name())
	}
	return nil
}
