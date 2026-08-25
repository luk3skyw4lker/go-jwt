package jwt

import (
	"crypto"
	stdhmac "crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/luk3skyw4lker/go-jwt/v2/signing/hmac"
	"github.com/luk3skyw4lker/go-jwt/v2/utils"
)

func generator(t *testing.T, key string, opts ...Options) *JWTGenerator {
	t.Helper()
	return NewGenerator(hmac.New(crypto.SHA256, key), opts...)
}

func TestGenerateAndVerify(t *testing.T) {
	for _, padded := range []bool{false, true} {
		name := "unpadded"
		if padded {
			name = "padded"
		}

		t.Run(name, func(t *testing.T) {
			g := generator(t, "secret", Options{ShouldPad: padded})

			token, err := g.Generate([]byte(`{"sub":"alice","exp":1893456000}`))
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if strings.Count(token, ".") != 2 {
				t.Fatalf("token is not three segments: %q", token)
			}

			ok, err := g.Verify(token)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !ok {
				t.Fatal("a freshly generated token did not verify")
			}
		})
	}
}

func TestGeneratedHeaderNamesTheAlgorithm(t *testing.T) {
	g := generator(t, "secret")

	token, err := g.Generate([]byte(`{"sub":"alice"}`))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	encoded, _, _, err := utils.SplitToken(token)
	if err != nil {
		t.Fatalf("SplitToken: %v", err)
	}
	raw, err := Base64URLEncoder.DecodeBase64Url(encoded, false)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}

	var header map[string]string
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header["alg"] != "HS256" || header["typ"] != "JWT" {
		t.Fatalf("header = %v", header)
	}
}

// TestVerifyRejectsAnotherKeysToken is the end-to-end form of the forgery: a
// token minted with one secret must not verify under another.
func TestVerifyRejectsAnotherKeysToken(t *testing.T) {
	token, err := generator(t, "the-real-key").Generate([]byte(`{"sub":"alice"}`))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	ok, err := generator(t, "a-completely-different-key").Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("a token verified under a key that did not sign it")
	}
}

func TestVerifyRejectsATamperedPayload(t *testing.T) {
	g := generator(t, "secret")

	token, err := g.Generate([]byte(`{"sub":"alice"}`))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	forgedPayload, err := Base64URLEncoder.EncodeBase64Url([]byte(`{"sub":"admin"}`), false)
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	parts := strings.Split(token, ".")
	tampered := strings.Join([]string{parts[0], forgedPayload, parts[2]}, ".")

	ok, err := g.Verify(tampered)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("a token verified after its payload was rewritten")
	}
}

// TestVerifyRefusesAForeignAlgorithm covers alg substitution, whose worst form
// is a token claiming "none". The header is attacker-controlled and so must
// never select the verifier.
func TestVerifyRefusesAForeignAlgorithm(t *testing.T) {
	g := generator(t, "secret")

	for _, alg := range []string{"none", "HS512", "RS256", ""} {
		t.Run(alg, func(t *testing.T) {
			header, err := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
			if err != nil {
				t.Fatalf("marshal header: %v", err)
			}

			token, err := g.GenerateWithCustomHeader(header, []byte(`{"sub":"admin"}`))
			if err != nil {
				t.Fatalf("GenerateWithCustomHeader: %v", err)
			}

			// The token is correctly signed with the right key; only the
			// algorithm it names is wrong. It must still be refused.
			ok, err := g.Verify(token)
			if ok {
				t.Fatal("a token naming another algorithm verified")
			}
			if !errors.Is(err, ErrAlgorithmMismatch) {
				t.Fatalf("error = %v, want ErrAlgorithmMismatch", err)
			}
		})
	}
}

func TestVerifyRejectsMalformedTokens(t *testing.T) {
	g := generator(t, "secret")

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"one segment", "garbage"},
		{"two segments", "aaa.bbb"},
		{"four segments", "aaa.bbb.ccc.ddd"},
		{"header is not json", "Zm9v.YmFy.YmF6"},
		{"signature is not base64url", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.!!!!"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Verify panicked on %q: %v", tc.token, r)
				}
			}()

			ok, err := g.Verify(tc.token)
			if ok {
				t.Fatal("a malformed token verified")
			}
			if err == nil {
				t.Fatal("a malformed token was refused without saying why")
			}
		})
	}
}

// TestTokenMatchesRFC7515 pins the wire format to the specification rather
// than to this implementation: the signature must be the MAC over
// "header.payload", so that a token minted here verifies in every other
// library and vice versa.
func TestTokenMatchesRFC7515(t *testing.T) {
	const secret = "super-secret-key"

	token, err := generator(t, secret).Generate([]byte(`{"sub":"alice"}`))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	parts := strings.Split(token, ".")

	mac := stdhmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if parts[2] != want {
		t.Fatalf("signature = %q, want %q (HMAC-SHA256 over header.payload)", parts[2], want)
	}
}
