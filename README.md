# GO Jwt

A short library to generate your JWT. Lightweight and with no dependencies.

## Installation
```shell
go get github.com/luk3skyw4lker/go-jwt
```

## API
```go
type Hmac interface {
  Generate([]byte, []byte) ([]byte, error)
  Name() string
  Verify([]byte, []byte, []byte) (bool, error)
}

type Options struct {
  ShouldPad bool
}

type JWTGenerator struct {}

func NewGenerator(algorithm Hmac, options Options) *JWTGenerator

func (g *JWTGenerator) Generate(payload []byte) (string, error)
func (g *JWTGenerator) GenerateWithCustomHeader(headerInfo, payload []byte) (string, error)
func (g *JWTGenerator) Verify(token string) (bool, error)
```

### Errors

The errors are stored in their respective package, examples:

```go
package hmac

var ErrKeyNotSet = errors.New("key not set, use SetKey or instantiate a new signing method setting the keys")
```

```go
package rsa

var (
  ErrHashUnavailable = errors.New("hash unavailable")
  ErrKeyPairNotSet   = errors.New("key pair was not set, use SetKeyPair to set the keys or instantiate a new signing method setting the keys")
)
```

```go
package utils

var (
	ErrInvalidToken                    = errors.New("invalid token sent to split")
	ErrFailedToParsePEMBlockPrivateKey = errors.New("failed to parse PEM block containing the private key")
	ErrFailedToParsePEMBlockPublicKey  = errors.New("failed to parse PEM block containing the public key")
	ErrFailedToParsePrivateKey         = errors.New("failed to parse private key")
	ErrFailedToParsePublicKey          = errors.New("failed to parse public key")
)
```

```go
package encoder

var (
	ErrBreakLineInvalidChar      = errors.New("\\n is a invalid character for a base64 alphabet")
	ErrCarriageReturnInvalidChar = errors.New("\\r is a invalid character for a base64 alphabet")
	ErrGenericInvalidChar        = errors.New("invalid character in the alphabet")
	ErrNoData                    = errors.New("no data provided to encode")
	ErrWrongPadding              = errors.New("padding is wrong for base64url pattern")
	ErrCharOutsideAlphabet       = errors.New("char is outside of base64url alphabet")
)
```

## Usage

Here is a example code for generation and verification of your JWT:

```go
import (
  "crypto"
  "encoding/json"
  "flag"
  "fmt"
  "log"
  "strings"

  "github.com/luk3skyw4lker/go-jwt/encoder"
  "github.com/luk3skyw4lker/go-jwt/jwt"
  "github.com/luk3skyw4lker/go-jwt/signing/rsa"
  "github.com/luk3skyw4lker/go-jwt/utils"
)

var Base64 *encoder.Encoder = encoder.MustNewEncoder(encoder.Base64URLAlphabet)

var hmacAlgorithm jwt.Hmac = utils.Must(rsa.New(crypto.SHA256, utils.RSAPrivateKey, utils.RSAPublicKey))
var shouldPad = false

func main() {
  generator := jwt.NewGenerator(hmacAlgorithm, jwt.Options{ShouldPad: shouldPad})

  payload := utils.Must(
    json.Marshal(
      map[string]any{
        "sub":  "@luk3skyw4lker",
        "name": "Lucas",
        "iat":  1516239022,
      },
    ),
  )

  jwt, err := generator.Generate(payload)
  if err != nil {
    panic(err)
  }

  log.Printf("token: %s\n", jwt)

  verified, err := generator.Verify(jwt)
  if err != nil {
    panic(err)
  }

  log.Printf("verified: %s\n", verified)
}
```

You can generate padded data for your JWTs using the `shouldPad` option set to true, although it's not recommended and it's not in accordance with the JWT spec, you can do it here, the default option for this is false.

## Custom Headers

The library mainly uses a defaultHeader for all generated JWTs, but if you wan to customize your headers, you can do it, here's an example:

```go
import (
  "crypto"
  "log"

  "github.com/luk3skyw4lker/go-jwt/signing/hmac"
  "github.com/luk3skyw4lker/go-jwt/jwt"
)

var shouldPad = false

func main() {
  // the name of the key is your choice
  algorithm := hmac.New(crypto.SHA256, os.Getenv("JWT_SECRET_KEY"))
  generator := jwt.NewGenerator(algorithm, jwt.Options{ShouldPad: shouldPad})

  headerInfo := utils.Must(
    json.Marshal(
      map[string]any{
        "type":       "JWT",
        "custominfo": "info",
        "algorithm":  algorithm.Name(),
        "iat":        1516239022,
      },
    ),
  )
  payload := utils.Must(
    json.Marshal(
      map[string]any{
        "sub":  "@luk3skyw4lker",
        "name": "Lucas",
        "iat":  1516239022,
      },
    ),
  )

  jwt, err := generator.GenerateWithCustomHeader(headerInfo, payload)

  if err != nil {
    panic(err)
  }

  log.Printf("token: %s\n", jwt)

  verified, err := generator.Verify(jwt)
  if err != nil {
    panic(err)
  }

  log.Printf("verified: %s\n", verified)
}
```

# Signing Methods

There are a few methods that are supported out of the box by this library. Check them below.

The HMAC signing methods:

- HS224 (with SHA-224 as a hash algorithm)
- HS256 (with SHA-256 as a hash algorithm)
- HS512 (with SHA-512 as a hash algorithm)

The RSA signing methods:

- RS224 (with SHA-224 as a hash algorithm)
- RS256 (with SHA-256 as a hash algorithm)
- RS512 (with SHA-512 as a hash algorithm)

They can be found in the `github.com/luk3skyw4lker/go-jwt/signing/hmac` and `github.com/luk3skyw4lker/go-jwt/signing/rsa`, respectively.

You can also implement your own HMAC generation algorithm following the `Hmac` interface spec:

```go
type Hmac interface {
  Sign([]byte, []byte) ([]byte, error)
  Name() string
  Verify([]byte, []byte, []byte) (bool, error)
}
```

To ask for a different HMAC generation method to be implemented natively by the library, please open an issue specificating a feature request.