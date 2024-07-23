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

## Usage

Here is a example code for generation and verification of your JWT:

```go
import (
  "log"

  "github.com/luk3skyw4lker/go-jwt/hmac"
  "github.com/luk3skyw4lker/go-jwt/jwt"
)

var shouldPad = false

func main() {
  // the name of the key is your choice
  algorithm := hmac.NewHS256(os.Getenv("JWT_SECRET_KEY"))
  generator := jwt.NewGenerator(algorithm, jwt.Options{ShouldPad: shouldPad})

  jsonData, _ := json.Marshal(
		map[string]any{
			"sub":  "@luk3skyw4lker",
			"name": "Lucas",
			"iat":  1516239022,
		},
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

You can generate padded data for your JWTs using the `shouldPad` option set to true, although it's not recommended and it's not in accordance with the JWT spec, you can do it in this lib.

## Custom Headers

The library mainly uses a defaultHeader for all generated JWTs, but if you wan to customize your headers, you can do it, here's an example:

```go
import (
  "log"

  "github.com/luk3skyw4lker/go-jwt/hmac"
  "github.com/luk3skyw4lker/go-jwt/jwt"
)

var shouldPad = false

func main() {
  // the name of the key is your choice
  algorithm := hmac.NewHS256(os.Getenv("JWT_SECRET_KEY"))
  generator := jwt.NewGenerator(algorithm, jwt.Options{ShouldPad: shouldPad})

  headerInfo, _ := json.Marshal(
    map[string]any{
			"type":       "JWT",
			"custominfo": "info",
      "algorithm":  algorithm.Name(),
			"iat":        1516239022,
		},
  )
  jsonData, _ := json.Marshal(
		map[string]any{
			"sub":  "@luk3skyw4lker",
			"name": "Lucas",
			"iat":  1516239022,
		},
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

# HMACs

The library offers two HMAC generation algorithms out of the box: `HS256` and `RS256`, you can import them from `github.com/luk3skyw4lker/go-jwt/hmac` and instantiate each one of them with the methods: `NewHS256` and `NewRS256`. Both of those methods accepts a key which will be used in your JWT generation.

You can also implement your own HMAC generation algorithm following the `Hmac` interface spec:

```go
type Hmac interface {
	Generate([]byte, []byte) ([]byte, error)
	Name() string
}
```

To ask for a different HMAC generation method to be implemented natively by the library, please open an issue specificating a feature request.