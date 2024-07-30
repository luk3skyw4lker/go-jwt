package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/luk3skyw4lker/go-jwt/encoder"
	"github.com/luk3skyw4lker/go-jwt/hmac/rs256"
	"github.com/luk3skyw4lker/go-jwt/jwt"
	"github.com/luk3skyw4lker/go-jwt/utils"
)

var Base64 *encoder.Encoder = encoder.MustNewEncoder(encoder.Base64URLAlphabet)

var hmacAlgorithm jwt.Hmac = utils.Must(rs256.New(utils.RSAPrivateKey, utils.RSAPublicKey))
var shouldPad = false

func generate() string {
	// You should store your secret into a safe environment variable and it should be a strong string
	jsonData, _ := json.Marshal(
		map[string]any{
			"sub":  "@luk3skyw4lker",
			"name": "Lucas",
			"iat":  1516239022,
		},
	)

	generator := jwt.NewGenerator(hmacAlgorithm, jwt.Options{ShouldPad: shouldPad})

	jwtString, _ := generator.Generate(jsonData)

	return jwtString
}

func degenerate() string {
	token := generate()

	log.Printf("token: %s", token)

	parts := strings.Split(token, ".")

	headerDecoded, err := Base64.DecodeBase64Url(parts[0], shouldPad)
	if err != nil {
		panic(err)
	}

	payloadDecoded, err := Base64.DecodeBase64Url(parts[1], shouldPad)
	if err != nil {
		panic(err)
	}

	return strings.Join([]string{string(headerDecoded), string(payloadDecoded)}, "\n")
}

func verify(token string) bool {
	if token == "" {
		return false
	}

	generator := jwt.NewGenerator(hmacAlgorithm, jwt.Options{ShouldPad: shouldPad})

	verified, err := generator.Verify(token)
	if err != nil {
		panic(err)
	}

	return verified
}

func main() {
	flag.Parse()

	arg := flag.Arg(0)

	switch arg {
	case "generate":
		fmt.Println(generate())
	case "degenerate":
		fmt.Println(degenerate())
	case "verify":
		fmt.Println(verify(flag.Arg(1)))
	default:
		fmt.Printf("invalid arg: %s", arg)
	}
}
