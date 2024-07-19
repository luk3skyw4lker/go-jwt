package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/luk3skyw4lker/go-jwt/encoder"
	"github.com/luk3skyw4lker/go-jwt/hmac"
	"github.com/luk3skyw4lker/go-jwt/jwt"
)

var Base64 *encoder.Encoder = encoder.MustNewEncoder(encoder.Base64URLAlphabet)

func generate() string {
	// You should store your secret into a safe environment variable and it should be a strong string
	algorithm := hmac.NewHS256("secret")

	jsonData, _ := json.Marshal(map[string]any{
		"sub":  "@luk3skyw4lker",
		"name": "Lucas",
		"iat":  1516239022,
	})
	headerInfo, _ := json.Marshal(
		map[string]string{
			"alg": algorithm.Name(),
			"typ": "JWT",
		},
	)

	jwtString, _ := jwt.Generate(headerInfo, jsonData, algorithm)

	return jwtString
}

func degenerate() string {
	token := generate()

	parts := strings.Split(token, ".")

	headerDecoded, err := Base64.DecodeBase64Url(parts[0])
	if err != nil {
		panic(err)
	}

	payloadDecoded, err := Base64.DecodeBase64Url(parts[1])
	if err != nil {
		panic(err)
	}

	return strings.Join([]string{headerDecoded, payloadDecoded}, "\n")
}

func main() {
	flag.Parse()

	arg := flag.Arg(0)

	switch arg {
	case "generate":
		fmt.Println(generate())
	case "degenerate":
		fmt.Println(degenerate())
	default:
		fmt.Printf("invalid arg: %s", arg)
	}
}
