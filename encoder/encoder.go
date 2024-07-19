//nolint:ineffassign
package encoder

import (
	"errors"
	"strings"
)

var Base64URLAlphabet string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

var Base64URLEncoder *Encoder = must(NewEncoder(Base64URLAlphabet))

var padChar rune = '='

type Encoder struct {
	alphabet      []string
	bytesAlphabet [64]byte
	decodeMap     [256]byte
}

func must[T any](data T, err error) T {
	if err != nil {
		panic(err)
	}

	return data
}

func MustNewEncoder(alphabet string) *Encoder {
	return must(NewEncoder(alphabet))
}

func NewEncoder(alphabet string) (*Encoder, error) {
	enc := Encoder{
		alphabet: strings.Split(alphabet, ""),
	}

	copy(enc.bytesAlphabet[:], alphabet)
	copy(enc.decodeMap[:], decodeMapInitialize)

	for i := 0; i < len(alphabet); i++ {
		switch alphabet[i] {
		case '\n':
			return nil, errors.New("\\n is a invalid character for a base64 alphabet")
		case '\r':
			return nil, errors.New("\\r is a invalid character for a base64 alphabet")
		case invalidIndex:
			return nil, errors.New("invalid character in the alphabet")
		}

		enc.decodeMap[alphabet[i]] = uint8(i)
	}

	return &enc, nil
}

func (e *Encoder) addRemainingSmallBlock(data, result []byte, remaining, j, i int) ([]byte, uint) {
	val := uint(data[j]) << 16
	if remaining == 2 {
		val |= uint(data[j+1]) << 8
	}

	result[i] = e.bytesAlphabet[val>>18&0x3f]
	result[i+1] = e.bytesAlphabet[val>>12&0x3f]

	return result, val
}

func (e *Encoder) EncodeBase64Url(data []byte) (string, error) {
	if len(data) == 0 {
		return "", errors.New("no data provided to encode")
	}

	result := make([]byte, (len(data)+2)/3*4)
	i, j := 0, 0
	// This is to reduce the number to the closest multiple of 3 before it
	// like if the length of data is 32 this will result in 30
	n := (len(data) / 3) * 3
	for j < n {
		val := uint(data[j])<<16 | uint(data[j+1])<<8 | uint(data[j+2])

		result[i] = e.bytesAlphabet[val>>18&0x3f]
		result[i+1] = e.bytesAlphabet[val>>12&0x3f]
		result[i+2] = e.bytesAlphabet[val>>6&0x3f]
		result[i+3] = e.bytesAlphabet[val&0x3f]

		j += 3
		i += 4
	}

	switch remaining := len(data) - j; remaining {
	case 0:
		return string(result), nil
	case 2:
		result, val := e.addRemainingSmallBlock(data, result, remaining, j, i)

		result[i+2] = e.bytesAlphabet[val>>6&0x3F]
		result[i+3] = byte(padChar)
	case 1:
		result, _ = e.addRemainingSmallBlock(data, result, remaining, j, i)

		result[i+2] = byte(padChar)
		result[i+3] = byte(padChar)
	}

	return string(result), nil
}

func (e *Encoder) EncodeBase64UrlString(data string) (string, error) {
	if data == "" {
		return "", errors.New("no data provided to encode")
	}

	return e.EncodeBase64Url([]byte(data))
}

func (e *Encoder) DecodeBase64Url(data string) (string, error) {
	if len(data)%4 != 0 {
		return "", errors.New("string is not at the right length for base64url")
	}

	padIndex := strings.Index(data, "=")

	if padIndex != -1 && padIndex < len(data)-2 {
		return "", errors.New("padding is wrong for base64url pattern")
	}

	var missingOctets int
	if strings.HasSuffix(data, "==") {
		missingOctets = 2
	} else if strings.HasSuffix(data, "=") {
		missingOctets = 2
	} else {
		missingOctets = 0
	}

	var i = 0
	var j = 0
	var result = make([]byte, (len(data)*3)/4)

	for i = 0; i < len(data); {
		firstCode, err := getBase64Code(int([]rune(data)[i]), e.decodeMap)
		secondCode, err := getBase64Code(int([]rune(data)[i+1]), e.decodeMap)
		thirdCode, err := getBase64Code(int([]rune(data)[i+2]), e.decodeMap)
		fourthCode, err := getBase64Code(int([]rune(data)[i+3]), e.decodeMap)

		if err != nil {
			return "", err
		}

		buffer := firstCode<<18 | secondCode<<12 | thirdCode<<6 | fourthCode

		result[j] = byte(buffer >> 16)
		result[j+1] = byte((buffer >> 8) & 0xff)
		result[j+2] = byte(buffer & 0xff)

		i += 4
		j += 3
	}

	return string(result[0 : len(result)-missingOctets]), nil
}
