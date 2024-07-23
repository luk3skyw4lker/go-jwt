package encoder

import (
	"errors"
)

func encodedLen(n int, padded bool) int {
	if !padded {
		return n/3*4 + (n%3*8+5)/6 // minimum # chars at 6 bits per char
	}

	return (n + 2) / 3 * 4 // minimum # 4-char quanta, 3 bytes each
}

func decodedLen(n int) int {
	return n / 4 * 3
}

func getBase64Code(charCode int, decodeMap [256]byte) (int, error) {
	if charCode > len(decodeMap) {
		return 0, errors.New("char is outside of base64url alphabet")
	}

	code := decodeMap[charCode]

	if code == 255 {
		return 0, errors.New("char is a invalid base64url char")
	}

	return int(code), nil
}
