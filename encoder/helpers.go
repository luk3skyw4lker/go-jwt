package encoder

import (
	"errors"
)

func encodedLen(dataLength int) int {
	return (dataLength + 2) / 3 * 4
}

func decodedLen(dataLength int) int {
	return dataLength / 4 * 3
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
