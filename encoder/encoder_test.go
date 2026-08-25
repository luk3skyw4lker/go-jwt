package encoder

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func enc(t *testing.T) *Encoder {
	t.Helper()
	e, err := NewEncoder(Base64URLAlphabet)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	return e
}

// TestAgreesWithStdlib pins this encoder to the standard library's, which is
// the only definition of "correct" worth having here: a token this package
// produces has to be readable by every other JWT implementation.
func TestAgreesWithStdlib(t *testing.T) {
	e := enc(t)

	inputs := [][]byte{
		[]byte("a"),
		[]byte("ab"),
		[]byte("abc"),
		[]byte("abcd"),
		[]byte(`{"alg":"HS256","typ":"JWT"}`),
		[]byte(`{"sub":"alice","exp":1893456000}`),
		{0x00, 0xff, 0xfe, 0x7f, 0x80},
	}

	for _, in := range inputs {
		t.Run(string(in), func(t *testing.T) {
			for _, padded := range []bool{false, true} {
				std := base64.RawURLEncoding
				if padded {
					std = base64.URLEncoding
				}

				got, err := e.EncodeBase64Url(in, padded)
				if err != nil {
					t.Fatalf("EncodeBase64Url: %v", err)
				}
				if want := std.EncodeToString(in); got != want {
					t.Fatalf("padded=%v encode = %q, want %q", padded, got, want)
				}

				back, err := e.DecodeBase64Url(got, padded)
				if err != nil {
					t.Fatalf("DecodeBase64Url: %v", err)
				}
				if !bytes.Equal(back, in) {
					t.Fatalf("padded=%v round trip = %q, want %q", padded, back, in)
				}
			}
		})
	}
}

// TestDecodeRejectsInvalidCharactersInEveryPosition covers a shadowed err:
// only the fourth character of each block was checked, so an invalid character
// in the other three decoded silently as zero.
func TestDecodeRejectsInvalidCharactersInEveryPosition(t *testing.T) {
	e := enc(t)

	const valid = "YWJjZGVm" // "abcdef"
	for i := range valid {
		bad := valid[:i] + "!" + valid[i+1:]

		if _, err := e.DecodeBase64Url(bad, false); err == nil {
			t.Fatalf("an invalid character at index %d decoded without an error: %q", i, bad)
		}
	}
}

func TestDecodeRejectsMalformedInput(t *testing.T) {
	e := enc(t)

	for _, tc := range []struct {
		name string
		data string
	}{
		{"one leftover character", "YWJjZGVmZ"},
		{"padding in the middle", "YW=jZGVm"},
		{"non-ascii", "YWJé"},
		{"multibyte rune", "YWJ一"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.DecodeBase64Url(tc.data, false); err == nil {
				t.Fatalf("%q decoded without an error", tc.data)
			}
		})
	}
}

func TestEncodeRejectsEmptyInput(t *testing.T) {
	e := enc(t)

	if _, err := e.EncodeBase64Url(nil, false); err != ErrNoData {
		t.Fatalf("error = %v, want ErrNoData", err)
	}
	if _, err := e.EncodeBase64UrlString("", false); err != ErrNoData {
		t.Fatalf("error = %v, want ErrNoData", err)
	}
}

func TestNewEncoderRejectsUnusableAlphabets(t *testing.T) {
	for _, tc := range []struct {
		name     string
		alphabet string
	}{
		{"newline", strings.Replace(Base64URLAlphabet, "A", "\n", 1)},
		{"carriage return", strings.Replace(Base64URLAlphabet, "A", "\r", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewEncoder(tc.alphabet); err == nil {
				t.Fatal("an alphabet containing a line break was accepted")
			}
		})
	}
}
