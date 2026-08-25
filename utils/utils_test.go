package utils

import (
	"errors"
	"testing"
)

// TestSplitTokenDoesNotPanic is the regression test for a panic on input the
// caller does not control: SplitToken used to panic on anything with fewer
// than three segments, and every caller is holding a string that arrived from
// a client.
func TestSplitToken(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
		valid bool
	}{
		{"three segments", "aaa.bbb.ccc", true},
		{"empty", "", false},
		{"no separator", "notatoken", false},
		{"two segments", "aaa.bbb", false},
		{"four segments", "aaa.bbb.ccc.ddd", false},
		{"blank header", ".bbb.ccc", false},
		{"blank payload", "aaa..ccc", false},
		{"blank signature", "aaa.bbb.", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("SplitToken panicked on %q: %v", tc.token, r)
				}
			}()

			header, payload, signature, err := SplitToken(tc.token)
			if !tc.valid {
				if !errors.Is(err, ErrInvalidToken) {
					t.Fatalf("error = %v, want ErrInvalidToken", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("SplitToken: %v", err)
			}
			if header != "aaa" || payload != "bbb" || signature != "ccc" {
				t.Fatalf("got %q, %q, %q", header, payload, signature)
			}
		})
	}
}
