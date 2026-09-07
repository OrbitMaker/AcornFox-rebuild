package acornfoxsetup

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerateSetupTokenIsCanonicalAndBounded(t *testing.T) {
	seed := bytes.Repeat([]byte{0xab}, SetupTokenBytes)
	token, err := GenerateSetupToken(bytes.NewReader(seed))
	if err != nil || len(token) != 44 || token[len(token)-1] != '\n' || ValidateSetupToken(token) != nil {
		t.Fatalf("token shape is invalid: length=%d err=%v", len(token), err)
	}
	for _, invalid := range [][]byte{token[:43], append(append([]byte(nil), token...), '\n'), []byte(strings.Repeat("!", 43) + "\n")} {
		if ValidateSetupToken(invalid) == nil {
			t.Fatal("invalid token was accepted")
		}
	}
	if _, err := GenerateSetupToken(bytes.NewReader(seed[:31])); err == nil {
		t.Fatal("short randomness was accepted")
	}
}
