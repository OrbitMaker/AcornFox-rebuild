package acornfoxsetup

import (
	"encoding/base64"
	"errors"
	"io"
)

const SetupTokenBytes = 32

// GenerateSetupToken creates the server-only first-install token. The trailing
// newline is intentional: systemd credentials are line-oriented files, while
// the receiving API accepts exactly one final LF and no other whitespace.
func GenerateSetupToken(randomness io.Reader) ([]byte, error) {
	if randomness == nil {
		return nil, errors.New("AcornFox setup randomness is required")
	}
	raw := make([]byte, SetupTokenBytes)
	if _, err := io.ReadFull(randomness, raw); err != nil {
		return nil, err
	}
	return append([]byte(base64.RawURLEncoding.EncodeToString(raw)), '\n'), nil
}

// ValidateSetupToken accepts only the canonical 32-byte RFC 4648 base64url
// representation with its single final line feed.
func ValidateSetupToken(value []byte) error {
	if len(value) != base64.RawURLEncoding.EncodedLen(SetupTokenBytes)+1 || value[len(value)-1] != '\n' {
		return errInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(value[:len(value)-1]))
	if err != nil || len(raw) != SetupTokenBytes || base64.RawURLEncoding.EncodeToString(raw) != string(value[:len(value)-1]) {
		return errInvalid
	}
	return nil
}
