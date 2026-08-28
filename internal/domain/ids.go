package domain

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// ID is an opaque identifier. Prefixes make logs and evidence easier to read
// while the random suffix prevents callers from deriving object ordering.
type ID string

func (id ID) String() string { return string(id) }
func (id ID) Empty() bool    { return strings.TrimSpace(string(id)) == "" }

func NewID(prefix string) (ID, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	prefix = strings.Trim(strings.TrimSpace(prefix), "_")
	if prefix == "" {
		return ID(hex.EncodeToString(raw[:])), nil
	}
	return ID(prefix + "_" + hex.EncodeToString(raw[:])), nil
}

func MustNewID(prefix string) ID {
	id, err := NewID(prefix)
	if err != nil {
		panic(err)
	}
	return id
}

func RequireID(id ID, field string) error {
	if id.Empty() {
		return ValidationError(field + " is required")
	}
	return nil
}
