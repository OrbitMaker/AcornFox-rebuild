package secret

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strings"
)

// DeriveExistingContextKey derives a stable, domain-separated key from an
// already-provisioned installation master key. It never creates or rotates the
// master key, which makes it safe for read-only server features that need a
// restart-stable signing key.
func DeriveExistingContextKey(masterKeyPath, label string) ([32]byte, error) {
	var derived [32]byte
	label = strings.TrimSpace(label)
	if label == "" || len(label) > 128 || strings.ContainsRune(label, 0) {
		return derived, errors.New("context key label is invalid")
	}
	_, master, err := loadExistingMasterKey(masterKeyPath)
	if err != nil {
		return derived, errors.New("existing secret master key is unavailable")
	}
	defer zeroBytes(master[:])
	mac := hmac.New(sha256.New, master[:])
	_, _ = mac.Write([]byte("open-card-context-key-v1\x00" + label))
	copy(derived[:], mac.Sum(nil))
	return derived, nil
}

// ZeroContextKey clears a derived context key when its owning composition is
// shutting down. Callers never need access to the installation master key.
func ZeroContextKey(key *[32]byte) {
	if key != nil {
		zeroBytes(key[:])
	}
}
