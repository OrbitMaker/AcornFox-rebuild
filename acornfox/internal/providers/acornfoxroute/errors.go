package acornfoxroute

import "errors"

// Route provider errors. Callers classify them with errors.Is.
var (
	ErrPublicAccessConflict          = errors.New("public access conflict")
	ErrPublicAccessOwnershipConflict = errors.New("public access ownership conflict")
	ErrPublicAccessUnavailable       = errors.New("public access unavailable")
)
