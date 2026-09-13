package hostlifecycle

import "errors"

const (
	// MaxFramePayloadSize defines the maximum size in bytes for a single frame payload.
	MaxFramePayloadSize = 4096

	// HeaderSize defines the 4-byte big-endian framing header.
	HeaderSize = 4

	// ProtocolVersion1 is the only supported protocol version.
	ProtocolVersion1 = 1

	// SHA256HexLength is the fixed length of a hex-encoded SHA-256 digest.
	SHA256HexLength = 64

	// NonceHexLength is the fixed length of a 32-byte hex-encoded random nonce.
	NonceHexLength = 64
)

var (
	ErrFrameTooLarge     = errors.New("hostlifecycle: frame payload exceeds 4096 bytes")
	ErrFrameTruncated   = errors.New("hostlifecycle: frame truncated or incomplete")
	ErrEmptyFrame       = errors.New("hostlifecycle: empty frame payload")
	ErrInvalidFrameType = errors.New("hostlifecycle: invalid or unrecognized frame type")
	ErrInvalidSchema    = errors.New("hostlifecycle: unsupported schema version")
	ErrUnknownField     = errors.New("hostlifecycle: unknown field in payload")
	ErrDuplicateField   = errors.New("hostlifecycle: duplicate or case-conflicting field")
	ErrInvalidOperation = errors.New("hostlifecycle: invalid operation")
	ErrInvalidRole      = errors.New("hostlifecycle: invalid role")
	ErrInvalidSlotID    = errors.New("hostlifecycle: invalid slot ID")
	ErrInvalidInstanceID= errors.New("hostlifecycle: invalid instance ID")
	ErrInvalidNonce     = errors.New("hostlifecycle: invalid nonce")
	ErrProtocolViolation= errors.New("hostlifecycle: protocol sequence violation")
)
