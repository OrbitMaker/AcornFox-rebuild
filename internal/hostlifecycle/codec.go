package hostlifecycle

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	allowedHelloKeys = map[string]struct{}{
		"type":           {},
		"schema_version": {},
	}

	allowedAdmitKeys = map[string]struct{}{
		"type":           {},
		"schema_version": {},
		"operation":      {},
		"role":           {},
		"slot_id":        {},
		"instance_id":    {},
		"nonce":          {},
	}

	allowedReselectKeys = map[string]struct{}{
		"type":           {},
		"schema_version": {},
		"nonce":          {},
		"reason_code":    {},
		"active_slot_id": {},
	}

	allowedResultKeys = map[string]struct{}{
		"type":           {},
		"schema_version": {},
		"nonce":          {},
		"operation":      {},
		"state":          {},
		"reason_code":    {},
		"version":        {},
		"slot_id":        {},
	}
)

// WriteFrame writes a 4-byte big-endian length prefix followed by the payload.
// It guarantees a complete write across any short writes on stream connections.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return ErrEmptyFrame
	}
	if len(payload) > MaxFramePayloadSize {
		return ErrFrameTooLarge
	}
	buf := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint32(buf[:HeaderSize], uint32(len(payload)))
	copy(buf[HeaderSize:], payload)

	total := 0
	for total < len(buf) {
		n, err := w.Write(buf[total:])
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		total += n
	}
	return nil
}

// ReadFrame reads a 4-byte big-endian length prefix and exactly length payload bytes.
func ReadFrame(r io.Reader) ([]byte, error) {
	var header [HeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrFrameTruncated
		}
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 {
		return nil, ErrEmptyFrame
	}
	if length > MaxFramePayloadSize {
		return nil, ErrFrameTooLarge
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, ErrFrameTruncated
	}
	return payload, nil
}

func checkStrictJSONKeys(data []byte, allowed map[string]struct{}) error {
	if len(data) == 0 {
		return ErrEmptyFrame
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return ErrProtocolViolation
	}

	seenLower := make(map[string]string)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return ErrProtocolViolation
		}
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("%w: field %q", ErrUnknownField, key)
		}
		lower := strings.ToLower(key)
		if prior, exists := seenLower[lower]; exists {
			return fmt.Errorf("%w: %q conflicts with %q", ErrDuplicateField, key, prior)
		}
		seenLower[lower] = key

		valTok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := valTok.(json.Delim); ok {
			_ = d
			return ErrProtocolViolation
		}
	}

	tok, err = dec.Token()
	if err != nil || tok != json.Delim('}') {
		return ErrProtocolViolation
	}

	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrProtocolViolation
	}
	return nil
}

// DetectFrameType inspects the frame payload to determine its frame type.
func DetectFrameType(data []byte) (string, error) {
	if len(data) == 0 {
		return "", ErrEmptyFrame
	}
	if len(data) > MaxFramePayloadSize {
		return "", ErrFrameTooLarge
	}
	var probe struct {
		Type string `json:"type"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&probe); err != nil {
		return "", err
	}
	switch probe.Type {
	case FrameTypeHello, FrameTypeAdmit, FrameTypeReselect, FrameTypeResult:
		return probe.Type, nil
	default:
		return "", ErrInvalidFrameType
	}
}

// DecodeHello strictly decodes and validates a HelloFrame with canonical byte equality.
func DecodeHello(data []byte) (*HelloFrame, error) {
	if err := checkStrictJSONKeys(data, allowedHelloKeys); err != nil {
		return nil, err
	}
	var h HelloFrame
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return nil, err
	}
	if h.Type != FrameTypeHello {
		return nil, ErrInvalidFrameType
	}
	if h.SchemaVersion != ProtocolVersion1 {
		return nil, ErrInvalidSchema
	}
	canonical, err := json.Marshal(h)
	if err != nil || !bytes.Equal(bytes.TrimSpace(data), canonical) {
		return nil, fmt.Errorf("%w: non-canonical JSON representation", ErrProtocolViolation)
	}
	return &h, nil
}

// EncodeHello canonicalizes and encodes a HelloFrame.
func EncodeHello(h *HelloFrame) ([]byte, error) {
	if h == nil || h.Type != FrameTypeHello || h.SchemaVersion != ProtocolVersion1 {
		return nil, ErrProtocolViolation
	}
	raw, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxFramePayloadSize {
		return nil, ErrFrameTooLarge
	}
	return raw, nil
}

// DecodeAdmit strictly decodes and validates an AdmitFrame with canonical byte equality.
func DecodeAdmit(data []byte) (*AdmitFrame, error) {
	if err := checkStrictJSONKeys(data, allowedAdmitKeys); err != nil {
		return nil, err
	}
	var a AdmitFrame
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, err
	}
	if a.Type != FrameTypeAdmit {
		return nil, ErrInvalidFrameType
	}
	if a.SchemaVersion != ProtocolVersion1 {
		return nil, ErrInvalidSchema
	}
	if !IsValidOperation(a.Operation) {
		return nil, ErrInvalidOperation
	}
	if !IsValidRole(a.Role) {
		return nil, ErrInvalidRole
	}
	if !IsValidHexSHA256(a.SlotID) {
		return nil, ErrInvalidSlotID
	}
	if !IsValidHexSHA256(a.InstanceID) {
		return nil, ErrInvalidInstanceID
	}
	if !IsValidHexNonce(a.Nonce) {
		return nil, ErrInvalidNonce
	}
	canonical, err := json.Marshal(a)
	if err != nil || !bytes.Equal(bytes.TrimSpace(data), canonical) {
		return nil, fmt.Errorf("%w: non-canonical JSON representation", ErrProtocolViolation)
	}
	return &a, nil
}

// EncodeAdmit canonicalizes and encodes an AdmitFrame.
func EncodeAdmit(a *AdmitFrame) ([]byte, error) {
	if a == nil || a.Type != FrameTypeAdmit || a.SchemaVersion != ProtocolVersion1 {
		return nil, ErrProtocolViolation
	}
	if !IsValidOperation(a.Operation) || !IsValidRole(a.Role) ||
		!IsValidHexSHA256(a.SlotID) || !IsValidHexSHA256(a.InstanceID) ||
		!IsValidHexNonce(a.Nonce) {
		return nil, ErrProtocolViolation
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxFramePayloadSize {
		return nil, ErrFrameTooLarge
	}
	return raw, nil
}

// DecodeReselect strictly decodes and validates a ReselectFrame with canonical byte equality.
func DecodeReselect(data []byte) (*ReselectFrame, error) {
	if err := checkStrictJSONKeys(data, allowedReselectKeys); err != nil {
		return nil, err
	}
	var r ReselectFrame
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, err
	}
	if r.Type != FrameTypeReselect {
		return nil, ErrInvalidFrameType
	}
	if r.SchemaVersion != ProtocolVersion1 {
		return nil, ErrInvalidSchema
	}
	if !IsValidHexNonce(r.Nonce) {
		return nil, ErrInvalidNonce
	}
	if !IsValidReasonCode(r.ReasonCode) {
		return nil, ErrProtocolViolation
	}
	if !IsValidHexSHA256(r.ActiveSlotID) {
		return nil, ErrInvalidSlotID
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(bytes.TrimSpace(data), canonical) {
		return nil, fmt.Errorf("%w: non-canonical JSON representation", ErrProtocolViolation)
	}
	return &r, nil
}

// EncodeReselect canonicalizes and encodes a ReselectFrame.
func EncodeReselect(r *ReselectFrame) ([]byte, error) {
	if r == nil || r.Type != FrameTypeReselect || r.SchemaVersion != ProtocolVersion1 {
		return nil, ErrProtocolViolation
	}
	if !IsValidHexNonce(r.Nonce) || !IsValidReasonCode(r.ReasonCode) || !IsValidHexSHA256(r.ActiveSlotID) {
		return nil, ErrProtocolViolation
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxFramePayloadSize {
		return nil, ErrFrameTooLarge
	}
	return raw, nil
}

// DecodeResult strictly decodes and validates a ResultFrame with canonical byte equality.
func DecodeResult(data []byte) (*ResultFrame, error) {
	if err := checkStrictJSONKeys(data, allowedResultKeys); err != nil {
		return nil, err
	}
	var res ResultFrame
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&res); err != nil {
		return nil, err
	}
	if res.Type != FrameTypeResult {
		return nil, ErrInvalidFrameType
	}
	if res.SchemaVersion != ProtocolVersion1 {
		return nil, ErrInvalidSchema
	}
	if !IsValidHexNonce(res.Nonce) {
		return nil, ErrInvalidNonce
	}
	if !IsValidOperation(res.Operation) {
		return nil, ErrInvalidOperation
	}
	if !IsValidState(res.State) {
		return nil, fmt.Errorf("%w: invalid state %q", ErrProtocolViolation, res.State)
	}
	if !IsValidReasonCode(res.ReasonCode) {
		return nil, fmt.Errorf("%w: invalid reason code %q", ErrProtocolViolation, res.ReasonCode)
	}
	if !IsValidSemver(res.Version) {
		return nil, fmt.Errorf("%w: invalid semver %q", ErrProtocolViolation, res.Version)
	}
	if !IsValidHexSHA256(res.SlotID) {
		return nil, ErrInvalidSlotID
	}
	canonical, err := json.Marshal(res)
	if err != nil || !bytes.Equal(bytes.TrimSpace(data), canonical) {
		return nil, fmt.Errorf("%w: non-canonical JSON representation", ErrProtocolViolation)
	}
	return &res, nil
}

// EncodeResult canonicalizes and encodes a ResultFrame.
func EncodeResult(res *ResultFrame) ([]byte, error) {
	if res == nil || res.Type != FrameTypeResult || res.SchemaVersion != ProtocolVersion1 {
		return nil, ErrProtocolViolation
	}
	if !IsValidHexNonce(res.Nonce) || !IsValidOperation(res.Operation) || !IsValidState(res.State) ||
		!IsValidReasonCode(res.ReasonCode) || !IsValidSemver(res.Version) || !IsValidHexSHA256(res.SlotID) {
		return nil, ErrProtocolViolation
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxFramePayloadSize {
		return nil, ErrFrameTooLarge
	}
	return raw, nil
}
