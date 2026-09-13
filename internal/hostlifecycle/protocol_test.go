package hostlifecycle

import (
	"bytes"
	"strings"
	"testing"
)

func TestFramingIO(t *testing.T) {
	var buf bytes.Buffer

	// Normal write and read
	payload := []byte(`{"type":"hello","schema_version":1}`)
	if err := WriteFrame(&buf, payload); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}
	read, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if !bytes.Equal(read, payload) {
		t.Fatalf("mismatched payload: got %s, want %s", read, payload)
	}

	// Empty payload rejected
	if err := WriteFrame(&buf, nil); err != ErrEmptyFrame {
		t.Fatalf("expected ErrEmptyFrame, got %v", err)
	}

	// Overlarge frame rejected
	overlarge := make([]byte, MaxFramePayloadSize+1)
	if err := WriteFrame(&buf, overlarge); err != ErrFrameTooLarge {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}

	// Truncated header
	truncatedBuf := bytes.NewReader([]byte{0, 0, 1})
	if _, err := ReadFrame(truncatedBuf); err != ErrFrameTruncated {
		t.Fatalf("expected ErrFrameTruncated, got %v", err)
	}

	// Truncated body
	truncatedBody := bytes.NewReader([]byte{0, 0, 0, 10, 1, 2, 3})
	if _, err := ReadFrame(truncatedBody); err != ErrFrameTruncated {
		t.Fatalf("expected ErrFrameTruncated, got %v", err)
	}
}

func TestHelloFrame(t *testing.T) {
	h := &HelloFrame{
		Type:          FrameTypeHello,
		SchemaVersion: 1,
	}
	data, err := EncodeHello(h)
	if err != nil {
		t.Fatalf("EncodeHello failed: %v", err)
	}
	decoded, err := DecodeHello(data)
	if err != nil {
		t.Fatalf("DecodeHello failed: %v", err)
	}
	if decoded.Type != FrameTypeHello || decoded.SchemaVersion != 1 {
		t.Fatalf("unexpected decoded hello: %+v", decoded)
	}

	// Unknown field
	unknown := []byte(`{"type":"hello","schema_version":1,"extra":"bad"}`)
	if _, err := DecodeHello(unknown); err == nil {
		t.Fatal("expected error on unknown field")
	}

	// Duplicate / case-conflicting field
	dup := []byte(`{"type":"hello","schema_version":1,"Type":"hello"}`)
	if _, err := DecodeHello(dup); err == nil {
		t.Fatal("expected error on case-conflicting field")
	}

	// Non-canonical key order
	outOfOrder := []byte(`{"schema_version":1,"type":"hello"}`)
	if _, err := DecodeHello(outOfOrder); err == nil {
		t.Fatal("expected error on non-canonical key order")
	}

	// Invalid schema
	invalidSchema := []byte(`{"type":"hello","schema_version":2}`)
	if _, err := DecodeHello(invalidSchema); err == nil {
		t.Fatal("expected error on invalid schema")
	}
}

func TestAdmitFrame(t *testing.T) {
	validSlot := strings.Repeat("a", 64)
	validInstance := strings.Repeat("b", 64)
	validNonce := strings.Repeat("c", 64)

	a := &AdmitFrame{
		Type:          FrameTypeAdmit,
		SchemaVersion: 1,
		Operation:     OpStatus,
		Role:          RoleNormal,
		SlotID:        validSlot,
		InstanceID:    validInstance,
		Nonce:         validNonce,
	}
	data, err := EncodeAdmit(a)
	if err != nil {
		t.Fatalf("EncodeAdmit failed: %v", err)
	}
	decoded, err := DecodeAdmit(data)
	if err != nil {
		t.Fatalf("DecodeAdmit failed: %v", err)
	}
	if *decoded != *a {
		t.Fatalf("mismatched decoded admit: %+v vs %+v", decoded, a)
	}

	// Invalid operation
	badOp := *a
	badOp.Operation = "destroy"
	if _, err := EncodeAdmit(&badOp); err == nil {
		t.Fatal("expected error on invalid operation")
	}

	// Invalid slot ID (too short)
	badSlot := *a
	badSlot.SlotID = "deadbeef"
	if _, err := EncodeAdmit(&badSlot); err == nil {
		t.Fatal("expected error on invalid slot ID")
	}

	// Case conflict
	caseConf := []byte(`{"type":"admit","schema_version":1,"operation":"status","role":"normal","slot_id":"` + validSlot + `","instance_id":"` + validInstance + `","nonce":"` + validNonce + `","Nonce":"other"}`)
	if _, err := DecodeAdmit(caseConf); err == nil {
		t.Fatal("expected error on case conflict")
	}
}

func TestReselectFrame(t *testing.T) {
	validSlot := strings.Repeat("f", 64)
	validNonce := strings.Repeat("d", 64)
	r := &ReselectFrame{
		Type:          FrameTypeReselect,
		SchemaVersion: 1,
		Nonce:         validNonce,
		ReasonCode:    "active_slot_repaired",
		ActiveSlotID:  validSlot,
	}
	data, err := EncodeReselect(r)
	if err != nil {
		t.Fatalf("EncodeReselect failed: %v", err)
	}
	decoded, err := DecodeReselect(data)
	if err != nil {
		t.Fatalf("DecodeReselect failed: %v", err)
	}
	if *decoded != *r {
		t.Fatalf("mismatched decoded reselect: %+v vs %+v", decoded, r)
	}

	// Unknown field
	unknown := []byte(`{"type":"reselect","schema_version":1,"nonce":"` + validNonce + `","reason_code":"active_slot_repaired","active_slot_id":"` + validSlot + `","bogus":"val"}`)
	if _, err := DecodeReselect(unknown); err == nil {
		t.Fatal("expected error on unknown field in reselect")
	}
}

func TestResultFrame(t *testing.T) {
	validSlot := strings.Repeat("e", 64)
	validNonce := strings.Repeat("a", 64)
	res := &ResultFrame{
		Type:          FrameTypeResult,
		SchemaVersion: 1,
		Nonce:         validNonce,
		Operation:     OpAdvance,
		State:         "ready",
		ReasonCode:    "ok",
		Version:       "1.0.0",
		SlotID:        validSlot,
	}
	data, err := EncodeResult(res)
	if err != nil {
		t.Fatalf("EncodeResult failed: %v", err)
	}
	decoded, err := DecodeResult(data)
	if err != nil {
		t.Fatalf("DecodeResult failed: %v", err)
	}
	if *decoded != *res {
		t.Fatalf("mismatched decoded result: %+v vs %+v", decoded, res)
	}

	// Invalid state (not in closed vocabulary)
	badState := *res
	badState.State = "arbitrary-unknown-state"
	if _, err := EncodeResult(&badState); err == nil {
		t.Fatal("expected error on invalid state")
	}

	// Invalid reason code (not in closed vocabulary)
	badReason := *res
	badReason.ReasonCode = "arbitrary-reason"
	if _, err := EncodeResult(&badReason); err == nil {
		t.Fatal("expected error on invalid reason code")
	}

	// Detection
	frameType, err := DetectFrameType(data)
	if err != nil || frameType != FrameTypeResult {
		t.Fatalf("expected FrameTypeResult, got %s (err: %v)", frameType, err)
	}
}
