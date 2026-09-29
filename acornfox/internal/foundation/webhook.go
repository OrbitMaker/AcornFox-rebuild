package foundation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const DefaultWebhookReplayWindow = 24 * time.Hour

var (
	ErrInvalidWebhookInput = errors.New("invalid webhook input")
	ErrWebhookReplay       = errors.New("webhook signature is outside replay window")
)

// WebhookSignature is the signed metadata emitted with a notification. The
// value is a lowercase hex HMAC-SHA256 digest prefixed with sha256=, which is
// unambiguous in HTTP headers and easy to compare in fixed vectors.
type WebhookSignature struct {
	Timestamp int64
	EventID   string
	Value     string
}

// CanonicalWebhookMessage is intentionally public so a receiver can produce
// the exact bytes used by SignWebhook for independent evidence.
func CanonicalWebhookMessage(timestamp int64, eventID string, payload []byte) []byte {
	return []byte(strconv.FormatInt(timestamp, 10) + "." + eventID + "." + string(payload))
}

// SignWebhook computes HMAC-SHA256 over timestamp.event_id.payload. Payload
// is treated as opaque bytes; no JSON re-encoding is performed, so signatures
// remain stable for the exact body sent over the wire.
func SignWebhook(secret string, timestamp int64, eventID string, payload []byte) (string, error) {
	if strings.TrimSpace(secret) == "" || timestamp <= 0 || strings.TrimSpace(eventID) == "" {
		return "", ErrInvalidWebhookInput
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(CanonicalWebhookMessage(timestamp, eventID, payload))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil)), nil
}

// ComputeWebhookSignature is an alias used by notification providers.
func ComputeWebhookSignature(secret string, timestamp int64, eventID string, payload []byte) (string, error) {
	return SignWebhook(secret, timestamp, eventID, payload)
}

func SignWebhookAt(secret, eventID string, payload []byte, occurredAt time.Time) (WebhookSignature, error) {
	timestamp := occurredAt.Unix()
	value, err := SignWebhook(secret, timestamp, eventID, payload)
	if err != nil {
		return WebhookSignature{}, err
	}
	return WebhookSignature{Timestamp: timestamp, EventID: eventID, Value: value}, nil
}

// VerifyWebhook checks the signature and enforces a bounded timestamp window.
// It accepts the canonical sha256= prefix and plain/v1= hex values so older
// receivers can migrate without changing the signing bytes.
func VerifyWebhook(secret string, timestamp int64, eventID string, payload []byte, provided string, now time.Time, replayWindow time.Duration) error {
	if replayWindow <= 0 {
		replayWindow = DefaultWebhookReplayWindow
	}
	if strings.TrimSpace(secret) == "" || timestamp <= 0 || strings.TrimSpace(eventID) == "" || strings.TrimSpace(provided) == "" {
		return ErrInvalidWebhookInput
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	delta := now.Unix() - timestamp
	if delta < 0 {
		delta = -delta
	}
	maxAgeSeconds := int64(replayWindow / time.Second)
	if maxAgeSeconds <= 0 || delta > maxAgeSeconds {
		return ErrWebhookReplay
	}
	expected, err := SignWebhook(secret, timestamp, eventID, payload)
	if err != nil {
		return err
	}
	provided = normalizeSignature(provided)
	expected = normalizeSignature(expected)
	if !hmac.Equal([]byte(strings.ToLower(provided)), []byte(strings.ToLower(expected))) {
		return fmt.Errorf("%w: signature mismatch", ErrInvalidWebhookInput)
	}
	return nil
}

// VerifyWebhookSignature is a spelling that makes the security operation
// explicit at call sites.
func VerifyWebhookSignature(secret string, timestamp int64, eventID string, payload []byte, provided string, now time.Time) error {
	return VerifyWebhook(secret, timestamp, eventID, payload, provided, now, DefaultWebhookReplayWindow)
}

// WebhookEventID deterministically identifies a logical event. Callers should
// include a stable object/event key rather than a random request ID so retries
// deduplicate across process restarts.
func WebhookEventID(eventType, objectKey string, occurredAt time.Time) string {
	h := sha256.New()
	_, _ = h.Write([]byte(strings.TrimSpace(eventType)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strings.TrimSpace(objectKey)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strconv.FormatInt(occurredAt.UTC().Unix(), 10)))
	return hex.EncodeToString(h.Sum(nil))
}

func normalizeSignature(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(value), "sha256=") {
		return value[len("sha256="):]
	}
	if strings.HasPrefix(strings.ToLower(value), "v1=") {
		return value[len("v1="):]
	}
	// Accommodate a Stripe-like composite header: t=...,v1=.... Verify uses
	// the separately supplied timestamp, so only the digest is relevant here.
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "v1=") {
			return part[len("v1="):]
		}
	}
	return value
}
