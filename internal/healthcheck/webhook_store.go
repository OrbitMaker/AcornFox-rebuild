package healthcheck

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/install"
)

const (
	productionWebhookConfigRoot = "/etc/open-card"
	productionWebhookStateRoot  = "/var/lib/open-card/healthcheck"
	webhookConfigFile           = "health-webhook.json"
	webhookDeliveryStateFile    = "webhook-delivery.json"
	webhookDeliveryLockFile     = "webhook-delivery.lock"
)

// WebhookDeliveryAttemptResult is the bounded result a provider may record.
// No provider text, payload, endpoint, or secret is accepted by this boundary.
type WebhookDeliveryAttemptResult string

const (
	WebhookDeliveryAttemptDelivered        WebhookDeliveryAttemptResult = "delivered"
	WebhookDeliveryAttemptRetryableFailure WebhookDeliveryAttemptResult = "retryable_failure"
	WebhookDeliveryAttemptFailed           WebhookDeliveryAttemptResult = "failed"
)

// WebhookFileStore is the root-owned filesystem source and durable delivery
// state machine for the one system host-alert webhook. Configuration and
// mutable delivery state intentionally use separate pinned roots.
type WebhookFileStore struct {
	mu           sync.Mutex
	configWriter *install.DurableWriter
	stateWriter  *install.DurableWriter
	lock         *install.DurableLock
}

// NewProductionWebhookFileStore opens the fixed production roots. Both roots
// must already be root-owned secure directories; it never creates directories
// or configuration/state files (the lock is created by AcquireMetadataLock).
func NewProductionWebhookFileStore() (*WebhookFileStore, error) {
	configWriter, err := install.ProductionDurableWriter(productionWebhookConfigRoot)
	if err != nil {
		return nil, errors.New("webhook config root is unavailable")
	}
	stateWriter, err := install.ProductionDurableWriter(productionWebhookStateRoot)
	if err != nil {
		_ = configWriter.Close()
		return nil, errors.New("webhook state root is unavailable")
	}
	return newWebhookFileStore(configWriter, stateWriter)
}

// NewTaskWebhookFileStore opens explicit task-owned roots. It exists only for
// tests and callers that supply both roots and their expected owner; it never
// redirects production paths into a task directory.
func NewTaskWebhookFileStore(configRoot, stateRoot string, uid, gid int) (*WebhookFileStore, error) {
	configWriter, err := install.TaskDurableWriter(configRoot, uid, gid)
	if err != nil {
		return nil, errors.New("webhook config root is unavailable")
	}
	stateWriter, err := install.TaskDurableWriter(stateRoot, uid, gid)
	if err != nil {
		_ = configWriter.Close()
		return nil, errors.New("webhook state root is unavailable")
	}
	return newWebhookFileStore(configWriter, stateWriter)
}

func newWebhookFileStore(configWriter, stateWriter *install.DurableWriter) (*WebhookFileStore, error) {
	if configWriter == nil || stateWriter == nil {
		return nil, errors.New("webhook store dependencies are required")
	}
	lock, err := stateWriter.AcquireMetadataLock(webhookDeliveryLockFile)
	if err != nil {
		_ = stateWriter.Close()
		_ = configWriter.Close()
		return nil, errors.New("webhook delivery state is already in use")
	}
	return &WebhookFileStore{configWriter: configWriter, stateWriter: stateWriter, lock: lock}, nil
}

// Close releases all root descriptors and the process lock. Regardless of an
// ambiguous release or close result the store becomes unavailable.
func (s *WebhookFileStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.configWriter == nil && s.stateWriter == nil && s.lock == nil {
		return nil
	}
	configWriter, stateWriter, lock := s.configWriter, s.stateWriter, s.lock
	s.configWriter, s.stateWriter, s.lock = nil, nil, nil
	var first error
	if lock != nil {
		first = lock.Release()
	}
	if stateWriter != nil {
		if err := stateWriter.Close(); err != nil && first == nil {
			first = err
		}
	}
	if configWriter != nil {
		if err := configWriter.Close(); err != nil && first == nil {
			first = err
		}
	}
	if first != nil {
		return errors.New("webhook store close failed")
	}
	return nil
}

// WebhookHealth implements WebhookHealthSource. A missing configuration is a
// normal nil Config observation; a missing state is a normal nil Delivery.
func (s *WebhookFileStore) WebhookHealth(ctx context.Context) (WebhookHealthObservation, error) {
	if ctx == nil || ctx.Err() != nil {
		return WebhookHealthObservation{}, errors.New("webhook source is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.availableLocked() {
		return WebhookHealthObservation{}, errors.New("webhook source is unavailable")
	}
	config, err := s.loadConfigLocked()
	if err != nil || config == nil {
		return WebhookHealthObservation{Config: config}, err
	}
	if err := ctx.Err(); err != nil {
		return WebhookHealthObservation{}, errors.New("webhook source is unavailable")
	}
	delivery, err := s.loadDeliveryLocked()
	if err != nil {
		return WebhookHealthObservation{}, err
	}
	return WebhookHealthObservation{Config: config, Delivery: delivery}, nil
}

// BeginDelivery durably records an accepted occurrence before any network
// attempt. Repeating it for an in-flight revision preserves its original
// pending time; an allowed config transition advances the durable generation.
func (s *WebhookFileStore) BeginDelivery(config WebhookConfigV1, event WebhookDeliveryEventV1, occurredAt time.Time) (DeliveryHealthV1, error) {
	if config.Validate() != nil || event.Validate() != nil || !utc(occurredAt) || occurredAt.Before(config.ConfiguredAt) {
		return DeliveryHealthV1{}, errors.New("invalid webhook delivery begin")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.availableLocked() {
		return DeliveryHealthV1{}, errors.New("webhook delivery state is unavailable")
	}
	digest, err := s.requireCurrentConfigLocked(config)
	if err != nil {
		return DeliveryHealthV1{}, err
	}
	state, err := s.loadDeliveryLocked()
	if err != nil {
		return DeliveryHealthV1{}, err
	}
	if state != nil && state.ConfigDigest != digest && (state.Status == WebhookDeliveryPending || state.Status == WebhookDeliveryRetryableFailure) {
		return DeliveryHealthV1{}, errors.New("webhook config changed with delivery in flight")
	}
	if state != nil && state.ConfigDigest == digest {
		if webhookTimesBefore(config.ConfiguredAt, *state) {
			return DeliveryHealthV1{}, errors.New("webhook delivery state is out of order")
		}
		switch state.Status {
		case WebhookDeliveryPending, WebhookDeliveryRetryableFailure:
			if sameWebhookDeliveryEvent(*state.Event, event) {
				return *state, nil
			}
			return DeliveryHealthV1{}, errors.New("webhook delivery event conflicts")
		case WebhookDeliveryDelivered:
			if sameWebhookDeliveryEvent(*state.Event, event) {
				return *state, nil
			}
		case WebhookDeliveryFailed:
			return DeliveryHealthV1{}, errors.New("webhook delivery is terminal")
		}
		if webhookTimesAfter(occurredAt, *state) {
			return DeliveryHealthV1{}, errors.New("webhook delivery begin is out of order")
		}
	}
	generation := int64(1)
	if state != nil {
		generation = state.Revision + 1
	}
	next := DeliveryHealthV1{Schema: deliveryHealthSchema, ConfigDigest: digest, Revision: generation, OldestPendingAt: webhookStoreTime(occurredAt), Status: WebhookDeliveryPending, Event: &event}
	if state != nil && state.ConfigDigest == digest && state.LastDeliveredAt != nil {
		lastDeliveredAt := *state.LastDeliveredAt
		next.LastDeliveredAt = &lastDeliveredAt
	}
	return s.saveDeliveryLocked(next)
}

// RecordDeliveryAttempt records exactly one result for the current pending or
// retryable delivery. A terminal result cannot be retried until configuration
// changes and BeginDelivery creates a new revision.
func (s *WebhookFileStore) RecordDeliveryAttempt(config WebhookConfigV1, event WebhookDeliveryEventV1, expectedGeneration int64, at time.Time, result WebhookDeliveryAttemptResult) (DeliveryHealthV1, error) {
	if config.Validate() != nil || event.Validate() != nil || expectedGeneration < 1 || !utc(at) || !validWebhookAttemptResult(result) || at.Before(config.ConfiguredAt) {
		return DeliveryHealthV1{}, errors.New("invalid webhook delivery attempt")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.availableLocked() {
		return DeliveryHealthV1{}, errors.New("webhook delivery state is unavailable")
	}
	digest, err := s.requireCurrentConfigLocked(config)
	if err != nil {
		return DeliveryHealthV1{}, err
	}
	state, err := s.loadDeliveryLocked()
	if err != nil {
		return DeliveryHealthV1{}, err
	}
	if state == nil || state.ConfigDigest != digest || state.Revision != expectedGeneration || state.Event == nil || !sameWebhookDeliveryEvent(*state.Event, event) || (state.Status != WebhookDeliveryPending && state.Status != WebhookDeliveryRetryableFailure) || state.OldestPendingAt == nil || at.Before(*state.OldestPendingAt) || (state.LastAttemptAt != nil && !at.After(*state.LastAttemptAt)) {
		return DeliveryHealthV1{}, errors.New("webhook delivery attempt is out of order")
	}
	if webhookTimesBefore(config.ConfiguredAt, *state) || webhookTimesAfter(at, *state) {
		return DeliveryHealthV1{}, errors.New("webhook delivery attempt is out of order")
	}
	next := *state
	next.Revision++
	next.LastAttemptAt = webhookStoreTime(at)
	switch result {
	case WebhookDeliveryAttemptDelivered:
		next.Status = WebhookDeliveryDelivered
		next.OldestPendingAt = nil
		next.LastDeliveredAt = webhookStoreTime(at)
		next.ConsecutiveFailureCount = 0
	case WebhookDeliveryAttemptRetryableFailure:
		next.Status = WebhookDeliveryRetryableFailure
		next.ConsecutiveFailureCount++
	case WebhookDeliveryAttemptFailed:
		next.Status = WebhookDeliveryFailed
		next.OldestPendingAt = nil
		next.TerminalFailureCount++
	}
	return s.saveDeliveryLocked(next)
}

func (s *WebhookFileStore) availableLocked() bool {
	return s != nil && s.configWriter != nil && s.stateWriter != nil && s.lock != nil
}

func (s *WebhookFileStore) loadConfigLocked() (*WebhookConfigV1, error) {
	present, err := secureWebhookMetadataPresent(s.configWriter, webhookConfigFile)
	if err != nil {
		return nil, errors.New("webhook config is unavailable")
	}
	if !present {
		return nil, nil
	}
	raw, err := s.configWriter.ReadMetadata(webhookConfigFile)
	if err != nil {
		return nil, errors.New("webhook config is unavailable")
	}
	config, err := ParseWebhookConfig(raw)
	if err != nil {
		return nil, errors.New("webhook config is invalid")
	}
	return &config, nil
}

func (s *WebhookFileStore) loadDeliveryLocked() (*DeliveryHealthV1, error) {
	present, err := secureWebhookMetadataPresent(s.stateWriter, webhookDeliveryStateFile)
	if err != nil {
		return nil, errors.New("webhook delivery state is unavailable")
	}
	if !present {
		return nil, nil
	}
	raw, err := s.stateWriter.ReadMetadata(webhookDeliveryStateFile)
	if err != nil {
		return nil, errors.New("webhook delivery state is unavailable")
	}
	state, err := ParseDeliveryHealth(raw)
	if err != nil {
		return nil, errors.New("webhook delivery state is invalid")
	}
	return &state, nil
}

func (s *WebhookFileStore) requireCurrentConfigLocked(config WebhookConfigV1) (string, error) {
	stored, err := s.loadConfigLocked()
	if err != nil {
		return "", err
	}
	if stored == nil {
		return "", errors.New("webhook config is missing")
	}
	digest, err := CanonicalWebhookConfigDigest(config)
	if err != nil {
		return "", errors.New("webhook config is invalid")
	}
	storedDigest, err := CanonicalWebhookConfigDigest(*stored)
	if err != nil || digest != storedDigest {
		return "", errors.New("webhook config changed")
	}
	return digest, nil
}

func (s *WebhookFileStore) saveDeliveryLocked(state DeliveryHealthV1) (DeliveryHealthV1, error) {
	raw, err := MarshalDeliveryHealth(state)
	if err != nil {
		return DeliveryHealthV1{}, errors.New("webhook delivery state is invalid")
	}
	present, err := secureWebhookMetadataPresent(s.stateWriter, webhookDeliveryStateFile)
	if err != nil {
		return DeliveryHealthV1{}, errors.New("webhook delivery state is unavailable")
	}
	if present {
		if _, err := s.stateWriter.ReadMetadata(webhookDeliveryStateFile); err != nil {
			return DeliveryHealthV1{}, errors.New("webhook delivery state is unavailable")
		}
	}
	if err := s.stateWriter.WriteMetadata(webhookDeliveryStateFile, raw); err != nil {
		return DeliveryHealthV1{}, errors.New("webhook delivery state persistence failed")
	}
	confirmed, err := s.loadDeliveryLocked()
	if err != nil || confirmed == nil || !sameWebhookDeliveryHealth(*confirmed, state) {
		return DeliveryHealthV1{}, errors.New("webhook delivery state persistence failed")
	}
	return *confirmed, nil
}

func validWebhookAttemptResult(result WebhookDeliveryAttemptResult) bool {
	return result == WebhookDeliveryAttemptDelivered || result == WebhookDeliveryAttemptRetryableFailure || result == WebhookDeliveryAttemptFailed
}

func sameWebhookDeliveryEvent(left, right WebhookDeliveryEventV1) bool { return left == right }

func webhookStoreTime(value time.Time) *time.Time { return &value }

func sameWebhookDeliveryHealth(left, right DeliveryHealthV1) bool {
	leftRaw, leftErr := MarshalDeliveryHealth(left)
	rightRaw, rightErr := MarshalDeliveryHealth(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

// secureWebhookMetadataPresent uses the pinned root descriptor to distinguish
// a genuinely absent fixed file from a dangling symlink or another unsafe
// direct child. ReadMetadata alone cannot make that distinction on every OS.
func secureWebhookMetadataPresent(writer *install.DurableWriter, name string) (bool, error) {
	children, err := writer.ReadDirectChildren()
	if err != nil {
		return false, err
	}
	for _, child := range children {
		if child.Name != name {
			continue
		}
		if !child.Mode.IsRegular() || child.Mode.Perm() != 0o600 {
			return false, errors.New("unsafe webhook metadata")
		}
		return true, nil
	}
	return false, nil
}
