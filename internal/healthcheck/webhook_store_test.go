package healthcheck

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWebhookFileStoreReadsFixedSecureFiles(t *testing.T) {
	configRoot, stateRoot := webhookStoreRoots(t)
	store, err := NewTaskWebhookFileStore(configRoot, stateRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	observation, err := store.WebhookHealth(context.Background())
	if err != nil || observation.Config != nil || observation.Delivery != nil {
		t.Fatalf("observation=%+v err=%v", observation, err)
	}

	config := webhookConfigFixture(time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC))
	writeWebhookStoreConfig(t, configRoot, config)
	observation, err = store.WebhookHealth(context.Background())
	if err != nil || observation.Config == nil || *observation.Config != config || observation.Delivery != nil {
		t.Fatalf("observation=%+v err=%v", observation, err)
	}
	for _, path := range []string{filepath.Join(configRoot, webhookConfigFile), filepath.Join(stateRoot, webhookDeliveryLockFile)} {
		info, statErr := os.Lstat(path)
		if statErr != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("path=%s mode=%v err=%v", path, info.Mode(), statErr)
		}
	}
}

func TestWebhookFileStoreRejectsUnsafeFilesAndRoots(t *testing.T) {
	for name, prepare := range map[string]func(*testing.T, string, string){
		"config-symlink": func(t *testing.T, configRoot, _ string) {
			if err := os.Symlink("other", filepath.Join(configRoot, webhookConfigFile)); err != nil {
				t.Fatal(err)
			}
		},
		"config-corrupt": func(t *testing.T, configRoot, _ string) {
			if err := os.WriteFile(filepath.Join(configRoot, webhookConfigFile), []byte(`{"bad":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"state-symlink": func(t *testing.T, _, stateRoot string) {
			if err := os.Symlink("other", filepath.Join(stateRoot, webhookDeliveryStateFile)); err != nil {
				t.Fatal(err)
			}
		},
		"state-corrupt": func(t *testing.T, _, stateRoot string) {
			if err := os.WriteFile(filepath.Join(stateRoot, webhookDeliveryStateFile), []byte(`{"bad":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			configRoot, stateRoot := webhookStoreRoots(t)
			if name != "config-symlink" && name != "config-corrupt" {
				writeWebhookStoreConfig(t, configRoot, webhookConfigFixture(time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC)))
			}
			prepare(t, configRoot, stateRoot)
			store, err := NewTaskWebhookFileStore(configRoot, stateRoot, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if _, err := store.WebhookHealth(context.Background()); err == nil {
				t.Fatal("unsafe source was accepted")
			}
		})
	}
	configRoot, stateRoot := webhookStoreRoots(t)
	writeWebhookStoreConfig(t, configRoot, webhookConfigFixture(time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC)))
	store, err := NewTaskWebhookFileStore(configRoot, stateRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	moved := stateRoot + "-moved"
	if err := os.Rename(stateRoot, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WebhookHealth(context.Background()); err == nil {
		t.Fatal("root replacement accepted")
	}
}

func TestWebhookFileStoreLocksStateRoot(t *testing.T) {
	configRoot, stateRoot := webhookStoreRoots(t)
	first, err := NewTaskWebhookFileStore(configRoot, stateRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := NewTaskWebhookFileStore(configRoot, stateRoot, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("contended state lock acquired")
	}
}

func TestTaskWebhookFileStoreRejectsUnsafeRoots(t *testing.T) {
	configRoot, stateRoot := webhookStoreRoots(t)
	if _, err := NewTaskWebhookFileStore(configRoot, stateRoot, os.Getuid()+1, os.Getgid()); err == nil {
		t.Fatal("task store accepted a mismatched expected owner")
	}
	link := filepath.Join(filepath.Dir(configRoot), "config-link")
	if err := os.Symlink(configRoot, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTaskWebhookFileStore(link, stateRoot, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("task store accepted a symlink config root")
	}
}

func TestWebhookFileStoreTransitionsPersistAndReopen(t *testing.T) {
	configRoot, stateRoot := webhookStoreRoots(t)
	now := time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC)
	config := webhookConfigFixture(now)
	writeWebhookStoreConfig(t, configRoot, config)
	store := newTaskWebhookStore(t, configRoot, stateRoot)
	firstEvent := webhookStoreEvent(t, 1, "occurrence", 1)
	pending, err := store.BeginDelivery(config, firstEvent, now.Add(time.Minute))
	if err != nil || pending.Status != WebhookDeliveryPending || pending.OldestPendingAt == nil || pending.LastAttemptAt != nil || pending.ConsecutiveFailureCount != 0 || pending.TerminalFailureCount != 0 {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
	again, err := store.BeginDelivery(config, firstEvent, now.Add(2*time.Minute))
	if err != nil || !sameDeliveryHealth(again, pending) {
		t.Fatalf("again=%+v err=%v", again, err)
	}
	if _, err := store.BeginDelivery(config, webhookStoreEvent(t, 99, "escalation", 2), now.Add(2*time.Minute)); err == nil {
		t.Fatal("different incident replaced an in-flight delivery")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = newTaskWebhookStore(t, configRoot, stateRoot)
	retry, err := store.RecordDeliveryAttempt(config, firstEvent, pending.Revision, now.Add(3*time.Minute), WebhookDeliveryAttemptRetryableFailure)
	if err != nil || retry.Status != WebhookDeliveryRetryableFailure || retry.Revision != pending.Revision+1 || retry.ConsecutiveFailureCount != 1 || retry.OldestPendingAt == nil || !retry.OldestPendingAt.Equal(*pending.OldestPendingAt) {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}
	if _, err := store.RecordDeliveryAttempt(config, firstEvent, pending.Revision, now.Add(4*time.Minute), WebhookDeliveryAttemptDelivered); err == nil {
		t.Fatal("stale attempt generation was accepted")
	}
	if _, err := store.RecordDeliveryAttempt(config, webhookStoreEvent(t, 98, "escalation", 2), retry.Revision, now.Add(4*time.Minute), WebhookDeliveryAttemptDelivered); err == nil {
		t.Fatal("different attempt event was accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = newTaskWebhookStore(t, configRoot, stateRoot)
	delivered, err := store.RecordDeliveryAttempt(config, firstEvent, retry.Revision, now.Add(4*time.Minute), WebhookDeliveryAttemptDelivered)
	if err != nil || delivered.Status != WebhookDeliveryDelivered || delivered.OldestPendingAt != nil || delivered.LastDeliveredAt == nil || delivered.ConsecutiveFailureCount != 0 {
		t.Fatalf("delivered=%+v err=%v", delivered, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = newTaskWebhookStore(t, configRoot, stateRoot)
	if reconciled, err := store.BeginDelivery(config, firstEvent, now.Add(5*time.Minute)); err != nil || !sameDeliveryHealth(reconciled, delivered) {
		t.Fatalf("reconciled=%+v err=%v", reconciled, err)
	}
	secondEvent := webhookStoreEvent(t, 2, "escalation", 2)
	pending, err = store.BeginDelivery(config, secondEvent, now.Add(5*time.Minute))
	if err != nil || pending.LastDeliveredAt == nil || pending.ConsecutiveFailureCount != 0 || pending.TerminalFailureCount != 0 {
		t.Fatalf("post-success pending=%+v err=%v", pending, err)
	}
	failed, err := store.RecordDeliveryAttempt(config, secondEvent, pending.Revision, now.Add(6*time.Minute), WebhookDeliveryAttemptFailed)
	if err != nil || failed.Status != WebhookDeliveryFailed || failed.OldestPendingAt != nil || failed.TerminalFailureCount != 1 {
		t.Fatalf("failed=%+v err=%v", failed, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = newTaskWebhookStore(t, configRoot, stateRoot)
	if _, err := store.BeginDelivery(config, secondEvent, now.Add(7*time.Minute)); err == nil {
		t.Fatal("terminal delivery retried")
	}

	changed := config
	changed.EndpointID = "system_alerts_v2"
	writeWebhookStoreConfig(t, configRoot, changed)
	thirdEvent := webhookStoreEvent(t, 3, "escalation", 3)
	restarted, err := store.BeginDelivery(changed, thirdEvent, now.Add(8*time.Minute))
	if err != nil || restarted.Revision != failed.Revision+1 || restarted.ConfigDigest == failed.ConfigDigest || restarted.Status != WebhookDeliveryPending || restarted.LastDeliveredAt != nil {
		t.Fatalf("restarted=%+v previous=%+v err=%v", restarted, failed, err)
	}
	changedDelivered, err := store.RecordDeliveryAttempt(changed, thirdEvent, restarted.Revision, now.Add(9*time.Minute), WebhookDeliveryAttemptDelivered)
	if err != nil {
		t.Fatal(err)
	}
	writeWebhookStoreConfig(t, configRoot, config)
	returned, err := store.BeginDelivery(config, webhookStoreEvent(t, 4, "occurrence", 1), now.Add(10*time.Minute))
	if err != nil || returned.Revision != changedDelivered.Revision+1 || returned.ConfigDigest == changedDelivered.ConfigDigest {
		t.Fatalf("returned=%+v changed=%+v err=%v", returned, changedDelivered, err)
	}
}

func TestWebhookFileStoreRejectsStaleConfigAndClockOrder(t *testing.T) {
	configRoot, stateRoot := webhookStoreRoots(t)
	now := time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC)
	config := webhookConfigFixture(now)
	writeWebhookStoreConfig(t, configRoot, config)
	store := newTaskWebhookStore(t, configRoot, stateRoot)
	event := webhookStoreEvent(t, 1, "occurrence", 1)
	for _, at := range []time.Time{now.Add(-time.Second), now.Add(time.Minute).In(time.FixedZone("not-utc", 3600))} {
		if _, err := store.BeginDelivery(config, event, at); err == nil {
			t.Fatalf("invalid begin time accepted: %v", at)
		}
	}
	pending, err := store.BeginDelivery(config, event, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{now, now.Add(2 * time.Minute).In(time.FixedZone("not-utc", 3600))} {
		if _, err := store.RecordDeliveryAttempt(config, event, pending.Revision, at, WebhookDeliveryAttemptDelivered); err == nil {
			t.Fatalf("invalid attempt time accepted: %v", at)
		}
	}
	changed := config
	changed.EndpointID = "changed"
	writeWebhookStoreConfig(t, configRoot, changed)
	if _, err := store.RecordDeliveryAttempt(config, event, pending.Revision, now.Add(2*time.Minute), WebhookDeliveryAttemptDelivered); err == nil {
		t.Fatal("stale config accepted")
	}

	writeWebhookStoreConfig(t, configRoot, config)
	delivered, err := store.RecordDeliveryAttempt(config, event, pending.Revision, now.Add(2*time.Minute), WebhookDeliveryAttemptDelivered)
	if err != nil {
		t.Fatal(err)
	}
	if delivered.Revision != pending.Revision+1 || delivered.Event == nil || !sameWebhookDeliveryEvent(*delivered.Event, event) {
		t.Fatalf("delivered=%+v", delivered)
	}
	if _, err := store.BeginDelivery(config, webhookStoreEvent(t, 2, "escalation", 2), now.Add(time.Minute)); err == nil {
		t.Fatal("begin before last delivery accepted")
	}
}

func TestWebhookFileStoreConfigChangeCannotDiscardInflightEvent(t *testing.T) {
	for _, status := range []WebhookDeliveryHealthStatus{WebhookDeliveryPending, WebhookDeliveryRetryableFailure} {
		t.Run(string(status), func(t *testing.T) {
			configRoot, stateRoot := webhookStoreRoots(t)
			now := time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC)
			config := webhookConfigFixture(now)
			writeWebhookStoreConfig(t, configRoot, config)
			store := newTaskWebhookStore(t, configRoot, stateRoot)
			event := webhookStoreEvent(t, 1, "occurrence", 1)
			inflight, err := store.BeginDelivery(config, event, now.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if status == WebhookDeliveryRetryableFailure {
				inflight, err = store.RecordDeliveryAttempt(config, event, inflight.Revision, now.Add(2*time.Minute), WebhookDeliveryAttemptRetryableFailure)
				if err != nil {
					t.Fatal(err)
				}
			}
			changed := config
			changed.EndpointID = "system_alerts_changed"
			writeWebhookStoreConfig(t, configRoot, changed)
			if _, err := store.BeginDelivery(changed, webhookStoreEvent(t, 2, "escalation", 2), now.Add(3*time.Minute)); err == nil {
				t.Fatal("config change replaced an in-flight event")
			}
			observation, err := store.WebhookHealth(context.Background())
			if err != nil || observation.Delivery == nil || !sameWebhookDeliveryHealth(*observation.Delivery, inflight) {
				t.Fatalf("inflight state changed: observation=%+v err=%v", observation, err)
			}
			writeWebhookStoreConfig(t, configRoot, config)
			reconciled, err := store.BeginDelivery(config, event, now.Add(4*time.Minute))
			if err != nil || !sameWebhookDeliveryHealth(reconciled, inflight) {
				t.Fatalf("reverted config did not recover inflight event: state=%+v err=%v", reconciled, err)
			}
		})
	}
}

func TestWebhookFileStoreConcurrentBeginHasOneOldestPending(t *testing.T) {
	configRoot, stateRoot := webhookStoreRoots(t)
	now := time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC)
	config := webhookConfigFixture(now)
	writeWebhookStoreConfig(t, configRoot, config)
	store := newTaskWebhookStore(t, configRoot, stateRoot)
	event := webhookStoreEvent(t, 1, "occurrence", 1)
	defer store.Close()
	var group sync.WaitGroup
	errorsCh := make(chan error, 16)
	for index := 0; index < 16; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			_, err := store.BeginDelivery(config, event, now.Add(time.Duration(index+1)*time.Minute))
			errorsCh <- err
		}(index)
	}
	group.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	observation, err := store.WebhookHealth(context.Background())
	if err != nil || observation.Delivery == nil || observation.Delivery.Event == nil || !sameWebhookDeliveryEvent(*observation.Delivery.Event, event) || observation.Delivery.OldestPendingAt == nil || observation.Delivery.Status != WebhookDeliveryPending || observation.Delivery.OldestPendingAt.Before(now.Add(time.Minute)) || observation.Delivery.OldestPendingAt.After(now.Add(16*time.Minute)) {
		t.Fatalf("observation=%+v err=%v", observation, err)
	}
}

func TestWebhookFileStoreStateDoesNotPersistSecrets(t *testing.T) {
	configRoot, stateRoot := webhookStoreRoots(t)
	now := time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC)
	config := webhookConfigFixture(now)
	config.URL = "https://hooks.example.test/super-secret-url"
	config.SecretReference.Name = "super-secret-reference"
	writeWebhookStoreConfig(t, configRoot, config)
	store := newTaskWebhookStore(t, configRoot, stateRoot)
	defer store.Close()
	event := webhookStoreEvent(t, 1, "occurrence", 1)
	pending, err := store.BeginDelivery(config, event, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordDeliveryAttempt(config, event, pending.Revision, now.Add(2*time.Minute), WebhookDeliveryAttemptRetryableFailure); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(stateRoot, webhookDeliveryStateFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"super-secret-url", "super-secret-reference", "payload", "error", "https://"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("delivery state leaked %q: %s", forbidden, raw)
		}
	}
}

func webhookStoreRoots(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	configRoot, stateRoot := filepath.Join(root, "config"), filepath.Join(root, "state")
	for _, path := range []string{configRoot, stateRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return configRoot, stateRoot
}

func newTaskWebhookStore(t *testing.T, configRoot, stateRoot string) *WebhookFileStore {
	t.Helper()
	store, err := NewTaskWebhookFileStore(configRoot, stateRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func writeWebhookStoreConfig(t *testing.T, root string, config WebhookConfigV1) {
	t.Helper()
	raw, err := MarshalWebhookConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, webhookConfigFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, webhookConfigFile), 0o600); err != nil {
		t.Fatal(err)
	}
}

func webhookStoreEvent(t *testing.T, revision int64, kind string, stage int) WebhookDeliveryEventV1 {
	t.Helper()
	return *webhookDeliveryEventFixture(t, revision, kind, stage)
}

var _ WebhookHealthSource = (*WebhookFileStore)(nil)
