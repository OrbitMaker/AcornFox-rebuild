package healthcheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func collectorSubject() string {
	return strings.Repeat("a", 64)
}

func collectorProbes(order *[]CheckKind, severity map[CheckKind]Severity) []HostProbe {
	probes := make([]HostProbe, 0, len(fixedKinds))
	for _, kind := range fixedKinds {
		kind := kind
		probes = append(probes, HostProbe{Kind: kind, Check: func(context.Context) (HostFact, error) {
			if order != nil {
				*order = append(*order, kind)
			}
			sev := SeverityOK
			if severity != nil {
				if value, exists := severity[kind]; exists {
					sev = value
				}
			}
			return HostFact{Subject: collectorSubject(), Severity: sev}, nil
		}})
	}
	return probes
}

func newTaskCollector(t *testing.T, root string, now *time.Time, severity map[CheckKind]Severity) *TaskHostCollector {
	t.Helper()
	store, err := NewTaskStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	collector, err := NewTaskHostCollector(collectorProbes(nil, severity), store, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	return collector
}

func TestTaskHostCollectorCollectsFixedKindsInCanonicalOrder(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC)
	store, err := NewTaskStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var called []CheckKind
	collector, err := NewTaskHostCollector(collectorProbes(&called, map[CheckKind]Severity{CheckDisk: SeverityWarning, CheckWebhook: SeverityCritical}), store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.ObservedAt.Equal(now) || snapshot.Overall != SeverityCritical || len(snapshot.Results) != len(fixedKinds) {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	for i, kind := range fixedKinds {
		if called[i] != kind || snapshot.Results[i].Kind != kind {
			t.Fatalf("canonical order at %d = %q / %q, want %q", i, called[i], snapshot.Results[i].Kind, kind)
		}
	}
}

func TestTaskHostCollectorRejectsInvalidProbeSetsAndFacts(t *testing.T) {
	root := t.TempDir()
	store, err := NewTaskStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC)
	valid := collectorProbes(nil, nil)
	for _, probes := range [][]HostProbe{valid[:9], append(append([]HostProbe(nil), valid...), HostProbe{Kind: CheckKind("extra"), Check: valid[0].Check}), append(append([]HostProbe(nil), valid...), valid[0])} {
		if _, err := NewTaskHostCollector(probes, store, func() time.Time { return now }); err == nil {
			t.Fatal("invalid probe set accepted")
		}
	}
	probes := collectorProbes(nil, nil)
	probes[0].Check = func(context.Context) (HostFact, error) {
		return HostFact{Subject: "", Severity: SeverityOK}, nil
	}
	collector, err := NewTaskHostCollector(probes, store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Collect(context.Background()); err == nil {
		t.Fatal("invalid probe fact accepted")
	}
	probes = collectorProbes(nil, nil)
	probes[0].Check = func(context.Context) (HostFact, error) {
		return HostFact{}, errors.New("postgresql://secret-token")
	}
	collector, err = NewTaskHostCollector(probes, store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Collect(context.Background()); err == nil || strings.Contains(err.Error(), "postgresql") || strings.Contains(err.Error(), "token") {
		t.Fatalf("unsafe probe error = %v", err)
	}
}

func TestTaskHostCollectorPersistsOccurrenceEscalationRecoveryAndRestartReplay(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	failure := map[CheckKind]Severity{CheckDatabase: SeverityCritical}
	collector := newTaskCollector(t, root, &now, failure)
	first, err := collector.Evaluate(context.Background())
	if err != nil || !first.Decision.Notify || first.Decision.State.PendingNotification != "occurrence" {
		t.Fatalf("first = %#v, %v", first, err)
	}
	// A fresh task store simulates restart before delivery acknowledgement.
	if err := collector.store.Close(); err != nil {
		t.Fatal(err)
	}
	collector = newTaskCollector(t, root, &now, failure)
	replay, err := collector.Evaluate(context.Background())
	if err != nil || !replay.Decision.Notify || replay.Decision.State != first.Decision.State {
		t.Fatalf("replay = %#v, %v", replay, err)
	}
	if _, err := collector.Acknowledge(); err != nil {
		t.Fatal(err)
	}
	for _, checkpoint := range []struct {
		at        time.Duration
		wantStage int
	}{{time.Minute, 2}, {5 * time.Minute, 3}, {30 * time.Minute, 3}} {
		at, wantStage := checkpoint.at, checkpoint.wantStage
		now = first.Snapshot.ObservedAt.Add(at)
		next, err := collector.Evaluate(context.Background())
		if err != nil || !next.Decision.Notify || next.Decision.State.NotificationStage != wantStage {
			t.Fatalf("at %s = %#v, %v", at, next, err)
		}
		if at == 30*time.Minute && !next.Decision.State.ThirtyMinuteNotified {
			t.Fatal("30-minute reminder not recorded")
		}
		if _, err := collector.Acknowledge(); err != nil {
			t.Fatal(err)
		}
	}
	now = first.Snapshot.ObservedAt.Add(31 * time.Minute)
	if err := collector.store.Close(); err != nil {
		t.Fatal(err)
	}
	collector = newTaskCollector(t, root, &now, nil)
	recovery, err := collector.Evaluate(context.Background())
	if err != nil || !recovery.Decision.Recovery || recovery.Decision.State.PendingNotification != "recovery" {
		t.Fatalf("recovery = %#v, %v", recovery, err)
	}
	if _, err := collector.Acknowledge(); err != nil {
		t.Fatal(err)
	}
	if err := collector.store.Close(); err != nil {
		t.Fatal(err)
	}
	collector = newTaskCollector(t, root, &now, nil)
	sameTime, err := collector.Evaluate(context.Background())
	if err != nil || sameTime.Decision.Notify || sameTime.Decision.Recovery || !sameTime.Decision.Noop || sameTime.Decision.State.PendingNotification != "" {
		t.Fatalf("same-time post-ack = %#v, %v", sameTime, err)
	}
}

func TestTaskHostCollectorReplaysRecoveryUntilAcknowledged(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	collector := newTaskCollector(t, root, &now, map[CheckKind]Severity{CheckDatabase: SeverityCritical})
	if _, err := collector.Evaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Acknowledge(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err := collector.store.Close(); err != nil {
		t.Fatal(err)
	}
	collector = newTaskCollector(t, root, &now, nil)
	recovery, err := collector.Evaluate(context.Background())
	if err != nil || !recovery.Decision.Recovery || recovery.Decision.State.PendingNotification != "recovery" {
		t.Fatalf("recovery = %#v, %v", recovery, err)
	}
	if err := collector.store.Close(); err != nil {
		t.Fatal(err)
	}
	collector = newTaskCollector(t, root, &now, nil)
	replay, err := collector.Evaluate(context.Background())
	if err != nil || !replay.Decision.Recovery || replay.Decision.State != recovery.Decision.State {
		t.Fatalf("recovery replay = %#v, %v", replay, err)
	}
	if _, err := collector.Acknowledge(); err != nil {
		t.Fatal(err)
	}
}

func TestTaskStateStoreExcludesConcurrentInstancesAndSerializesAcknowledge(t *testing.T) {
	root := t.TempDir()
	first, err := NewTaskStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewTaskStateStore(root); err == nil {
		t.Fatal("concurrent state store accepted")
	}
	now := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	collector, err := NewTaskHostCollector(collectorProbes(nil, map[CheckKind]Severity{CheckDatabase: SeverityCritical}), first, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Evaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errorsSeen := make(chan error, 65)
	var wait sync.WaitGroup
	for i := 0; i < 64; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := collector.Evaluate(context.Background())
			errorsSeen <- err
		}()
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		_, err := collector.Acknowledge()
		errorsSeen <- err
	}()
	close(start)
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	first.mu.Lock()
	state, err := first.loadLocked()
	first.mu.Unlock()
	if err != nil || state == nil || state.PendingNotification != "" {
		t.Fatalf("acknowledged state was overwritten: %#v, %v", state, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewTaskStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTaskHostCollectorConstructorAndCloseAreRaceSafe(t *testing.T) {
	for iteration := 0; iteration < 64; iteration++ {
		store, err := NewTaskStateStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			_, _ = NewTaskHostCollector(collectorProbes(nil, nil), store, func() time.Time { return time.Now().UTC() })
		}()
		go func() {
			defer wait.Done()
			<-start
			_ = store.Close()
		}()
		close(start)
		wait.Wait()
	}
}

func TestTaskStateStoreRejectsUnsafeLockFile(t *testing.T) {
	for name, prepare := range map[string]func(*testing.T, string){
		"symlink": func(t *testing.T, root string) {
			if err := os.Symlink("missing-lock-target", filepath.Join(root, incidentLockFile)); err != nil {
				t.Fatal(err)
			}
		},
		"wrong-mode": func(t *testing.T, root string) {
			path := filepath.Join(root, incidentLockFile)
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			prepare(t, root)
			if _, err := NewTaskStateStore(root); err == nil {
				t.Fatal("unsafe lock file accepted")
			}
		})
	}
}

func TestTaskStateStoreRejectsUnsafeStateAndStrictJSON(t *testing.T) {
	now := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	for name, mutate := range map[string]func(t *testing.T, root string){
		"symlink root": func(t *testing.T, root string) {
			link := filepath.Join(filepath.Dir(root), "health-state-link")
			if err := os.Symlink(root, link); err != nil {
				t.Fatal(err)
			}
			if _, err := NewTaskStateStore(link); err == nil {
				t.Fatal("symlink root accepted")
			}
		},
		"writable root": func(t *testing.T, root string) {
			if err := os.Chmod(root, 0o777); err != nil {
				t.Fatal(err)
			}
			if _, err := NewTaskStateStore(root); err == nil {
				t.Fatal("writable root accepted")
			}
		},
		"path escape": func(t *testing.T, root string) {
			if _, err := NewTaskStateStore(root + "/.."); err == nil {
				t.Fatal("unclean root accepted")
			}
		},
	} {
		t.Run(name, func(t *testing.T) { mutate(t, t.TempDir()) })
	}
	for name, raw := range map[string][]byte{
		"corrupt":   []byte("not-json"),
		"unknown":   []byte(`{"schema_version":1,"revision":1,"fingerprint":"healthy","first_observed":"2026-08-31T01:00:00Z","last_observed":"2026-08-31T01:00:00Z","severity":"ok","notification_stage":0,"thirty_minute_notified":false,"pending_notification":"","recovery_pending":false,"healthy":true,"extra":true}`),
		"duplicate": []byte(`{"schema_version":1,"schema_version":1,"revision":1}`),
		"trailing":  []byte(`{"schema_version":1} {}`),
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, incidentStateFile), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			collector := newTaskCollector(t, root, &now, nil)
			if _, err := collector.Evaluate(context.Background()); err == nil {
				t.Fatal("invalid state accepted")
			}
		})
	}
	t.Run("symlink state", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Symlink("/tmp/not-health-state", filepath.Join(root, incidentStateFile)); err != nil {
			t.Fatal(err)
		}
		collector := newTaskCollector(t, root, &now, nil)
		if _, err := collector.Evaluate(context.Background()); err == nil {
			t.Fatal("symlink state accepted")
		}
	})
	t.Run("wrong state mode", func(t *testing.T) {
		root := t.TempDir()
		state := IncidentState{SchemaVersion: SchemaVersion, Revision: 1, Fingerprint: HealthyFingerprint, FirstObserved: now, LastObserved: now, Severity: SeverityOK, Healthy: true}
		raw, err := MarshalIncident(state)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, incidentStateFile)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0o644 {
			t.Fatalf("state mode = %v, %v", info, err)
		}
		collector := newTaskCollector(t, root, &now, nil)
		if _, err := collector.Evaluate(context.Background()); err == nil {
			t.Fatal("wrong-mode state accepted")
		}
	})
}

func TestTaskHostCollectorHashesProbeSubjectsAndFixesCodes(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	probes := collectorProbes(nil, nil)
	probes[0].Check = func(context.Context) (HostFact, error) {
		return HostFact{Subject: "postgresql://user:secret-token@db/private", Severity: SeverityCritical}, nil
	}
	store, err := NewTaskStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	collector, err := NewTaskHostCollector(probes, store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "postgresql") || snapshot.Results[0].Code != "five_units_failed" || snapshot.Results[0].SubjectSHA256 == strings.Repeat("a", 64) {
		t.Fatalf("unsafe or probe-controlled result escaped: %s", raw)
	}
}

func TestTaskStateStoreWritesOnlyStrictSecretFree0600State(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	collector := newTaskCollector(t, root, &now, map[CheckKind]Severity{CheckCertificate: SeverityEmergency})
	if _, err := collector.Evaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, incidentStateFile)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %v, %v", info, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseIncident(raw); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"postgresql://", "password", "token", "certificate", "private", "message", "output", "url", "dsn", "/var/lib"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Fatalf("state leaked %q: %s", forbidden, raw)
		}
	}
}
