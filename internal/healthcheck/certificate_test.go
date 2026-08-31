package healthcheck

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/providers/edgeprobe"
)

type certificateTargetsFunc func(context.Context) ([]CertificateTarget, error)

func (f certificateTargetsFunc) CertificateTargets(ctx context.Context) ([]CertificateTarget, error) {
	return f(ctx)
}

type certificateObserverFunc func(context.Context, string) (edgeprobe.CertificateObservation, error)

func (f certificateObserverFunc) ObserveCertificate(ctx context.Context, hostname string) (edgeprobe.CertificateObservation, error) {
	return f(ctx, hostname)
}

func TestTaskCertificateProbeObservesCompleteSortedCoverage(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	alpha := certificateObservation("alpha.example.test", certificateFingerprint('a'), now.Add(-time.Hour), now.Add(31*24*time.Hour))
	beta := certificateObservation("beta.example.test", certificateFingerprint('b'), now.Add(-time.Hour), now.Add(30*24*time.Hour))
	var calls []string
	probe := taskCertificateProbe(t,
		certificateTargetsFunc(func(context.Context) ([]CertificateTarget, error) {
			return []CertificateTarget{{Hostname: "BETA.EXAMPLE.TEST.", ExpectedLeafSHA256: beta.Fingerprint}, {Hostname: "alpha.example.test", Console: true}}, nil
		}),
		certificateObserverFunc(func(_ context.Context, hostname string) (edgeprobe.CertificateObservation, error) {
			calls = append(calls, hostname)
			if hostname == alpha.Hostname {
				return alpha, nil
			}
			return beta, nil
		}), now)
	fact, err := probe.Check(context.Background())
	if err != nil || fact.Severity != SeverityWarning {
		t.Fatalf("fact=%+v err=%v", fact, err)
	}
	if strings.Join(calls, ",") != "alpha.example.test,beta.example.test" {
		t.Fatalf("calls=%v", calls)
	}
	if !strings.HasPrefix(fact.Subject, certificateSubjectVersion+":healthy:") || strings.Contains(fact.Subject, "example.test") || len(fact.Subject) != len(certificateSubjectVersion)+len(":healthy:")+64 {
		t.Fatalf("unsafe subject=%q", fact.Subject)
	}
}

func TestTaskCertificateProbeCertificateThresholdsAndValidity(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		want      Severity
	}{
		{"31_days", now.Add(-time.Hour), now.Add(31 * 24 * time.Hour), SeverityOK},
		{"30_days", now.Add(-time.Hour), now.Add(30 * 24 * time.Hour), SeverityWarning},
		{"14_days", now.Add(-time.Hour), now.Add(14 * 24 * time.Hour), SeverityCritical},
		{"7_days", now.Add(-time.Hour), now.Add(7 * 24 * time.Hour), SeverityEmergency},
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Hour), SeverityEmergency},
		{"not_yet_valid", now.Add(time.Hour), now.Add(2 * time.Hour), SeverityEmergency},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observation := certificateObservation("console.example.test", certificateFingerprint('a'), tc.notBefore, tc.notAfter)
			probe := taskCertificateProbe(t, certificateTargetsFunc(func(context.Context) ([]CertificateTarget, error) {
				return []CertificateTarget{{Hostname: observation.Hostname, Console: true}}, nil
			}), certificateObserverFunc(func(context.Context, string) (edgeprobe.CertificateObservation, error) { return observation, nil }), now)
			fact, err := probe.Check(context.Background())
			if err != nil || fact.Severity != tc.want {
				t.Fatalf("fact=%+v err=%v", fact, err)
			}
		})
	}
}

func TestTaskCertificateProbeRejectsDriftButStillObservesEveryTarget(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	persisted := now.Add(60 * 24 * time.Hour)
	first := certificateObservation("first.example.test", certificateFingerprint('a'), now.Add(-time.Hour), now.Add(60*24*time.Hour))
	second := certificateObservation("second.example.test", certificateFingerprint('b'), now.Add(-time.Hour), now.Add(61*24*time.Hour))
	var calls []string
	probe := taskCertificateProbe(t, certificateTargetsFunc(func(context.Context) ([]CertificateTarget, error) {
		return []CertificateTarget{
			{Hostname: first.Hostname, ExpectedLeafSHA256: certificateFingerprint('c'), PersistedNotAfter: &persisted, Console: true},
			{Hostname: second.Hostname, ExpectedLeafSHA256: second.Fingerprint},
		}, nil
	}), certificateObserverFunc(func(_ context.Context, hostname string) (edgeprobe.CertificateObservation, error) {
		calls = append(calls, hostname)
		if hostname == first.Hostname {
			return first, nil
		}
		return second, nil
	}), now)
	fact, err := probe.Check(context.Background())
	if err != nil || fact.Severity != SeverityEmergency || !strings.Contains(fact.Subject, "fingerprint_drift") {
		t.Fatalf("fact=%+v err=%v", fact, err)
	}
	if strings.Join(calls, ",") != "first.example.test,second.example.test" {
		t.Fatalf("did not observe every target: %v", calls)
	}

	persistedDrift := persisted.Add(-time.Second)
	probe = taskCertificateProbe(t, certificateTargetsFunc(func(context.Context) ([]CertificateTarget, error) {
		return []CertificateTarget{{Hostname: first.Hostname, ExpectedLeafSHA256: first.Fingerprint, PersistedNotAfter: &persistedDrift, Console: true}}, nil
	}), certificateObserverFunc(func(context.Context, string) (edgeprobe.CertificateObservation, error) { return first, nil }), now)
	fact, err = probe.Check(context.Background())
	if err != nil || fact.Severity != SeverityEmergency || !strings.Contains(fact.Subject, "persisted_validity_drift") {
		t.Fatalf("persisted fact=%+v err=%v", fact, err)
	}
}

func TestTaskCertificateProbeRejectsMalformedCoverageAndRedactsOperationalFailures(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	observerCalled := false
	observer := certificateObserverFunc(func(context.Context, string) (edgeprobe.CertificateObservation, error) {
		observerCalled = true
		return edgeprobe.CertificateObservation{}, nil
	})
	for _, targets := range [][]CertificateTarget{
		nil,
		{{Hostname: "console.example.test", Console: true}, {Hostname: "CONSOLE.EXAMPLE.TEST.", Console: true}},
		{{Hostname: "one.example.test", Console: true}, {Hostname: "two.example.test", Console: true}},
		{{Hostname: "application.example.test"}},
		{{Hostname: "application.example.test", ExpectedLeafSHA256: certificateFingerprint('a')}},
		{{Hostname: "console.example.test", Console: true, ExpectedLeafSHA256: "secret"}},
	} {
		probe := taskCertificateProbe(t, certificateTargetsFunc(func(context.Context) ([]CertificateTarget, error) { return targets, nil }), observer, now)
		fact, err := probe.Check(context.Background())
		if err != nil || fact.Severity != SeverityEmergency || !strings.Contains(fact.Subject, "invalid_coverage") {
			t.Fatalf("targets=%+v fact=%+v err=%v", targets, fact, err)
		}
	}
	if observerCalled {
		t.Fatal("malformed coverage reached TLS observer")
	}
	overLimit := make([]CertificateTarget, maxCertificateTargets+1)
	for index := range overLimit {
		overLimit[index] = CertificateTarget{Hostname: fmt.Sprintf("host-%04d.example.test", index), ExpectedLeafSHA256: certificateFingerprint('a'), Console: index == 0}
	}
	probe := taskCertificateProbe(t, certificateTargetsFunc(func(context.Context) ([]CertificateTarget, error) { return overLimit, nil }), observer, now)
	if fact, err := probe.Check(context.Background()); err != nil || fact.Severity != SeverityEmergency || !strings.Contains(fact.Subject, "invalid_coverage") || observerCalled {
		t.Fatalf("over-limit fact=%+v err=%v called=%t", fact, err, observerCalled)
	}

	secret := "postgresql://token:secret@db.invalid/open-card"
	probe = taskCertificateProbe(t, certificateTargetsFunc(func(context.Context) ([]CertificateTarget, error) { return nil, errors.New(secret) }), observer, now)
	fact, err := probe.Check(context.Background())
	if err != nil || fact.Severity != SeverityEmergency || !strings.Contains(fact.Subject, "source_failure") || strings.Contains(fact.Subject, secret) {
		t.Fatalf("source fact=%+v err=%v", fact, err)
	}
	probe = taskCertificateProbe(t, certificateTargetsFunc(func(context.Context) ([]CertificateTarget, error) {
		return []CertificateTarget{{Hostname: "console.example.test", Console: true}}, nil
	}), certificateObserverFunc(func(context.Context, string) (edgeprobe.CertificateObservation, error) {
		return edgeprobe.CertificateObservation{}, errors.New(secret)
	}), now)
	fact, err = probe.Check(context.Background())
	if err != nil || fact.Severity != SeverityEmergency || !strings.Contains(fact.Subject, "tls_failure") || strings.Contains(fact.Subject, secret) {
		t.Fatalf("TLS fact=%+v err=%v", fact, err)
	}
}

func TestTaskCertificateProbeHonorsCancellationAndHasDeterministicSubject(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probe := taskCertificateProbe(t, certificateTargetsFunc(func(context.Context) ([]CertificateTarget, error) {
		t.Fatal("cancelled context called source")
		return nil, nil
	}), certificateObserverFunc(func(context.Context, string) (edgeprobe.CertificateObservation, error) {
		return edgeprobe.CertificateObservation{}, nil
	}), now)
	fact, err := probe.Check(ctx)
	if err == nil || fact.Severity != SeverityEmergency || !strings.Contains(fact.Subject, "cancelled") {
		t.Fatalf("fact=%+v err=%v", fact, err)
	}

	alpha := certificateObservation("alpha.example.test", certificateFingerprint('a'), now.Add(-time.Hour), now.Add(40*24*time.Hour))
	beta := certificateObservation("beta.example.test", certificateFingerprint('b'), now.Add(-time.Hour), now.Add(41*24*time.Hour))
	observer := certificateObserverFunc(func(_ context.Context, hostname string) (edgeprobe.CertificateObservation, error) {
		if hostname == alpha.Hostname {
			return alpha, nil
		}
		return beta, nil
	})
	first := taskCertificateProbe(t, certificateTargetsFunc(func(context.Context) ([]CertificateTarget, error) {
		return []CertificateTarget{{Hostname: beta.Hostname, ExpectedLeafSHA256: beta.Fingerprint}, {Hostname: alpha.Hostname, ExpectedLeafSHA256: alpha.Fingerprint, Console: true}}, nil
	}), observer, now)
	second := taskCertificateProbe(t, certificateTargetsFunc(func(context.Context) ([]CertificateTarget, error) {
		return []CertificateTarget{{Hostname: alpha.Hostname, ExpectedLeafSHA256: alpha.Fingerprint, Console: true}, {Hostname: beta.Hostname, ExpectedLeafSHA256: beta.Fingerprint}}, nil
	}), observer, now)
	firstFact, firstErr := first.Check(context.Background())
	secondFact, secondErr := second.Check(context.Background())
	if firstErr != nil || secondErr != nil || firstFact.Subject != secondFact.Subject || firstFact.Severity != secondFact.Severity {
		t.Fatalf("first=%+v %v second=%+v %v", firstFact, firstErr, secondFact, secondErr)
	}
}

func TestCertificateProbeFailurePersistsAndCancellationDoesNot(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	probe := taskCertificateProbe(t, certificateTargetsFunc(func(context.Context) ([]CertificateTarget, error) {
		return nil, errors.New("postgresql://token:secret@db.invalid/open-card")
	}), certificateObserverFunc(func(context.Context, string) (edgeprobe.CertificateObservation, error) {
		return edgeprobe.CertificateObservation{}, nil
	}), now)
	complete := collectorProbes(nil, nil)
	for index := range complete {
		if complete[index].Kind == CheckCertificate {
			complete[index] = probe
		}
	}
	root := t.TempDir()
	store, err := NewTaskStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := NewTaskHostCollector(complete, store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := collector.Evaluate(context.Background())
	if err != nil || !evaluation.Decision.Notify || evaluation.Snapshot.Overall != SeverityEmergency {
		t.Fatalf("evaluation=%+v err=%v", evaluation, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, incidentStateFile))
	if err != nil || strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "postgresql") {
		t.Fatalf("state=%q err=%v", raw, err)
	}

	cancelRoot := t.TempDir()
	cancelStore, err := NewTaskStateStore(cancelRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelStore.Close()
	cancelCollector, err := NewTaskHostCollector(complete, cancelStore, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cancelCollector.Evaluate(ctx); err == nil {
		t.Fatal("cancelled certificate evaluation succeeded")
	}
	if _, err := os.Lstat(filepath.Join(cancelRoot, incidentStateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled evaluation persisted state: %v", err)
	}
}

func taskCertificateProbe(t *testing.T, source CertificateTargetSource, observer edgeprobe.CertificateObserver, now time.Time) HostProbe {
	t.Helper()
	probe, err := NewTaskCertificateProbe(source, observer, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return probe
}

func certificateObservation(hostname, fingerprint string, notBefore, notAfter time.Time) edgeprobe.CertificateObservation {
	return edgeprobe.CertificateObservation{Hostname: hostname, Fingerprint: fingerprint, NotBefore: notBefore, NotAfter: notAfter}
}

func certificateFingerprint(character rune) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}
