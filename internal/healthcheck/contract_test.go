package healthcheck

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func subject(CheckKind) string { return strings.Repeat("a", 64) }
func snapshotAt(t time.Time, override map[CheckKind]Severity) Snapshot {
	results := make([]CheckResult, 0, len(fixedKinds))
	overall := SeverityOK
	for _, kind := range fixedKinds {
		sev := SeverityOK
		if override != nil {
			if v, ok := override[kind]; ok {
				sev = v
			}
		}
		results = append(results, CheckResult{Kind: kind, SubjectSHA256: subject(kind), Severity: sev, Code: "healthy"})
		overall = maxSeverity(overall, sev)
	}
	return Snapshot{SchemaVersion: SchemaVersion, ObservedAt: t, Results: results, Overall: overall}
}
func unhealthy(t time.Time) Snapshot {
	s := snapshotAt(t, map[CheckKind]Severity{CheckDatabase: SeverityCritical})
	for i := range s.Results {
		if s.Results[i].Kind == CheckDatabase {
			s.Results[i].Code = "database_unavailable"
		}
	}
	return s
}

func TestThresholdBoundaries(t *testing.T) {
	for value, want := range map[int]Severity{-1: SeverityEmergency, 0: SeverityOK, 69: SeverityOK, 70: SeverityWarning, 84: SeverityWarning, 85: SeverityCritical, 94: SeverityCritical, 95: SeverityEmergency, 100: SeverityEmergency, 101: SeverityEmergency} {
		if DiskSeverity(value) != want || InodeSeverity(value) != want {
			t.Fatalf("percent %d", value)
		}
	}
	for value, want := range map[time.Duration]Severity{31 * 24 * time.Hour: SeverityOK, 30 * 24 * time.Hour: SeverityWarning, 14 * 24 * time.Hour: SeverityCritical, 7 * 24 * time.Hour: SeverityEmergency, 0: SeverityEmergency} {
		if CertificateSeverity(value) != want {
			t.Fatalf("certificate %s", value)
		}
	}
	for _, tc := range []struct {
		age     time.Duration
		present bool
		want    Severity
	}{{24 * time.Hour, true, SeverityOK}, {24*time.Hour + time.Second, true, SeverityWarning}, {48*time.Hour + time.Second, true, SeverityCritical}, {72*time.Hour + time.Second, true, SeverityEmergency}, {0, false, SeverityEmergency}, {-time.Second, true, SeverityEmergency}} {
		if BackupSeverity(tc.age, tc.present) != tc.want {
			t.Fatalf("backup %#v", tc)
		}
	}
}

func TestSnapshotStrictnessOrderingAndFingerprint(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	healthy := snapshotAt(now, nil)
	if healthy.Validate() != nil {
		t.Fatal("healthy invalid")
	}
	fingerprint, err := IncidentFingerprint(healthy)
	if err != nil || fingerprint != HealthyFingerprint {
		t.Fatalf("healthy fingerprint %q %v", fingerprint, err)
	}
	bad := unhealthy(now)
	first, err := IncidentFingerprint(bad)
	if err != nil || len(first) != 64 {
		t.Fatal(err)
	}
	bad.Results[0], bad.Results[1] = bad.Results[1], bad.Results[0]
	second, err := IncidentFingerprint(bad)
	if err != nil || first != second {
		t.Fatal("fingerprint is not deterministic")
	}
	bad.Results = bad.Results[:9]
	if bad.Validate() == nil {
		t.Fatal("missing kind accepted")
	}
	bad = snapshotAt(now, nil)
	bad.Results[1].Kind = bad.Results[0].Kind
	if bad.Validate() == nil {
		t.Fatal("duplicate kind accepted")
	}
	bad = snapshotAt(now, nil)
	bad.Overall = SeverityCritical
	if bad.Validate() == nil {
		t.Fatal("wrong overall accepted")
	}
}

func TestIncidentEscalationRecoveryAndIdempotence(t *testing.T) {
	start := time.Date(2026, 2, 3, 4, 5, 0, 0, time.UTC)
	incident := unhealthy(start)
	first, err := Decide(nil, incident)
	if err != nil || !first.Notify || first.State.NotificationStage != 1 || first.State.Revision != 1 || first.State.PendingNotification != "occurrence" {
		t.Fatalf("first=%#v %v", first, err)
	}
	retryOccurrence, err := Decide(&first.State, unhealthy(start.Add(30*time.Second)))
	if err != nil || !retryOccurrence.Notify || retryOccurrence.State != first.State {
		t.Fatalf("retry occurrence=%#v %v", retryOccurrence, err)
	}
	ackFirst, err := AcknowledgeDelivery(first.State)
	if err != nil || ackFirst.PendingNotification != "" || ackFirst.Revision != 2 {
		t.Fatalf("ack first=%#v %v", ackFirst, err)
	}
	nochange, err := Decide(&ackFirst, incident)
	if err != nil || !nochange.Noop || nochange.Notify {
		t.Fatalf("same=%#v %v", nochange, err)
	}
	one, err := Decide(&ackFirst, unhealthy(start.Add(time.Minute)))
	if err != nil || !one.Notify || one.State.NotificationStage != 2 || one.State.PendingNotification != "escalation" {
		t.Fatalf("one=%#v %v", one, err)
	}
	ackOne, err := AcknowledgeDelivery(one.State)
	if err != nil {
		t.Fatal(err)
	}
	five, err := Decide(&ackOne, unhealthy(start.Add(5*time.Minute)))
	if err != nil || !five.Notify || five.State.NotificationStage != 3 || five.State.ThirtyMinuteNotified {
		t.Fatalf("five=%#v %v", five, err)
	}
	ackFive, err := AcknowledgeDelivery(five.State)
	if err != nil {
		t.Fatal(err)
	}
	thirty, err := Decide(&ackFive, unhealthy(start.Add(30*time.Minute)))
	if err != nil || !thirty.Notify || thirty.State.NotificationStage != 3 || !thirty.State.ThirtyMinuteNotified {
		t.Fatalf("thirty=%#v %v", thirty, err)
	}
	retryThirty, err := Decide(&thirty.State, unhealthy(start.Add(31*time.Minute)))
	if err != nil || !retryThirty.Notify || retryThirty.State != thirty.State {
		t.Fatalf("retry thirty=%#v %v", retryThirty, err)
	}
	ackThirty, err := AcknowledgeDelivery(thirty.State)
	if err != nil {
		t.Fatal(err)
	}
	repeat, err := Decide(&ackThirty, unhealthy(start.Add(31*time.Minute)))
	if err != nil || !repeat.Noop || repeat.Notify {
		t.Fatalf("repeat=%#v %v", repeat, err)
	}
	healthy, err := Decide(&repeat.State, snapshotAt(start.Add(32*time.Minute), nil))
	if err != nil || !healthy.Recovery || !healthy.State.Healthy || healthy.State.Fingerprint != HealthyFingerprint || !healthy.State.RecoveryPending || healthy.State.PendingNotification != "recovery" || healthy.State.RecoveryOf != repeat.State.Fingerprint {
		t.Fatalf("healthy=%#v %v", healthy, err)
	}
	retryRecovery, err := Decide(&healthy.State, snapshotAt(start.Add(33*time.Minute), nil))
	if err != nil || !retryRecovery.Recovery || retryRecovery.State != healthy.State {
		t.Fatalf("retry recovery=%#v %v", retryRecovery, err)
	}
	invalidRecovery := healthy.State
	invalidRecovery.RecoveryOf = ""
	if invalidRecovery.Validate() == nil {
		t.Fatal("recovery without recovered incident identity was accepted")
	}
	ackRecovery, err := AcknowledgeDelivery(healthy.State)
	if err != nil || ackRecovery.RecoveryPending || ackRecovery.PendingNotification != "" || ackRecovery.RecoveryOf != "" {
		t.Fatalf("ack recovery=%#v %v", ackRecovery, err)
	}
	stable, err := Decide(&ackRecovery, snapshotAt(start.Add(33*time.Minute), nil))
	if err != nil || !stable.Noop || stable.Recovery {
		t.Fatalf("stable=%#v %v", stable, err)
	}
	changed := unhealthy(start.Add(34 * time.Minute))
	for i := range changed.Results {
		if changed.Results[i].Kind == CheckDatabase {
			changed.Results[i].SubjectSHA256 = strings.Repeat("f", 64)
		}
	}
	decision, err := Decide(&repeat.State, changed)
	if err != nil || !decision.Notify || decision.State.NotificationStage != 1 || decision.State.Fingerprint == repeat.State.Fingerprint {
		t.Fatalf("changed=%#v %v", decision, err)
	}
	if _, err := Decide(&repeat.State, unhealthy(start.Add(29*time.Minute))); err == nil {
		t.Fatal("clock regression accepted")
	}
	if _, err := AcknowledgeDelivery(repeat.State); err == nil {
		t.Fatal("acknowledged state without pending notification")
	}
}

func TestStrictMarshalParseAndSecretFreeSurface(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	sample := unhealthy(now)
	raw, err := MarshalSnapshot(sample)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSnapshot(raw); err != nil {
		t.Fatal(err)
	}
	duplicate := append([]byte(`{"schema_version":1,"schema_version":1,`), raw[1:]...)
	trailing := append(append([]byte(nil), raw...), []byte(` {}`)...)
	for _, mutation := range [][]byte{duplicate, []byte(`{"schema_version":1,"observed_at":null,"results":[],"overall":"ok"}`), trailing} {
		if _, err := ParseSnapshot(mutation); err == nil {
			t.Fatal("invalid strict JSON accepted")
		}
	}
	unknown := append([]byte(`{"unknown":true,`), raw[1:]...)
	if _, err := ParseSnapshot(unknown); err == nil {
		t.Fatal("unknown snapshot field accepted")
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	rows := wire["results"].([]any)
	rows[0].(map[string]any)["code"] = "duplicate"
	mutated, _ := json.Marshal(wire)
	if _, err := ParseSnapshot(mutated); err != nil {
		t.Fatalf("canonical snapshot rejected: %v", err)
	}
	decision, err := Decide(nil, sample)
	if err != nil {
		t.Fatal(err)
	}
	stateRaw, err := MarshalIncident(decision.State)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseIncident(stateRaw)
	if err != nil || parsed != decision.State {
		t.Fatalf("state=%#v %v", parsed, err)
	}
	for _, secret := range []string{"postgresql://", "password", "token", "/var/lib", "message", "output", "url", "dsn"} {
		if strings.Contains(string(raw), secret) || strings.Contains(string(stateRaw), secret) {
			t.Fatalf("wire contract leaked %q", secret)
		}
	}
	encoded, _ := json.Marshal(CheckResult{})
	if strings.Contains(string(encoded), "message") || strings.Contains(string(encoded), "path") {
		t.Fatal("result has unsafe field")
	}
}

func TestIncidentParserMigratesOnlySafeLegacyState(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	decision, err := Decide(nil, unhealthy(now))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalIncident(decision.State)
	if err != nil {
		t.Fatal(err)
	}
	legacy := bytes.Replace(raw, []byte(`,"recovery_of":""`), nil, 1)
	parsed, err := ParseIncident(legacy)
	if err != nil || parsed != decision.State {
		t.Fatalf("legacy state=%#v err=%v", parsed, err)
	}
	acknowledged, err := AcknowledgeDelivery(decision.State)
	if err != nil {
		t.Fatal(err)
	}
	acknowledgedRaw, err := MarshalIncident(acknowledged)
	if err != nil {
		t.Fatal(err)
	}
	legacyAcknowledged := bytes.Replace(acknowledgedRaw, []byte(`,"recovery_of":""`), nil, 1)
	parsedAcknowledged, err := ParseIncident(legacyAcknowledged)
	if err != nil || parsedAcknowledged != acknowledged {
		t.Fatalf("legacy acknowledged=%#v err=%v", parsedAcknowledged, err)
	}
	recovery, err := Decide(&acknowledged, snapshotAt(now.Add(time.Minute), nil))
	if err != nil {
		t.Fatal(err)
	}
	recoveryRaw, err := MarshalIncident(recovery.State)
	if err != nil {
		t.Fatal(err)
	}
	legacyRecovery := bytes.Replace(recoveryRaw, []byte(`,"recovery_of":"`+recovery.State.RecoveryOf+`"`), nil, 1)
	if _, err := ParseIncident(legacyRecovery); err == nil {
		t.Fatal("legacy pending recovery without incident identity was accepted")
	}
}
