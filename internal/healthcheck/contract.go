// Package healthcheck defines the secret-free, durable Gate7 host-health
// wire contract. Collection, persistence and webhook delivery intentionally
// live outside this package.
package healthcheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"time"
)

const SchemaVersion = 1
const HealthyFingerprint = "healthy"

type CheckKind string

const (
	CheckFiveUnits   CheckKind = "five_units"
	CheckListeners   CheckKind = "listeners"
	CheckDatabase    CheckKind = "database"
	CheckControlAPI  CheckKind = "control_api"
	CheckEdge        CheckKind = "edge"
	CheckBackup      CheckKind = "backup"
	CheckDisk        CheckKind = "disk"
	CheckInode       CheckKind = "inode"
	CheckCertificate CheckKind = "certificate"
	CheckWebhook     CheckKind = "webhook"
)

var fixedKinds = []CheckKind{CheckFiveUnits, CheckListeners, CheckDatabase, CheckControlAPI, CheckEdge, CheckBackup, CheckDisk, CheckInode, CheckCertificate, CheckWebhook}

type Severity string

const (
	SeverityOK        Severity = "ok"
	SeverityWarning   Severity = "warning"
	SeverityCritical  Severity = "critical"
	SeverityEmergency Severity = "emergency"
)

type CheckResult struct {
	Kind          CheckKind `json:"kind"`
	SubjectSHA256 string    `json:"subject_sha256"`
	Severity      Severity  `json:"severity"`
	Code          string    `json:"code"`
}

type Snapshot struct {
	SchemaVersion int           `json:"schema_version"`
	ObservedAt    time.Time     `json:"observed_at"`
	Results       []CheckResult `json:"results"`
	Overall       Severity      `json:"overall"`
}

type IncidentState struct {
	SchemaVersion        int       `json:"schema_version"`
	Revision             int64     `json:"revision"`
	Fingerprint          string    `json:"fingerprint"`
	FirstObserved        time.Time `json:"first_observed"`
	LastObserved         time.Time `json:"last_observed"`
	Severity             Severity  `json:"severity"`
	NotificationStage    int       `json:"notification_stage"`
	ThirtyMinuteNotified bool      `json:"thirty_minute_notified"`
	PendingNotification  string    `json:"pending_notification"`
	RecoveryPending      bool      `json:"recovery_pending"`
	RecoveryOf           string    `json:"recovery_of"`
	Healthy              bool      `json:"healthy"`
}

type Decision struct {
	State    IncidentState
	Notify   bool
	Recovery bool
	Noop     bool
}

var codePattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
var shaPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (r CheckResult) Validate() error {
	if !validKind(r.Kind) || !shaPattern.MatchString(r.SubjectSHA256) || !validSeverity(r.Severity) || !codePattern.MatchString(r.Code) {
		return errors.New("invalid health result")
	}
	return nil
}
func (s Snapshot) Validate() error {
	if s.SchemaVersion != SchemaVersion || !utc(s.ObservedAt) || len(s.Results) != len(fixedKinds) || !validSeverity(s.Overall) {
		return errors.New("invalid health snapshot")
	}
	seen := map[CheckKind]bool{}
	overall := SeverityOK
	for _, r := range s.Results {
		if r.Validate() != nil || seen[r.Kind] {
			return errors.New("invalid health snapshot")
		}
		seen[r.Kind] = true
		overall = maxSeverity(overall, r.Severity)
	}
	for _, kind := range fixedKinds {
		if !seen[kind] {
			return errors.New("invalid health snapshot")
		}
	}
	if s.Overall != overall {
		return errors.New("invalid health snapshot")
	}
	return nil
}
func (s IncidentState) Validate() error {
	if s.SchemaVersion != SchemaVersion || s.Revision < 1 || !utc(s.FirstObserved) || !utc(s.LastObserved) || s.LastObserved.Before(s.FirstObserved) || !validSeverity(s.Severity) || s.NotificationStage < 0 || s.NotificationStage > 3 {
		return errors.New("invalid incident state")
	}
	if s.PendingNotification != "" && s.PendingNotification != "occurrence" && s.PendingNotification != "escalation" && s.PendingNotification != "recovery" {
		return errors.New("invalid incident state")
	}
	if s.RecoveryPending != (s.PendingNotification == "recovery") {
		return errors.New("invalid incident state")
	}
	if s.Healthy {
		if s.Fingerprint != HealthyFingerprint || s.Severity != SeverityOK || s.NotificationStage != 0 || s.ThirtyMinuteNotified || s.PendingNotification != "" && s.PendingNotification != "recovery" || s.RecoveryPending != shaPattern.MatchString(s.RecoveryOf) || !s.RecoveryPending && s.RecoveryOf != "" {
			return errors.New("invalid incident state")
		}
		return nil
	}
	if !shaPattern.MatchString(s.Fingerprint) || s.Severity == SeverityOK || s.NotificationStage < 1 || s.RecoveryOf != "" {
		return errors.New("invalid incident state")
	}
	if s.PendingNotification == "occurrence" && s.NotificationStage != 1 || s.PendingNotification == "escalation" && s.NotificationStage < 2 || s.PendingNotification == "recovery" {
		return errors.New("invalid incident state")
	}
	return nil
}

func DiskSeverity(percent int) Severity  { return percentageSeverity(percent) }
func InodeSeverity(percent int) Severity { return percentageSeverity(percent) }
func percentageSeverity(percent int) Severity {
	if percent < 0 || percent > 100 {
		return SeverityEmergency
	}
	if percent < 70 {
		return SeverityOK
	}
	if percent < 85 {
		return SeverityWarning
	}
	if percent < 95 {
		return SeverityCritical
	}
	return SeverityEmergency
}
func CertificateSeverity(remaining time.Duration) Severity {
	if remaining <= 0 {
		return SeverityEmergency
	}
	if remaining <= 7*24*time.Hour {
		return SeverityEmergency
	}
	if remaining <= 14*24*time.Hour {
		return SeverityCritical
	}
	if remaining <= 30*24*time.Hour {
		return SeverityWarning
	}
	return SeverityOK
}
func BackupSeverity(age time.Duration, present bool) Severity {
	if !present || age < 0 || age > 72*time.Hour {
		return SeverityEmergency
	}
	if age > 48*time.Hour {
		return SeverityCritical
	}
	if age > 24*time.Hour {
		return SeverityWarning
	}
	return SeverityOK
}

func IncidentFingerprint(snapshot Snapshot) (string, error) {
	if snapshot.Validate() != nil {
		return "", errors.New("invalid health snapshot")
	}
	parts := make([]string, 0, len(snapshot.Results))
	for _, r := range snapshot.Results {
		if r.Severity != SeverityOK {
			parts = append(parts, string(r.Kind)+"\x00"+r.SubjectSHA256+"\x00"+string(r.Severity)+"\x00"+r.Code)
		}
	}
	if len(parts) == 0 {
		return HealthyFingerprint, nil
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(joinNul(parts)))
	return hex.EncodeToString(sum[:]), nil
}
func joinNul(parts []string) string {
	out := ""
	for _, p := range parts {
		out += p + "\n"
	}
	return out
}

// Decide applies one observed snapshot. The +30m reminder is represented by
// ThirtyMinuteNotified because the externally visible notification stage is
// intentionally bounded at 0..3.
func Decide(previous *IncidentState, snapshot Snapshot) (Decision, error) {
	if snapshot.Validate() != nil {
		return Decision{}, errors.New("invalid health snapshot")
	}
	fingerprint, err := IncidentFingerprint(snapshot)
	if err != nil {
		return Decision{}, err
	}
	if previous == nil {
		return firstDecision(snapshot, fingerprint), nil
	}
	if previous.Validate() != nil || snapshot.ObservedAt.Before(previous.LastObserved) {
		return Decision{}, errors.New("incident clock regression")
	}
	if fingerprint == HealthyFingerprint {
		if previous.RecoveryPending {
			return Decision{State: *previous, Recovery: true}, nil
		}
		if previous.Healthy {
			next := *previous
			if snapshot.ObservedAt.Equal(previous.LastObserved) {
				return Decision{State: next, Noop: true}, nil
			}
			next.Revision++
			next.LastObserved = snapshot.ObservedAt
			return Decision{State: next, Noop: true}, nil
		}
		next := IncidentState{SchemaVersion: SchemaVersion, Revision: previous.Revision + 1, Fingerprint: HealthyFingerprint, FirstObserved: snapshot.ObservedAt, LastObserved: snapshot.ObservedAt, Severity: SeverityOK, PendingNotification: "recovery", RecoveryPending: true, RecoveryOf: previous.Fingerprint, Healthy: true}
		return Decision{State: next, Recovery: true}, nil
	}
	if previous.Healthy || previous.Fingerprint != fingerprint {
		return firstDecisionWithRevision(snapshot, fingerprint, previous.Revision+1), nil
	}
	if previous.PendingNotification != "" {
		return Decision{State: *previous, Notify: true}, nil
	}
	next := *previous
	if snapshot.ObservedAt.Equal(previous.LastObserved) {
		return Decision{State: next, Noop: true}, nil
	}
	next.Revision++
	next.LastObserved = snapshot.ObservedAt
	next.Severity = snapshot.Overall
	age := snapshot.ObservedAt.Sub(previous.FirstObserved)
	if next.NotificationStage == 1 && age >= time.Minute {
		next.NotificationStage = 2
		next.PendingNotification = "escalation"
		return Decision{State: next, Notify: true}, nil
	}
	if next.NotificationStage == 2 && age >= 5*time.Minute {
		next.NotificationStage = 3
		next.PendingNotification = "escalation"
		return Decision{State: next, Notify: true}, nil
	}
	if next.NotificationStage == 3 && !next.ThirtyMinuteNotified && age >= 30*time.Minute {
		next.ThirtyMinuteNotified = true
		next.PendingNotification = "escalation"
		return Decision{State: next, Notify: true}, nil
	}
	return Decision{State: next, Noop: true}, nil
}
func firstDecision(snapshot Snapshot, fingerprint string) Decision {
	return firstDecisionWithRevision(snapshot, fingerprint, 1)
}
func firstDecisionWithRevision(snapshot Snapshot, fingerprint string, revision int64) Decision {
	if fingerprint == HealthyFingerprint {
		return Decision{State: IncidentState{SchemaVersion: SchemaVersion, Revision: revision, Fingerprint: HealthyFingerprint, FirstObserved: snapshot.ObservedAt, LastObserved: snapshot.ObservedAt, Severity: SeverityOK, Healthy: true}, Noop: true}
	}
	return Decision{State: IncidentState{SchemaVersion: SchemaVersion, Revision: revision, Fingerprint: fingerprint, FirstObserved: snapshot.ObservedAt, LastObserved: snapshot.ObservedAt, Severity: snapshot.Overall, NotificationStage: 1, PendingNotification: "occurrence"}, Notify: true}
}

// AcknowledgeDelivery clears one durable pending notification only after the
// caller has positively persisted delivery success. Failed delivery leaves
// the state unchanged so Decide returns the same notification after restart.
func AcknowledgeDelivery(previous IncidentState) (IncidentState, error) {
	if previous.Validate() != nil || previous.PendingNotification == "" {
		return IncidentState{}, errors.New("no pending notification")
	}
	next := previous
	next.Revision++
	next.PendingNotification = ""
	next.RecoveryPending = false
	next.RecoveryOf = ""
	if next.Validate() != nil {
		return IncidentState{}, errors.New("invalid acknowledged incident")
	}
	return next, nil
}

func MarshalSnapshot(snapshot Snapshot) ([]byte, error) {
	if snapshot.Validate() != nil {
		return nil, errors.New("invalid health snapshot")
	}
	return json.Marshal(snapshot)
}
func ParseSnapshot(raw []byte) (Snapshot, error) {
	var v Snapshot
	if err := strictDecode(raw, &v); err != nil {
		return v, err
	}
	if err := requireSnapshotFields(raw); err != nil {
		return v, err
	}
	return v, v.Validate()
}
func MarshalIncident(state IncidentState) ([]byte, error) {
	if state.Validate() != nil {
		return nil, errors.New("invalid incident state")
	}
	return json.Marshal(state)
}
func ParseIncident(raw []byte) (IncidentState, error) {
	var v IncidentState
	if err := strictDecode(raw, &v); err != nil {
		return v, err
	}
	// recovery_of was added before the first production healthcheck release.
	// Accept the known earlier shape only when it has no pending recovery; the
	// recovered fingerprint cannot be reconstructed for a legacy pending state.
	if err := requireObjectFields(raw, []string{"schema_version", "revision", "fingerprint", "first_observed", "last_observed", "severity", "notification_stage", "thirty_minute_notified", "pending_notification", "recovery_pending", "healthy"}); err != nil {
		return v, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return v, err
	}
	if _, present := fields["recovery_of"]; !present && v.RecoveryPending {
		return v, errors.New("legacy pending recovery has no incident identity")
	}
	return v, v.Validate()
}

func validKind(k CheckKind) bool {
	for _, v := range fixedKinds {
		if v == k {
			return true
		}
	}
	return false
}
func validSeverity(s Severity) bool {
	return s == SeverityOK || s == SeverityWarning || s == SeverityCritical || s == SeverityEmergency
}
func severityRank(s Severity) int {
	switch s {
	case SeverityOK:
		return 0
	case SeverityWarning:
		return 1
	case SeverityCritical:
		return 2
	case SeverityEmergency:
		return 3
	}
	return -1
}
func maxSeverity(a, b Severity) Severity {
	if severityRank(b) > severityRank(a) {
		return b
	}
	return a
}
func utc(t time.Time) bool { return !t.IsZero() && t.Location() == time.UTC }

func strictDecode(raw []byte, target any) error {
	if err := rejectDuplicateAndTrailing(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON")
	}
	if hasNull(raw) {
		return errors.New("null JSON field")
	}
	return nil
}
func rejectDuplicateAndTrailing(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := walkJSON(d); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func walkJSON(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch t := token.(type) {
	case json.Delim:
		if t == '{' {
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate JSON field")
				}
				seen[name] = true
				if err := walkJSON(d); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("invalid JSON object")
			}
		} else if t == '[' {
			for d.More() {
				if err := walkJSON(d); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("invalid JSON array")
			}
		}
	}
	return nil
}
func hasNull(raw []byte) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return true
	}
	return containsNull(value)
}
func containsNull(value any) bool {
	switch x := value.(type) {
	case nil:
		return true
	case []any:
		for _, v := range x {
			if containsNull(v) {
				return true
			}
		}
	case map[string]any:
		for _, v := range x {
			if containsNull(v) {
				return true
			}
		}
	}
	return false
}
func requireSnapshotFields(raw []byte) error {
	if err := requireObjectFields(raw, []string{"schema_version", "observed_at", "results", "overall"}); err != nil {
		return err
	}
	var value struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	for _, result := range value.Results {
		if err := requireObjectFields(result, []string{"kind", "subject_sha256", "severity", "code"}); err != nil {
			return err
		}
	}
	return nil
}
func requireObjectFields(raw []byte, fields []string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return err
	}
	for _, field := range fields {
		value, ok := object[field]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("missing JSON field")
		}
	}
	return nil
}
