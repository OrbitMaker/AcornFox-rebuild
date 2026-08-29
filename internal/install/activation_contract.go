package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const ActivationSchemaVersion = 1
const upgradeArtifactsRoot = "/var/lib/open-card/upgrade-artifacts"

var installID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var sha256Text = regexp.MustCompile(`^[a-f0-9]{64}$`)

type JournalState string

const (
	JournalPreflighted      JournalState = "PREFLIGHTED"
	JournalLegacyProjected  JournalState = "LEGACY_PROJECTED"
	JournalQuiesced         JournalState = "QUIESCED"
	JournalSnapshotCreated  JournalState = "SNAPSHOT_CREATED"
	JournalCandidateDBReady JournalState = "CANDIDATE_DB_READY"
	JournalMigrated         JournalState = "MIGRATED"
	JournalValidated        JournalState = "VALIDATED"
	JournalActiveSwitched   JournalState = "ACTIVE_SWITCHED"
	JournalHealthy          JournalState = "HEALTHY"
	JournalEdgeArmed        JournalState = "EDGE_ARMED"
	JournalCommitted        JournalState = "COMMITTED"
	JournalAbortedPreSwitch JournalState = "ABORTED_PRE_SWITCH"
	JournalRollbackSwitched JournalState = "ROLLBACK_SWITCHED"
	JournalRolledBack       JournalState = "ROLLED_BACK"
	JournalRecoveryRequired JournalState = "RECOVERY_REQUIRED"
)

type ReleaseV1 struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	SourceCommit   string `json:"source_commit"`
	Architecture   string `json:"architecture"`
	ManifestSHA256 string `json:"manifest_sha256"`
}
type DatabaseV1 struct {
	Name                   string `json:"name"`
	Migration              string `json:"migration"`
	SchemaMigrationsSHA256 string `json:"schema_migrations_sha256"`
}
type LegacyProjectionV1 struct {
	Target string `json:"target"`
}
type ActivationV1 struct {
	SchemaVersion          int                 `json:"schema_version"`
	ActivationID           string              `json:"activation_id"`
	Origin                 string              `json:"origin"`
	Release                ReleaseV1           `json:"release"`
	Database               DatabaseV1          `json:"database"`
	DatabaseEnvSHA256      string              `json:"database_env_sha256"`
	CreatedAt              time.Time           `json:"created_at"`
	CreatedByTransactionID string              `json:"created_by_transaction_id"`
	LegacyProjection       *LegacyProjectionV1 `json:"legacy_projection,omitempty"`
}
type ArtifactV1 struct {
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
	SourceDatabase string `json:"source_database,omitempty"`
}
type MigrationV1 struct {
	From           string `json:"from"`
	To             string `json:"to"`
	ManifestSHA256 string `json:"manifest_sha256"`
}
type FailureV1 struct {
	Code          string       `json:"code"`
	Phase         JournalState `json:"phase"`
	MessageDigest string       `json:"message_digest"`
}
type JournalTransitionV1 struct {
	Revision       int64        `json:"revision"`
	From           JournalState `json:"from"`
	To             JournalState `json:"to"`
	At             time.Time    `json:"at"`
	EvidenceSHA256 string       `json:"evidence_sha256"`
}
type UnitSnapshotV1 struct {
	Active  bool `json:"active"`
	Enabled bool `json:"enabled"`
}
type ServiceSnapshotV1 struct {
	Edge     UnitSnapshotV1 `json:"edge"`
	Agent    UnitSnapshotV1 `json:"agent"`
	Server   UnitSnapshotV1 `json:"server"`
	Caddy    UnitSnapshotV1 `json:"caddy"`
	BuildKit UnitSnapshotV1 `json:"buildkit"`
}
type UpgradeJournalV1 struct {
	SchemaVersion                          int                   `json:"schema_version"`
	TransactionID                          string                `json:"transaction_id"`
	Revision                               int64                 `json:"revision"`
	State                                  JournalState          `json:"state"`
	CreatedAt                              time.Time             `json:"created_at"`
	UpdatedAt                              time.Time             `json:"updated_at"`
	RequestedManifestSHA256                string                `json:"requested_manifest_sha256"`
	OldActivationID                        string                `json:"old_activation_id"`
	OldActivationJSONSHA256                string                `json:"old_activation_json_sha256"`
	PreUpgradePreviousActivationID         string                `json:"pre_upgrade_previous_activation_id,omitempty"`
	PreUpgradePreviousActivationJSONSHA256 string                `json:"pre_upgrade_previous_activation_json_sha256,omitempty"`
	CandidateActivationID                  string                `json:"candidate_activation_id"`
	CandidateActivationJSONSHA256          string                `json:"candidate_activation_json_sha256,omitempty"`
	CandidateDatabaseName                  string                `json:"candidate_database_name"`
	CandidateDatabase                      *DatabaseV1           `json:"candidate_database,omitempty"`
	Snapshot                               *ArtifactV1           `json:"snapshot,omitempty"`
	Migration                              *MigrationV1          `json:"migration,omitempty"`
	Validation                             *ArtifactV1           `json:"validation,omitempty"`
	ServiceSnapshot                        ServiceSnapshotV1     `json:"service_snapshot"`
	Failure                                *FailureV1            `json:"failure,omitempty"`
	History                                []JournalTransitionV1 `json:"history"`
}

// CanonicalServiceSnapshotSHA256 returns the digest of the fixed service
// snapshot wire representation. ServiceSnapshotV1 deliberately uses a struct
// (rather than a map) so this representation has a stable field order.
func CanonicalServiceSnapshotSHA256(snapshot ServiceSnapshotV1) string {
	raw, _ := json.Marshal(snapshot)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func validID(v string) bool            { return installID.MatchString(v) }
func validSHA(v string) bool           { return sha256Text.MatchString(v) }
func artifactPath(tx, n string) string { return filepath.Join(upgradeArtifactsRoot, tx, n) }
func safeAbsPath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.Contains(value, "\x00")
}
func (r ReleaseV1) valid() bool {
	return validID(r.ID) && r.Version != "" && regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(r.SourceCommit) && validID(r.Architecture) && validSHA(r.ManifestSHA256)
}
func (d DatabaseV1) valid() bool {
	return validID(d.Name) && regexp.MustCompile(`^[0-9]{4}$`).MatchString(d.Migration) && validSHA(d.SchemaMigrationsSHA256)
}
func stateOK(v JournalState) bool {
	switch v {
	case JournalPreflighted, JournalLegacyProjected, JournalQuiesced, JournalSnapshotCreated, JournalCandidateDBReady, JournalMigrated, JournalValidated, JournalActiveSwitched, JournalHealthy, JournalEdgeArmed, JournalCommitted, JournalAbortedPreSwitch, JournalRollbackSwitched, JournalRolledBack, JournalRecoveryRequired:
		return true
	}
	return false
}
func terminal(v JournalState) bool {
	return v == JournalCommitted || v == JournalAbortedPreSwitch || v == JournalRolledBack || v == JournalRecoveryRequired
}

func journalRank(v JournalState) (int, bool) {
	switch v {
	case JournalPreflighted, JournalLegacyProjected:
		return 0, true
	case JournalQuiesced:
		return 1, true
	case JournalSnapshotCreated:
		return 2, true
	case JournalCandidateDBReady:
		return 3, true
	case JournalMigrated:
		return 4, true
	case JournalValidated:
		return 5, true
	case JournalActiveSwitched, JournalRollbackSwitched, JournalRolledBack:
		return 6, true
	case JournalHealthy:
		return 7, true
	case JournalEdgeArmed:
		return 8, true
	case JournalCommitted:
		return 9, true
	}
	return 0, false
}

func failureState(v JournalState) bool {
	return v == JournalAbortedPreSwitch || v == JournalRollbackSwitched || v == JournalRolledBack || v == JournalRecoveryRequired
}

func validFailure(v *FailureV1) bool {
	return v != nil && validID(v.Code) && stateOK(v.Phase) && validSHA(v.MessageDigest)
}

func validSnapshot(tx string, a *ArtifactV1) bool {
	return a != nil && a.Path == artifactPath(tx, "control-plane.dump") && !strings.Contains(a.Path, "\x00") && validSHA(a.SHA256) && a.Size > 0 && validID(a.SourceDatabase)
}

func validValidation(tx string, a *ArtifactV1) bool {
	return a != nil && a.Path == artifactPath(tx, "validation.json") && !strings.Contains(a.Path, "\x00") && validSHA(a.SHA256) && a.Size > 0 && a.SourceDatabase == ""
}

func (j UpgradeJournalV1) effectiveEvidenceRank() (int, error) {
	if j.State == JournalAbortedPreSwitch || j.State == JournalRecoveryRequired {
		if len(j.History) == 0 {
			return 0, fmt.Errorf("terminal journal without history")
		}
		if rank, ok := journalRank(j.History[len(j.History)-1].From); ok {
			return rank, nil
		}
		return 0, fmt.Errorf("invalid terminal evidence rank")
	}
	rank, ok := journalRank(j.State)
	if !ok {
		return 0, fmt.Errorf("invalid journal evidence rank")
	}
	return rank, nil
}
func (a ActivationV1) Validate() error {
	if a.SchemaVersion != 1 || !validID(a.ActivationID) || !validID(a.Origin) || !a.Release.valid() || !a.Database.valid() || !validSHA(a.DatabaseEnvSHA256) || a.CreatedAt.IsZero() || !validID(a.CreatedByTransactionID) {
		return fmt.Errorf("invalid activation v1")
	}
	if a.LegacyProjection != nil && a.LegacyProjection.Target != filepath.Join("/opt/open-card/releases", a.Release.ID) {
		return fmt.Errorf("invalid legacy projection")
	}
	return nil
}
func (j UpgradeJournalV1) Validate() error {
	if j.SchemaVersion != 1 || !validID(j.TransactionID) || j.History == nil || j.Revision != int64(len(j.History)+1) || !stateOK(j.State) || j.CreatedAt.IsZero() || j.UpdatedAt.Before(j.CreatedAt) || !validSHA(j.RequestedManifestSHA256) || !validID(j.OldActivationID) || !validSHA(j.OldActivationJSONSHA256) || !validID(j.CandidateActivationID) || !candidateDatabaseName.MatchString(j.CandidateDatabaseName) {
		return fmt.Errorf("invalid upgrade journal v1")
	}
	if (j.PreUpgradePreviousActivationID == "") != (j.PreUpgradePreviousActivationJSONSHA256 == "") || j.PreUpgradePreviousActivationID != "" && (!validID(j.PreUpgradePreviousActivationID) || !validSHA(j.PreUpgradePreviousActivationJSONSHA256)) {
		return fmt.Errorf("invalid pre-upgrade previous activation")
	}
	if len(j.History) == 0 {
		if j.Revision != 1 || j.State != JournalPreflighted || !j.UpdatedAt.Equal(j.CreatedAt) {
			return fmt.Errorf("invalid initial journal")
		}
	} else {
		lastAt := j.CreatedAt
		previous := JournalPreflighted
		for i, h := range j.History {
			if h.Revision != int64(i+2) || h.From != previous || h.At.IsZero() || h.At.Before(lastAt) || h.At.After(j.UpdatedAt) || !validSHA(h.EvidenceSHA256) || ValidateJournalTransition(h.From, h.To) != nil {
				return fmt.Errorf("invalid journal history")
			}
			lastAt, previous = h.At, h.To
		}
		if j.State != previous || j.UpdatedAt.Before(lastAt) {
			return fmt.Errorf("invalid journal history state")
		}
	}
	rank, err := j.effectiveEvidenceRank()
	if err != nil {
		return err
	}
	if rank >= 2 && !validSnapshot(j.TransactionID, j.Snapshot) {
		return fmt.Errorf("invalid progressive snapshot")
	}
	if rank < 2 && j.Snapshot != nil {
		return fmt.Errorf("early snapshot")
	}
	if rank >= 4 && (j.CandidateDatabase == nil || !j.CandidateDatabase.valid() || j.CandidateDatabase.Name != j.CandidateDatabaseName || j.CandidateDatabase.Migration != "0024" || j.Migration == nil || j.Migration.From != "0023" || j.Migration.To != "0024" || !validSHA(j.Migration.ManifestSHA256)) {
		return fmt.Errorf("invalid progressive candidate")
	}
	if rank < 4 && (j.CandidateDatabase != nil || j.Migration != nil) {
		return fmt.Errorf("early progressive candidate")
	}
	if rank >= 5 && (j.CandidateActivationJSONSHA256 == "" || !validSHA(j.CandidateActivationJSONSHA256) || j.Validation == nil || j.Validation.Path != artifactPath(j.TransactionID, "validation.json") || !validSHA(j.Validation.SHA256) || j.Validation.Size <= 0 || j.Validation.SourceDatabase != "") {
		return fmt.Errorf("invalid progressive validation")
	}
	if rank < 5 && (j.CandidateActivationJSONSHA256 != "" || j.Validation != nil) {
		return fmt.Errorf("early progressive validation")
	}
	if failureState(j.State) {
		if !validFailure(j.Failure) {
			return fmt.Errorf("invalid journal failure")
		}
	} else if j.Failure != nil {
		return fmt.Errorf("unexpected journal failure")
	}
	return nil
}
func ValidateJournalTransition(f, t JournalState) error {
	if !stateOK(f) || !stateOK(t) || terminal(f) {
		return fmt.Errorf("invalid journal transition")
	}
	if t == JournalRecoveryRequired {
		return nil
	}
	if t == JournalAbortedPreSwitch {
		switch f {
		case JournalPreflighted, JournalLegacyProjected, JournalQuiesced, JournalSnapshotCreated, JournalCandidateDBReady, JournalMigrated, JournalValidated:
			return nil
		}
	}
	if f == JournalPreflighted && t == JournalQuiesced {
		return nil
	}
	h := []JournalState{JournalPreflighted, JournalLegacyProjected, JournalQuiesced, JournalSnapshotCreated, JournalCandidateDBReady, JournalMigrated, JournalValidated, JournalActiveSwitched, JournalHealthy, JournalEdgeArmed, JournalCommitted}
	for i := 0; i < len(h)-1; i++ {
		if f == h[i] && t == h[i+1] {
			return nil
		}
	}
	if (f == JournalActiveSwitched || f == JournalHealthy || f == JournalEdgeArmed) && t == JournalRollbackSwitched {
		return nil
	}
	if f == JournalRollbackSwitched && t == JournalRolledBack {
		return nil
	}
	return fmt.Errorf("invalid journal transition")
}
func scanJSON(d *json.Decoder) error {
	tok, e := d.Token()
	if e != nil {
		return e
	}
	if x, ok := tok.(json.Delim); ok {
		switch x {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return fmt.Errorf("duplicate JSON key")
				}
				seen[s] = true
				if e = scanJSON(d); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		case '[':
			for d.More() {
				if e = scanJSON(d); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		}
	}
	return nil
}
func decodeStrict(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	if e := scanJSON(d); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

func requireJournalFields(raw []byte, j UpgradeJournalV1) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	required := []string{"schema_version", "transaction_id", "revision", "state", "created_at", "updated_at", "requested_manifest_sha256", "old_activation_id", "old_activation_json_sha256", "candidate_activation_id", "candidate_database_name", "service_snapshot", "history"}
	for _, name := range required {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("missing required journal field %q", name)
		}
	}
	rank, err := j.effectiveEvidenceRank()
	if err != nil {
		return err
	}
	checks := []struct {
		name     string
		required bool
	}{
		{"snapshot", rank >= 2},
		{"candidate_database", rank >= 4},
		{"migration", rank >= 4},
		{"candidate_activation_json_sha256", rank >= 5},
		{"validation", rank >= 5},
		{"failure", failureState(j.State)},
	}
	for _, check := range checks {
		value, present := fields[check.name]
		if check.required && (!present || bytes.Equal(bytes.TrimSpace(value), []byte("null"))) {
			return fmt.Errorf("missing required progressive journal field %q", check.name)
		}
		if !check.required && present {
			return fmt.Errorf("early or unexpected progressive journal field %q", check.name)
		}
	}
	return nil
}
func ParseActivationV1(raw []byte) (ActivationV1, error) {
	var a ActivationV1
	if e := decodeStrict(raw, &a); e != nil {
		return a, e
	}
	return a, a.Validate()
}
func ParseUpgradeJournalV1(raw []byte) (UpgradeJournalV1, error) {
	var j UpgradeJournalV1
	if e := decodeStrict(raw, &j); e != nil {
		return j, e
	}
	if e := j.Validate(); e != nil {
		return j, e
	}
	return j, requireJournalFields(raw, j)
}
func MarshalActivationV1(a ActivationV1) ([]byte, error) {
	if e := a.Validate(); e != nil {
		return nil, e
	}
	return json.Marshal(a)
}
func MarshalUpgradeJournalV1(j UpgradeJournalV1) ([]byte, error) {
	if e := j.Validate(); e != nil {
		return nil, e
	}
	return json.Marshal(j)
}
func ParseDatabaseEnv(raw []byte) (string, error) {
	const p = "OPEN_CARD_DATABASE_URL="
	if !bytes.HasSuffix(raw, []byte("\n")) || bytes.Count(raw, []byte("\n")) != 1 || bytes.ContainsAny(raw, "\x00\r") {
		return "", fmt.Errorf("invalid database.env")
	}
	line := strings.TrimSuffix(string(raw), "\n")
	if !strings.HasPrefix(line, p) {
		return "", fmt.Errorf("invalid database.env")
	}
	v := strings.TrimPrefix(line, p)
	if v == "" || strings.ContainsAny(v, " \t#$\\'\"") {
		return "", fmt.Errorf("invalid database.env")
	}
	u, e := url.Parse(v)
	if e != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" || u.User == nil || u.User.Username() == "" || strings.Trim(u.Path, "/") == "" {
		return "", fmt.Errorf("invalid database.env")
	}
	return v, nil
}
func FormatDatabaseEnv(v string) ([]byte, error) {
	if _, e := ParseDatabaseEnv([]byte("OPEN_CARD_DATABASE_URL=" + v + "\n")); e != nil {
		return nil, e
	}
	return []byte("OPEN_CARD_DATABASE_URL=" + v + "\n"), nil
}
