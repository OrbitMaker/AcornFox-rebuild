package install

import (
	"bytes"
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
	From JournalState `json:"from"`
	To   JournalState `json:"to"`
	At   time.Time    `json:"at"`
}
type UpgradeJournalV1 struct {
	SchemaVersion                 int                   `json:"schema_version"`
	TransactionID                 string                `json:"transaction_id"`
	Revision                      int64                 `json:"revision"`
	State                         JournalState          `json:"state"`
	CreatedAt                     time.Time             `json:"created_at"`
	UpdatedAt                     time.Time             `json:"updated_at"`
	RequestedManifestSHA256       string                `json:"requested_manifest_sha256"`
	OldActivationID               string                `json:"old_activation_id"`
	OldActivationJSONSHA256       string                `json:"old_activation_json_sha256"`
	CandidateActivationID         string                `json:"candidate_activation_id"`
	CandidateActivationJSONSHA256 string                `json:"candidate_activation_json_sha256"`
	CandidateDatabase             DatabaseV1            `json:"candidate_database"`
	Snapshot                      ArtifactV1            `json:"snapshot"`
	Migration                     MigrationV1           `json:"migration"`
	Validation                    ArtifactV1            `json:"validation"`
	ServiceSnapshotSHA256         string                `json:"service_snapshot_sha256"`
	Failure                       *FailureV1            `json:"failure"`
	History                       []JournalTransitionV1 `json:"history"`
}

func validID(v string) bool            { return installID.MatchString(v) }
func validSHA(v string) bool           { return sha256Text.MatchString(v) }
func artifactPath(tx, n string) string { return filepath.Join(upgradeArtifactsRoot, tx, n) }
func safeAbsPath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.Contains(value, "\x00")
}
func (r ReleaseV1) valid() bool {
	return validID(r.ID) && r.Version != "" && validSHA(r.SourceCommit) && validID(r.Architecture) && validSHA(r.ManifestSHA256)
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
	if j.SchemaVersion != 1 || !validID(j.TransactionID) || j.Revision < 1 || !stateOK(j.State) || j.CreatedAt.IsZero() || j.UpdatedAt.IsZero() || !validSHA(j.RequestedManifestSHA256) || !validID(j.OldActivationID) || !validSHA(j.OldActivationJSONSHA256) || !validID(j.CandidateActivationID) || !validSHA(j.CandidateActivationJSONSHA256) || !j.CandidateDatabase.valid() || j.Snapshot.Path != artifactPath(j.TransactionID, "snapshot.sql.zst") || !validSHA(j.Snapshot.SHA256) || j.Snapshot.Size < 0 || !validID(j.Snapshot.SourceDatabase) || j.Validation.Path != artifactPath(j.TransactionID, "validation.json") || !validSHA(j.Validation.SHA256) || j.Validation.Size < 0 || !regexp.MustCompile(`^[0-9]{4}$`).MatchString(j.Migration.From) || !regexp.MustCompile(`^[0-9]{4}$`).MatchString(j.Migration.To) || !validSHA(j.Migration.ManifestSHA256) || !validSHA(j.ServiceSnapshotSHA256) {
		return fmt.Errorf("invalid upgrade journal v1")
	}
	if j.Failure != nil && (!validID(j.Failure.Code) || !stateOK(j.Failure.Phase) || !validSHA(j.Failure.MessageDigest)) {
		return fmt.Errorf("invalid journal failure")
	}
	for _, h := range j.History {
		if h.At.IsZero() || ValidateJournalTransition(h.From, h.To) != nil {
			return fmt.Errorf("invalid journal history")
		}
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
	return j, j.Validate()
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
