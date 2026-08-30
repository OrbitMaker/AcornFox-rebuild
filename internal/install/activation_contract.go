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

// RequestKind distinguishes ordinary release upgrades from database restores.
// It is persisted explicitly so a restore cannot be interpreted as a normal
// 0023 -> 0024 migration during recovery.
type RequestKind string

const (
	RequestKindUpgrade RequestKind = "upgrade"
	RequestKindRestore RequestKind = "restore"

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
	Target                 string `json:"target"`
	ServerEnvBeforeSHA256  string `json:"server_env_before_sha256"`
	ServerEnvAfterSHA256   string `json:"server_env_after_sha256"`
	ServerUnitBeforeSHA256 string `json:"server_unit_before_sha256"`
	ServerUnitAfterSHA256  string `json:"server_unit_after_sha256"`
	ServerUnitReleaseID    string `json:"server_unit_release_id"`
}
type ActivationV1 struct {
	SchemaVersion          int                        `json:"schema_version"`
	ActivationID           string                     `json:"activation_id"`
	Origin                 string                     `json:"origin"`
	Release                ReleaseV1                  `json:"release"`
	Database               DatabaseV1                 `json:"database"`
	DatabaseEnvSHA256      string                     `json:"database_env_sha256"`
	CreatedAt              time.Time                  `json:"created_at"`
	CreatedByTransactionID string                     `json:"created_by_transaction_id"`
	LegacyProjection       *LegacyProjectionV1        `json:"legacy_projection,omitempty"`
	RestoreSource          *ActivationRestoreSourceV1 `json:"restore_source,omitempty"`
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

// EdgeConfigTransitionV1 binds the non-secret Caddy configuration transition
// to one upgrade transaction. The prepared configuration path is deliberately
// not serialized or caller-provided; it is derived from TransactionID.
type EdgeConfigTransitionV1 struct {
	SchemaVersion           int    `json:"schema_version"`
	TransactionID           string `json:"transaction_id"`
	SourceReleaseID         string `json:"source_release_id"`
	CandidateReleaseID      string `json:"candidate_release_id"`
	ConsoleHostname         string `json:"console_hostname"`
	SourceTemplateSHA256    string `json:"source_template_sha256"`
	CandidateTemplateSHA256 string `json:"candidate_template_sha256"`
	InstalledBeforeSHA256   string `json:"installed_before_sha256"`
	InstalledAfterSHA256    string `json:"installed_after_sha256"`
	CandidateCaddySHA256    string `json:"candidate_caddy_sha256"`
}

// EdgeConfigValidationV1 records only stable digests from Caddy validation;
// command output and configuration bytes never enter the journal.
type EdgeConfigValidationV1 struct {
	ConfigSHA256   string `json:"config_sha256"`
	CaddySHA256    string `json:"caddy_sha256"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}
type UpgradeJournalV1 struct {
	SchemaVersion           int          `json:"schema_version"`
	TransactionID           string       `json:"transaction_id"`
	RequestKind             RequestKind  `json:"request_kind"`
	Revision                int64        `json:"revision"`
	State                   JournalState `json:"state"`
	CreatedAt               time.Time    `json:"created_at"`
	UpdatedAt               time.Time    `json:"updated_at"`
	RequestedManifestSHA256 string       `json:"requested_manifest_sha256"`
	// UpgradeControlDatabaseEnvSHA256 binds a mutable upgrade transaction to
	// the separately-authenticated control database environment without ever
	// serializing its bytes or DSN.
	UpgradeControlDatabaseEnvSHA256        string                  `json:"upgrade_control_database_env_sha256"`
	RestoreSource                          *RestoreSourceV1        `json:"restore_source,omitempty"`
	OldActivationID                        string                  `json:"old_activation_id"`
	OldActivationJSONSHA256                string                  `json:"old_activation_json_sha256"`
	PreUpgradePreviousActivationID         string                  `json:"pre_upgrade_previous_activation_id,omitempty"`
	PreUpgradePreviousActivationJSONSHA256 string                  `json:"pre_upgrade_previous_activation_json_sha256,omitempty"`
	PlannedOldActivation                   *ActivationV1           `json:"planned_old_activation,omitempty"`
	CandidateActivationID                  string                  `json:"candidate_activation_id"`
	CandidateActivationJSONSHA256          string                  `json:"candidate_activation_json_sha256,omitempty"`
	CandidateDatabaseName                  string                  `json:"candidate_database_name"`
	CandidateDatabase                      *DatabaseV1             `json:"candidate_database,omitempty"`
	Snapshot                               *ArtifactV1             `json:"snapshot,omitempty"`
	Migration                              *MigrationV1            `json:"migration,omitempty"`
	Validation                             *ArtifactV1             `json:"validation,omitempty"`
	EdgeConfigTransition                   *EdgeConfigTransitionV1 `json:"edge_config_transition,omitempty"`
	EdgeConfigValidation                   *EdgeConfigValidationV1 `json:"edge_config_validation,omitempty"`
	ServiceSnapshot                        ServiceSnapshotV1       `json:"service_snapshot"`
	Failure                                *FailureV1              `json:"failure,omitempty"`
	History                                []JournalTransitionV1   `json:"history"`
}

// CanonicalServiceSnapshotSHA256 returns the digest of the fixed service
// snapshot wire representation. ServiceSnapshotV1 deliberately uses a struct
// (rather than a map) so this representation has a stable field order.
func CanonicalServiceSnapshotSHA256(snapshot ServiceSnapshotV1) string {
	raw, _ := json.Marshal(snapshot)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func validID(v string) bool  { return installID.MatchString(v) }
func validSHA(v string) bool { return sha256Text.MatchString(v) }
func validRequestKind(v RequestKind) bool {
	return v == RequestKindUpgrade || v == RequestKindRestore
}
func artifactPath(tx, n string) string { return filepath.Join(upgradeArtifactsRoot, tx, n) }
func edgeConfigPreparedArtifactPath(tx string) string {
	return artifactPath(tx, "open-card-edge.Caddyfile")
}
func safeAbsPath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.Contains(value, "\x00")
}
func (r ReleaseV1) valid() bool {
	return validID(r.ID) && r.Version != "" && regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(r.SourceCommit) && validID(r.Architecture) && validSHA(r.ManifestSHA256)
}
func (d DatabaseV1) valid() bool {
	return validID(d.Name) && regexp.MustCompile(`^[0-9]{4}$`).MatchString(d.Migration) && validSHA(d.SchemaMigrationsSHA256)
}
func normalizedConsoleHostname(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") || strings.ContainsAny(value, " \t\r\n\x00/:@") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	return true
}
func (e EdgeConfigTransitionV1) valid() bool {
	return e.SchemaVersion == 1 && validID(e.TransactionID) && validID(e.SourceReleaseID) && validID(e.CandidateReleaseID) && e.SourceReleaseID != e.CandidateReleaseID && normalizedConsoleHostname(e.ConsoleHostname) && validSHA(e.SourceTemplateSHA256) && validSHA(e.CandidateTemplateSHA256) && validSHA(e.InstalledBeforeSHA256) && validSHA(e.InstalledAfterSHA256) && validSHA(e.CandidateCaddySHA256)
}
func (e EdgeConfigValidationV1) valid() bool {
	return validSHA(e.ConfigSHA256) && validSHA(e.CaddySHA256) && validSHA(e.EvidenceSHA256)
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

func validJournalMigration(kind RequestKind, migration *MigrationV1) bool {
	if migration == nil || !validSHA(migration.ManifestSHA256) {
		return false
	}
	switch kind {
	case RequestKindUpgrade:
		return migration.From == "0023" && migration.To == CurrentMigrationVersion
	case RequestKindRestore:
		// A restore uses the verified current schema rather than applying an
		// upgrade step. Keeping both values explicit prevents an incomplete
		// restore from being treated as a successful version transition.
		return migration.From == CurrentMigrationVersion && migration.To == CurrentMigrationVersion
	default:
		return false
	}
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
	if a.SchemaVersion != 1 || !validID(a.ActivationID) || !a.Release.valid() || !a.Database.valid() || !validSHA(a.DatabaseEnvSHA256) || a.CreatedAt.IsZero() || !validID(a.CreatedByTransactionID) {
		return fmt.Errorf("invalid activation v1")
	}
	if a.RestoreSource != nil {
		if a.Origin != "restore" || a.LegacyProjection != nil || a.RestoreSource.Validate() != nil {
			return fmt.Errorf("invalid restore activation")
		}
		return nil
	}
	if a.LegacyProjection == nil {
		if a.Origin != "native" {
			return fmt.Errorf("invalid native activation origin")
		}
		return nil
	}
	if a.Origin != "rc0_compat_projection" || !validRC0Release(a.Release) || a.Database.Migration != "0023" || !a.LegacyProjection.valid(a.Release) {
		return fmt.Errorf("invalid legacy projection")
	}
	return nil
}

// CanonicalActivationJSONSHA256 returns the digest of the activation's stable
// JSON representation. It is used as the journaled pointer identity.
func CanonicalActivationJSONSHA256(a ActivationV1) (string, error) {
	raw, err := MarshalActivationV1(a)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}
func (j UpgradeJournalV1) Validate() error {
	if j.SchemaVersion != 1 || !validID(j.TransactionID) || !validRequestKind(j.RequestKind) || j.History == nil || j.Revision != int64(len(j.History)+1) || !stateOK(j.State) || j.CreatedAt.IsZero() || j.UpdatedAt.Before(j.CreatedAt) || !validSHA(j.RequestedManifestSHA256) || !validSHA(j.UpgradeControlDatabaseEnvSHA256) || !validID(j.OldActivationID) || !validSHA(j.OldActivationJSONSHA256) || !validID(j.CandidateActivationID) || !candidateDatabaseName.MatchString(j.CandidateDatabaseName) {
		return fmt.Errorf("invalid upgrade journal v1")
	}
	if j.RequestKind == RequestKindRestore {
		if j.RestoreSource == nil || j.RestoreSource.Validate() != nil || j.PlannedOldActivation != nil {
			return fmt.Errorf("invalid restore journal source")
		}
	} else if j.RestoreSource != nil {
		return fmt.Errorf("unexpected upgrade restore source")
	}
	if (j.PreUpgradePreviousActivationID == "") != (j.PreUpgradePreviousActivationJSONSHA256 == "") || j.PreUpgradePreviousActivationID != "" && (!validID(j.PreUpgradePreviousActivationID) || !validSHA(j.PreUpgradePreviousActivationJSONSHA256)) {
		return fmt.Errorf("invalid pre-upgrade previous activation")
	}
	if j.PlannedOldActivation != nil {
		planned := *j.PlannedOldActivation
		if planned.Validate() != nil || planned.LegacyProjection == nil || planned.ActivationID != j.OldActivationID {
			return fmt.Errorf("invalid planned old activation")
		}
		digest, err := CanonicalActivationJSONSHA256(planned)
		if err != nil || digest != j.OldActivationJSONSHA256 {
			return fmt.Errorf("invalid planned old activation digest")
		}
	}
	if j.EdgeConfigTransition != nil {
		if !j.EdgeConfigTransition.valid() || j.EdgeConfigTransition.TransactionID != j.TransactionID {
			return fmt.Errorf("invalid edge configuration transition")
		}
		if j.PlannedOldActivation != nil && j.EdgeConfigTransition.SourceReleaseID != j.PlannedOldActivation.Release.ID {
			return fmt.Errorf("legacy edge configuration source release mismatch")
		}
	} else if j.PlannedOldActivation != nil {
		return fmt.Errorf("missing legacy edge configuration transition")
	}
	if j.RequestKind == RequestKindRestore {
		if j.State == JournalLegacyProjected {
			return fmt.Errorf("restore journal cannot project legacy activation")
		}
		for _, h := range j.History {
			if h.From == JournalLegacyProjected || h.To == JournalLegacyProjected {
				return fmt.Errorf("restore journal cannot project legacy activation")
			}
		}
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
	if rank >= 4 && (j.CandidateDatabase == nil || !j.CandidateDatabase.valid() || j.CandidateDatabase.Name != j.CandidateDatabaseName || j.CandidateDatabase.Migration != CurrentMigrationVersion || !validJournalMigration(j.RequestKind, j.Migration)) {
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
	if rank >= 5 && j.EdgeConfigTransition != nil {
		if j.EdgeConfigValidation == nil || !j.EdgeConfigValidation.valid() || j.EdgeConfigValidation.ConfigSHA256 != j.EdgeConfigTransition.InstalledAfterSHA256 || j.EdgeConfigValidation.CaddySHA256 != j.EdgeConfigTransition.CandidateCaddySHA256 {
			return fmt.Errorf("invalid progressive edge configuration validation")
		}
	} else if j.EdgeConfigValidation != nil {
		return fmt.Errorf("early edge configuration validation")
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
	required := []string{"schema_version", "transaction_id", "request_kind", "revision", "state", "created_at", "updated_at", "requested_manifest_sha256", "upgrade_control_database_env_sha256", "old_activation_id", "old_activation_json_sha256", "candidate_activation_id", "candidate_database_name", "service_snapshot", "history"}
	for _, name := range required {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("missing required journal field %q", name)
		}
	}
	if value, present := fields["planned_old_activation"]; present && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return fmt.Errorf("invalid planned old activation field")
	}
	if value, present := fields["restore_source"]; present && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return fmt.Errorf("invalid restore source field")
	}
	if j.RequestKind == RequestKindRestore {
		if value, present := fields["restore_source"]; !present || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("missing restore source field")
		}
	} else if _, present := fields["restore_source"]; present {
		return fmt.Errorf("unexpected upgrade restore source field")
	}
	for _, name := range []string{"edge_config_transition", "edge_config_validation"} {
		if value, present := fields[name]; present && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("invalid %s field", name)
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
		{"edge_config_validation", rank >= 5 && j.EdgeConfigTransition != nil},
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

func requireActivationFields(raw []byte, a ActivationV1) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if value, present := fields["restore_source"]; present && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return fmt.Errorf("invalid activation restore source field")
	}
	if a.Origin == "restore" {
		if value, present := fields["restore_source"]; !present || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("missing activation restore source field")
		}
	} else if _, present := fields["restore_source"]; present {
		return fmt.Errorf("unexpected activation restore source field")
	}
	return nil
}
func ParseActivationV1(raw []byte) (ActivationV1, error) {
	var a ActivationV1
	if e := decodeStrict(raw, &a); e != nil {
		return a, e
	}
	if e := a.Validate(); e != nil {
		return a, e
	}
	return a, requireActivationFields(raw, a)
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
