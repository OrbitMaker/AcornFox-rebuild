package install

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
)

const legacyCurrentTarget = "active/release"

// ActivationPointerIdentity is an activation pointer's non-secret identity.
// Its zero value denotes an absent pointer; only complete non-zero pairs are
// accepted otherwise.
type ActivationPointerIdentity struct {
	ID         string `json:"id"`
	JSONSHA256 string `json:"json_sha256"`
}

func (p ActivationPointerIdentity) Validate() error {
	if p.ID == "" && p.JSONSHA256 == "" {
		return nil
	}
	if !validID(p.ID) || !validSHA(p.JSONSHA256) {
		return fmt.Errorf("invalid activation pointer identity")
	}
	return nil
}

func (p ActivationPointerIdentity) equal(other ActivationPointerIdentity) bool {
	return p.ID == other.ID && p.JSONSHA256 == other.JSONSHA256
}

// UpgradePreflightRequest contains the immutable caller-supplied upgrade
// identity. Preflight itself must not mutate the host.
type UpgradePreflightRequest struct {
	TransactionID    string    `json:"transaction_id"`
	CandidateRelease ReleaseV1 `json:"candidate_release"`
}

func (r UpgradePreflightRequest) Validate() error {
	if !validID(r.TransactionID) || !r.CandidateRelease.valid() {
		return fmt.Errorf("invalid upgrade preflight request")
	}
	return nil
}

type ExistingActivationPreflight struct {
	Activation ActivationV1 `json:"activation"`
	JSONSHA256 string       `json:"json_sha256"`
	// DatabaseEnv is deliberately in-memory only.  A native activation is not
	// sufficient to open the upgrade database: the pinned slot environment
	// must agree with the activation digest before a session is created.
	DatabaseEnv []byte `json:"-"`
}

func (p ExistingActivationPreflight) Validate() error {
	if err := p.Activation.Validate(); err != nil || !validSHA(p.JSONSHA256) {
		return fmt.Errorf("invalid existing activation preflight")
	}
	digest, err := CanonicalActivationJSONSHA256(p.Activation)
	if err != nil || digest != p.JSONSHA256 {
		return fmt.Errorf("existing activation digest mismatch")
	}
	if _, err := ParseDatabaseEnv(p.DatabaseEnv); err != nil || databaseEnvSHA256(p.DatabaseEnv) != p.Activation.DatabaseEnvSHA256 {
		return fmt.Errorf("existing activation database environment mismatch")
	}
	return nil
}

// LegacyProjectionPlan carries the exact, non-secret facts used to project an
// RC0 installation into the activation layout. DatabaseEnv never crosses a
// serialization boundary.
type LegacyProjectionPlan struct {
	TransactionID string `json:"transaction_id"`
	ActivationID  string `json:"activation_id"`

	Release            ReleaseV1 `json:"release"`
	CurrentTarget      string    `json:"current_target"`
	ExpectedMigration  string    `json:"expected_migration"`
	ExpectedRowsSHA256 string    `json:"expected_rows_sha256"`

	DatabaseEnv       []byte `json:"-"`
	DatabaseEnvSHA256 string `json:"database_env_sha256"`

	ServerEnvBeforeSHA256  string `json:"server_env_before_sha256"`
	ServerEnvAfterSHA256   string `json:"server_env_after_sha256"`
	ServerUnitBeforeSHA256 string `json:"server_unit_before_sha256"`
	ServerUnitAfterSHA256  string `json:"server_unit_after_sha256"`
	ServerUnitReleaseID    string `json:"server_unit_release_id"`

	Previous ActivationPointerIdentity `json:"previous"`
}

func validRC0Release(release ReleaseV1) bool {
	return release.valid() && release.Version == ProductionNMinusOneVersion && release.SourceCommit == RC0SourceCommit && release.Architecture == "amd64" && release.ManifestSHA256 == RC0ReleaseManifestSHA256
}

func legacyReleaseTarget(release ReleaseV1) string {
	return filepath.Join("/opt/open-card/releases", release.ID)
}

func databaseEnvSHA256(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (p LegacyProjectionPlan) Validate() error {
	if !validID(p.TransactionID) || !validID(p.ActivationID) || !validRC0Release(p.Release) || p.CurrentTarget != legacyReleaseTarget(p.Release) || p.ExpectedMigration != "0023" || !validSHA(p.ExpectedRowsSHA256) || !validSHA(p.DatabaseEnvSHA256) || !validSHA(p.ServerEnvBeforeSHA256) || !validSHA(p.ServerEnvAfterSHA256) || !validSHA(p.ServerUnitBeforeSHA256) || !validSHA(p.ServerUnitAfterSHA256) || !validID(p.ServerUnitReleaseID) || p.Previous.Validate() != nil {
		return fmt.Errorf("invalid legacy projection plan")
	}
	if _, err := ParseDatabaseEnv(p.DatabaseEnv); err != nil || databaseEnvSHA256(p.DatabaseEnv) != p.DatabaseEnvSHA256 {
		return fmt.Errorf("invalid legacy projection database environment")
	}
	return nil
}

// ValidateForCandidate binds the unit replacement evidence to the exact
// candidate release supplied for this transaction.
func (p LegacyProjectionPlan) ValidateForCandidate(candidate ReleaseV1) error {
	if err := p.Validate(); err != nil || !candidate.valid() || p.ServerUnitReleaseID != candidate.ID {
		return fmt.Errorf("legacy projection candidate release mismatch")
	}
	return nil
}

// UpgradePreflight is the read-only result. Exactly one branch describes the
// host's current activation state.
type UpgradePreflight struct {
	Existing *ExistingActivationPreflight `json:"existing,omitempty"`
	Legacy   *LegacyProjectionPlan        `json:"legacy,omitempty"`
	Previous ActivationPointerIdentity    `json:"previous"`
}

func (p UpgradePreflight) Validate() error {
	if p.Previous.Validate() != nil || (p.Existing == nil) == (p.Legacy == nil) {
		return fmt.Errorf("invalid upgrade preflight")
	}
	if p.Existing != nil {
		return p.Existing.Validate()
	}
	if p.Legacy.Previous.equal(p.Previous) {
		return p.Legacy.Validate()
	}
	return fmt.Errorf("legacy preflight previous pointer mismatch")
}

// ValidateForRequest additionally binds a legacy plan's replacement unit to
// the candidate release named by the preflight request.
func (p UpgradePreflight) ValidateForRequest(request UpgradePreflightRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if p.Legacy != nil {
		return p.Legacy.ValidateForCandidate(request.CandidateRelease)
	}
	return nil
}

// ActiveDatabaseInspectionRequest keeps the DSN-derived environment in
// memory while binding inspection to the expected RC0 migration evidence.
type ActiveDatabaseInspectionRequest struct {
	DatabaseEnv        []byte `json:"-"`
	ExpectedMigration  string `json:"expected_migration"`
	ExpectedRowsSHA256 string `json:"expected_rows_sha256"`
	ExpectedRowCount   int    `json:"expected_row_count"`
}

func (r ActiveDatabaseInspectionRequest) Validate() error {
	if _, err := ParseDatabaseEnv(r.DatabaseEnv); err != nil || !validSHA(r.ExpectedRowsSHA256) || (r.ExpectedMigration != "0023" && r.ExpectedMigration != "0024") || r.ExpectedRowCount != 23 && r.ExpectedRowCount != 24 || r.ExpectedMigration != fmt.Sprintf("%04d", r.ExpectedRowCount) {
		return fmt.Errorf("invalid active database inspection request")
	}
	return nil
}

// LegacyProjectionObservation is the non-secret state required to verify a
// prepared or finalized compatibility projection.
type LegacyProjectionObservation struct {
	ActivationID         string                    `json:"activation_id"`
	ActivationJSONSHA256 string                    `json:"activation_json_sha256"`
	DatabaseEnvSHA256    string                    `json:"database_env_sha256"`
	Active               ActivationPointerIdentity `json:"active"`
	Previous             ActivationPointerIdentity `json:"previous"`
	CurrentTarget        string                    `json:"current_target"`
	ServerEnvSHA256      string                    `json:"server_env_sha256"`
	ServerUnitSHA256     string                    `json:"server_unit_sha256"`
}

func (o LegacyProjectionObservation) Validate() error {
	if !validID(o.ActivationID) || !validSHA(o.ActivationJSONSHA256) || !validSHA(o.DatabaseEnvSHA256) || o.Active.Validate() != nil || o.Active.ID != o.ActivationID || o.Active.JSONSHA256 != o.ActivationJSONSHA256 || o.Previous.Validate() != nil || o.CurrentTarget != legacyCurrentTarget || !validSHA(o.ServerEnvSHA256) || !validSHA(o.ServerUnitSHA256) {
		return fmt.Errorf("invalid legacy projection observation")
	}
	return nil
}

func (p LegacyProjectionV1) valid(release ReleaseV1) bool {
	return p.Target == legacyReleaseTarget(release) && validSHA(p.ServerEnvBeforeSHA256) && validSHA(p.ServerEnvAfterSHA256) && validSHA(p.ServerUnitBeforeSHA256) && validSHA(p.ServerUnitAfterSHA256) && validID(p.ServerUnitReleaseID)
}
