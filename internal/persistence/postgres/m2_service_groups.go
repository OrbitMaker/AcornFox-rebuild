package postgres

// M2 service-group persistence is additive to the M0/M1 repository.  A group
// and each normalized ServiceSpec are immutable facts.  The import report is
// stored beside them, while request idempotency is the only mutable state.

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const m2ServiceGroupIdempotencyScope = "m2.service_group"

var (
	// ErrServiceGroupPreviouslyFailed distinguishes a durable failed request
	// from a transient database error.  Callers must choose a new key after a
	// failed immutable import rather than guessing that it partially succeeded.
	ErrServiceGroupPreviouslyFailed = errors.New("service group request previously failed")
	ErrServiceGroupDigestMismatch   = errors.New("release digest set does not match service group")
)

// M2ServiceGroupIdentity is the immutable identity of one ServiceGroup
// definition revision.  The display name is intentionally absent from the
// key: an application may publish the same logical name at a later version,
// while a definition/version/digest tuple can never be rewritten.
type M2ServiceGroupIdentity struct {
	DefinitionID    domain.ID `json:"definition_id"`
	Version         int64     `json:"version"`
	ConfigDigest    string    `json:"config_digest"`
	CanonicalDigest string    `json:"canonical_digest"`
}

// M2ServiceGroupVolumeClaim is an immutable named-volume declaration.  The
// repository copies it to each release so restart and GC never infer data
// ownership from a mutable runtime container.
type M2ServiceGroupVolumeClaim struct {
	ID        domain.ID `json:"id"`
	Name      string    `json:"name"`
	SizeBytes int64     `json:"size_bytes"`
	Retain    bool      `json:"retain"`
}

// M2ReleaseRollout is persisted beside an immutable release.  Execution
// state remains on deployments; this row records the approved strategy and
// old-release reference needed for recovery and rollback.
type M2ReleaseRollout struct {
	Mode                    string    `json:"mode"`
	PreviousReleaseID       domain.ID `json:"previous_release_id,omitempty"`
	PreviousDeploymentID    domain.ID `json:"previous_deployment_id,omitempty"`
	PreserveOldUntilHealthy bool      `json:"preserve_old_until_healthy"`
	DowntimeApproved        bool      `json:"downtime_approved"`
}

// M2ImageProtectionReference is an explicit GC protection fact.  The digest
// must belong to the release provenance union; callers cannot pin an
// unrelated image by inserting a protection row.
type M2ImageProtectionReference struct {
	Repository     string     `json:"repository"`
	Digest         string     `json:"digest"`
	Reason         string     `json:"reason"`
	ProtectedUntil *time.Time `json:"protected_until,omitempty"`
}

// ServiceGroupCreateRequest is the typed persistence boundary for a controlled
// ServiceGroup import.  RequestDigest is optional; when omitted it is derived
// from the exact group/report payload.  A caller-supplied digest must match
// that derivation, so idempotency can never be keyed by an unverified digest.
type ServiceGroupCreateRequest struct {
	Group          domain.ServiceGroup
	ImportReport   domain.ComposeImportReport
	IdempotencyKey string
	RequestDigest  string
	// Identity is the preferred form. The scalar fields remain accepted as a
	// source-compatible adapter for callers that construct request literals.
	Identity        M2ServiceGroupIdentity
	DefinitionID    domain.ID
	Version         int64
	ConfigDigest    string
	CanonicalDigest string
	VolumeClaims    []M2ServiceGroupVolumeClaim
}

// ServiceGroupRecord is the read projection used by API adapters.  The
// normalized ServiceSpec rows are reconstructed into Group.Services; the raw
// Compose document is intentionally never returned or persisted here.
type ServiceGroupRecord struct {
	Group        domain.ServiceGroup         `json:"service_group"`
	ImportReport domain.ComposeImportReport  `json:"import_report"`
	Identity     M2ServiceGroupIdentity      `json:"identity"`
	VolumeClaims []M2ServiceGroupVolumeClaim `json:"volume_claims,omitempty"`
}

// M2ReleaseServiceBinding makes the source-to-digest provenance explicit.
// Built/static services bind to a successful immutable Artifact; prebuilt
// services bind to a resolved repository digest without fabricating a Build.
type M2ReleaseServiceBindingKind string

const (
	M2ReleaseBindingArtifact      M2ReleaseServiceBindingKind = "artifact"
	M2ReleaseBindingResolvedImage M2ReleaseServiceBindingKind = "resolved_image"
)

type M2ReleaseServiceBinding struct {
	ServiceName  string                      `json:"service_name"`
	Kind         M2ReleaseServiceBindingKind `json:"kind"`
	ArtifactID   domain.ID                   `json:"artifact_id,omitempty"`
	Image        domain.ImageDigest          `json:"image,omitempty"`
	ResolvedFrom string                      `json:"resolved_from,omitempty"`
}

// M2ReleaseCreation is the atomic input for releases containing a mix of
// built artifacts and resolved prebuilt images.  DefinitionID remains
// mandatory because releases retain the M1 delivery-definition provenance.
type M2ReleaseCreation struct {
	Release          domain.Release
	DefinitionID     domain.ID
	Bindings         []M2ReleaseServiceBinding
	CanonicalDigest  string
	RuntimeSpec      contracts.ServiceGroupRuntimeSpec
	Rollout          M2ReleaseRollout
	ImageProtections []M2ImageProtectionReference
}

type m2ServiceGroupRequestResponse struct {
	ServiceGroupID domain.ID `json:"service_group_id"`
	ImportReportID domain.ID `json:"import_report_id"`
}

func (i M2ServiceGroupIdentity) Validate() error {
	if err := domain.RequireID(i.DefinitionID, "service group definition id"); err != nil {
		return err
	}
	if i.Version < 1 {
		return domain.ValidationError("service group definition version must be positive")
	}
	if !validM2SHA256(i.ConfigDigest) || !validM2SHA256(i.CanonicalDigest) {
		return domain.ValidationError("service group config and canonical digests must be sha256")
	}
	return nil
}

func validM2SHA256(value string) bool {
	value = strings.TrimPrefix(strings.TrimSpace(value), "sha256:")
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func normalizeM2ServiceGroupRequest(request ServiceGroupCreateRequest) (ServiceGroupCreateRequest, error) {
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	if request.IdempotencyKey == "" {
		return ServiceGroupCreateRequest{}, domain.ValidationError("service group idempotency key is required")
	}
	identity := request.Identity
	for _, value := range []struct {
		name string
		set  bool
		old  any
		new  any
	}{
		{name: "definition id", set: !request.DefinitionID.Empty(), old: identity.DefinitionID, new: request.DefinitionID},
		{name: "version", set: request.Version != 0, old: identity.Version, new: request.Version},
		{name: "config digest", set: strings.TrimSpace(request.ConfigDigest) != "", old: identity.ConfigDigest, new: request.ConfigDigest},
		{name: "canonical digest", set: strings.TrimSpace(request.CanonicalDigest) != "", old: identity.CanonicalDigest, new: request.CanonicalDigest},
	} {
		if value.set && fmt.Sprint(value.old) != fmt.Sprint(value.new) && fmt.Sprint(value.old) != "" && fmt.Sprint(value.old) != "0" {
			return ServiceGroupCreateRequest{}, domain.ValidationError("service group identity fields conflict: " + value.name)
		}
	}
	if identity.DefinitionID.Empty() {
		identity.DefinitionID = request.DefinitionID
	}
	if identity.Version == 0 {
		identity.Version = request.Version
	}
	if strings.TrimSpace(identity.ConfigDigest) == "" {
		identity.ConfigDigest = strings.TrimSpace(request.ConfigDigest)
	}
	if strings.TrimSpace(identity.CanonicalDigest) == "" {
		identity.CanonicalDigest = strings.TrimSpace(request.CanonicalDigest)
	}
	group, report := cloneM2ServiceGroupInput(request.Group, request.ImportReport)
	if err := validateM2ServiceGroup(group, report, request.IdempotencyKey); err != nil {
		return ServiceGroupCreateRequest{}, err
	}
	claims := append([]M2ServiceGroupVolumeClaim(nil), request.VolumeClaims...)
	if err := validateM2VolumeClaims(claims); err != nil {
		return ServiceGroupCreateRequest{}, err
	}
	if strings.TrimSpace(identity.ConfigDigest) == "" {
		var err error
		identity.ConfigDigest, err = m2ServiceGroupDigest(group, report)
		if err != nil {
			return ServiceGroupCreateRequest{}, fmt.Errorf("derive service group config digest: %w", err)
		}
	}
	canonical, err := m2CanonicalServiceGroupDigest(identity, group, claims)
	if err != nil {
		return ServiceGroupCreateRequest{}, fmt.Errorf("derive service group canonical digest: %w", err)
	}
	if identity.CanonicalDigest == "" {
		identity.CanonicalDigest = canonical
	} else if identity.CanonicalDigest != canonical {
		return ServiceGroupCreateRequest{}, domain.ValidationError("service group canonical digest does not match normalized definition")
	}
	if err := identity.Validate(); err != nil {
		return ServiceGroupCreateRequest{}, err
	}
	request.Group, request.ImportReport = group, report
	request.Identity = identity
	request.DefinitionID = identity.DefinitionID
	request.Version = identity.Version
	request.ConfigDigest = identity.ConfigDigest
	request.CanonicalDigest = identity.CanonicalDigest
	request.VolumeClaims = claims
	return request, nil
}

func validateM2VolumeClaims(claims []M2ServiceGroupVolumeClaim) error {
	seenIDs := make(map[domain.ID]struct{}, len(claims))
	seenNames := make(map[string]struct{}, len(claims))
	for _, claim := range claims {
		if err := domain.RequireID(claim.ID, "service group volume claim id"); err != nil {
			return err
		}
		name := strings.TrimSpace(claim.Name)
		if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "..") || claim.SizeBytes <= 0 || !claim.Retain {
			return domain.ValidationError("service group volume claim must be retained and have a safe positive size")
		}
		if _, ok := seenIDs[claim.ID]; ok {
			return domain.ValidationError("service group volume claim ids must be unique")
		}
		if _, ok := seenNames[name]; ok {
			return domain.ValidationError("service group volume claim names must be unique")
		}
		seenIDs[claim.ID], seenNames[name] = struct{}{}, struct{}{}
	}
	return nil
}

func m2CanonicalServiceGroupDigest(identity M2ServiceGroupIdentity, group domain.ServiceGroup, claims []M2ServiceGroupVolumeClaim) (string, error) {
	services := append([]domain.ServiceSpec(nil), group.Services...)
	sort.SliceStable(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	claims = append([]M2ServiceGroupVolumeClaim(nil), claims...)
	sort.SliceStable(claims, func(i, j int) bool { return claims[i].Name < claims[j].Name })
	payload, err := json.Marshal(struct {
		ApplicationID domain.ID                   `json:"application_id"`
		Name          string                      `json:"name"`
		DefinitionID  domain.ID                   `json:"definition_id"`
		Version       int64                       `json:"version"`
		ConfigDigest  string                      `json:"config_digest"`
		Services      []domain.ServiceSpec        `json:"services"`
		VolumeClaims  []M2ServiceGroupVolumeClaim `json:"volume_claims,omitempty"`
	}{group.ApplicationID, group.Name, identity.DefinitionID, identity.Version, identity.ConfigDigest, services, claims})
	if err != nil {
		return "", err
	}
	return m1Digest(payload), nil
}

func m2ServiceGroupRequestDigest(identity M2ServiceGroupIdentity, group domain.ServiceGroup, report domain.ComposeImportReport, claims []M2ServiceGroupVolumeClaim) (string, error) {
	payload, err := json.Marshal(struct {
		Identity     M2ServiceGroupIdentity      `json:"identity"`
		Group        domain.ServiceGroup         `json:"service_group"`
		ImportReport domain.ComposeImportReport  `json:"import_report"`
		VolumeClaims []M2ServiceGroupVolumeClaim `json:"volume_claims,omitempty"`
	}{identity, group, report, claims})
	if err != nil {
		return "", err
	}
	return m1Digest(payload), nil
}

// CreateServiceGroup persists one immutable group, all of its specs, its
// import report, one audit fact and one transaction-outbox fact.  Retrying the
// same idempotency key returns the original group without writing duplicates.
func (s *Store) CreateServiceGroup(ctx context.Context, group domain.ServiceGroup, report domain.ComposeImportReport, idempotencyKey string) (domain.ServiceGroup, error) {
	return s.CreateServiceGroupWithDigest(ctx, group, report, idempotencyKey, "")
}

// CreateServiceGroupWithRequest is the request-struct form used by API and
// controller adapters that already carry a request digest.
func (s *Store) CreateServiceGroupWithRequest(ctx context.Context, request ServiceGroupCreateRequest) (domain.ServiceGroup, error) {
	normalized, err := normalizeM2ServiceGroupRequest(request)
	if err != nil {
		return domain.ServiceGroup{}, err
	}
	return s.persistServiceGroup(ctx, normalized)
}

// CreateServiceGroupRevision is the explicit M2 name for the immutable
// revision write.  CreateServiceGroupWithRequest remains as a compatibility
// alias for adapters already using that repository method.
func (s *Store) CreateServiceGroupRevision(ctx context.Context, request ServiceGroupCreateRequest) (domain.ServiceGroup, error) {
	return s.CreateServiceGroupWithRequest(ctx, request)
}

// PersistServiceGroup is an explicit repository-oriented alias for callers
// that prefer a verb distinct from the create API name.
func (s *Store) PersistServiceGroup(ctx context.Context, request ServiceGroupCreateRequest) (domain.ServiceGroup, error) {
	return s.CreateServiceGroupWithRequest(ctx, request)
}

// CreateServiceGroupWithDigest performs the durable transaction.  The digest
// argument is optional for compatibility with older controller callers.
func (s *Store) CreateServiceGroupWithDigest(ctx context.Context, group domain.ServiceGroup, report domain.ComposeImportReport, idempotencyKey, requestDigest string) (domain.ServiceGroup, error) {
	return s.CreateServiceGroupWithRequest(ctx, ServiceGroupCreateRequest{
		Group: group, ImportReport: report, IdempotencyKey: idempotencyKey, RequestDigest: requestDigest,
	})
}

func (s *Store) persistServiceGroup(ctx context.Context, request ServiceGroupCreateRequest) (domain.ServiceGroup, error) {
	if err := s.requireDB(); err != nil {
		return domain.ServiceGroup{}, err
	}
	group, report, identity := request.Group, request.ImportReport, request.Identity
	if err := validateM2ServiceGroup(group, report, request.IdempotencyKey); err != nil {
		return domain.ServiceGroup{}, err
	}
	group, report = cloneM2ServiceGroupInput(group, report)
	derivedDigest, err := m2ServiceGroupRequestDigest(identity, group, report, request.VolumeClaims)
	if err != nil {
		return domain.ServiceGroup{}, fmt.Errorf("derive service group request digest: %w", err)
	}
	requestDigest := strings.TrimSpace(request.RequestDigest)
	if requestDigest != "" && requestDigest != derivedDigest {
		return domain.ServiceGroup{}, domain.ValidationError("service group request digest does not match payload")
	}
	requestDigest = derivedDigest
	idempotencyKey := strings.TrimSpace(request.IdempotencyKey)
	if group.CreatedAt.IsZero() {
		group.CreatedAt = s.now().UTC()
	} else {
		group.CreatedAt = group.CreatedAt.UTC()
	}
	if err := domain.RequireID(group.ID, "service group id"); err != nil {
		return domain.ServiceGroup{}, err
	}
	if err := identity.Validate(); err != nil {
		return domain.ServiceGroup{}, err
	}
	if err := validateM2VolumeClaims(request.VolumeClaims); err != nil {
		return domain.ServiceGroup{}, err
	}
	reportID, err := domain.NewID("import")
	if err != nil {
		return domain.ServiceGroup{}, fmt.Errorf("generate service group import report id: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.ServiceGroup{}, fmt.Errorf("begin service group transaction: %w", err)
	}
	rollback := func(cause error) (domain.ServiceGroup, error) {
		return domain.ServiceGroup{}, rollbackTx(tx, cause)
	}

	reservation, err := tx.ExecContext(ctx, `
		INSERT INTO m2_service_group_requests
			(idempotency_key,request_digest,status,created_at,updated_at)
		VALUES ($1,$2,'in_progress',$3,$3)
		ON CONFLICT (idempotency_key) DO NOTHING
	`, idempotencyKey, requestDigest, group.CreatedAt)
	if err != nil {
		return rollback(fmt.Errorf("reserve service group idempotency: %w", err))
	}
	inserted, err := reservation.RowsAffected()
	if err != nil {
		return rollback(fmt.Errorf("inspect service group idempotency reservation: %w", err))
	}

	var storedDigest, status string
	var storedGroupID, storedReportID sql.NullString
	var storedResponse []byte
	var failure sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT request_digest,status,service_group_id,import_report_id,response,failure_reason
		  FROM m2_service_group_requests
		 WHERE idempotency_key=$1
		 FOR UPDATE
	`, idempotencyKey).Scan(&storedDigest, &status, &storedGroupID, &storedReportID, &storedResponse, &failure); err != nil {
		return rollback(fmt.Errorf("read service group idempotency record: %w", err))
	}
	if storedDigest != requestDigest {
		return rollback(ErrIdempotencyConflict)
	}
	if inserted == 0 {
		switch status {
		case "completed":
			if !storedGroupID.Valid || !storedReportID.Valid || len(storedResponse) == 0 || !json.Valid(storedResponse) {
				return rollback(fmt.Errorf("%w: invalid service group response", ErrIdempotencyCorrupt))
			}
			storedGroup := domain.ID(storedGroupID.String)
			if storedGroup != group.ID {
				return rollback(fmt.Errorf("%w: idempotent service group identity changed", ErrIdempotencyCorrupt))
			}
			persisted, err := loadServiceGroupTx(ctx, tx, storedGroup)
			if err != nil {
				return rollback(fmt.Errorf("replay service group: %w", err))
			}
			if err := tx.Commit(); err != nil {
				return domain.ServiceGroup{}, fmt.Errorf("%w: commit service group replay: %v", ErrOutcomeUnknown, err)
			}
			return persisted, nil
		case "in_progress":
			return rollback(ErrIdempotencyInProgress)
		case "failed":
			return rollback(fmt.Errorf("%w: %s", ErrServiceGroupPreviouslyFailed, failure.String))
		default:
			return rollback(fmt.Errorf("%w: unsupported service group request status %q", ErrIdempotencyCorrupt, status))
		}
	}
	if status != "in_progress" {
		return rollback(fmt.Errorf("%w: newly reserved request has status %q", ErrIdempotencyCorrupt, status))
	}

	encodedSpecs := make([]struct {
		name      string
		sortOrder int
		role      string
		source    string
		payload   []byte
	}, 0, len(group.Services))
	for index, service := range group.Services {
		payload, err := json.Marshal(service)
		if err != nil {
			return rollback(fmt.Errorf("encode service spec %q: %w", service.Name, err))
		}
		encodedSpecs = append(encodedSpecs, struct {
			name      string
			sortOrder int
			role      string
			source    string
			payload   []byte
		}{name: service.Name, sortOrder: index, role: string(service.Role), source: string(service.Source.Kind), payload: payload})
	}
	var definitionApplication string
	var definitionVersion int64
	if err := tx.QueryRowContext(ctx, `SELECT application_id,version FROM delivery_definitions WHERE id=$1`, identity.DefinitionID.String()).Scan(&definitionApplication, &definitionVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rollback(ErrNotFound)
		}
		return rollback(fmt.Errorf("load service group definition: %w", err))
	}
	if definitionApplication != group.ApplicationID.String() || definitionVersion != identity.Version {
		return rollback(domain.ValidationError("service group application or version does not match definition"))
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO service_groups(id,application_id,name,definition_id,version,config_digest,canonical_digest,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)
	`, group.ID.String(), group.ApplicationID.String(), group.Name, identity.DefinitionID.String(), identity.Version, identity.ConfigDigest, identity.CanonicalDigest, group.CreatedAt); err != nil {
		return rollback(fmt.Errorf("insert service group: %w", err))
	}
	for _, spec := range encodedSpecs {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO service_group_specs(service_group_id,service_name,sort_order,role,source_kind,spec,created_at)
			VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)
		`, group.ID.String(), spec.name, spec.sortOrder, spec.role, spec.source, spec.payload, group.CreatedAt); err != nil {
			return rollback(fmt.Errorf("insert service spec %q: %w", spec.name, err))
		}
	}
	for _, claim := range request.VolumeClaims {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO service_group_volume_claims(service_group_id,claim_id,name,size_bytes,retain,created_at)
			VALUES($1,$2,$3,$4,$5,$6)
		`, group.ID.String(), claim.ID.String(), claim.Name, claim.SizeBytes, claim.Retain, group.CreatedAt); err != nil {
			return rollback(fmt.Errorf("insert service group volume claim %q: %w", claim.Name, err))
		}
	}
	mappedFields, err := json.Marshal(report.MappedFields)
	if err != nil {
		return rollback(fmt.Errorf("encode service group mapped fields: %w", err))
	}
	if string(mappedFields) == "null" {
		mappedFields = []byte("[]")
	}
	warnings, err := json.Marshal(report.Warnings)
	if err != nil {
		return rollback(fmt.Errorf("encode service group warnings: %w", err))
	}
	if string(warnings) == "null" {
		warnings = []byte("[]")
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO service_group_import_reports(id,service_group_id,mapped_fields,warnings,created_at)
		VALUES($1,$2,$3::jsonb,$4::jsonb,$5)
	`, reportID.String(), group.ID.String(), mappedFields, warnings, group.CreatedAt); err != nil {
		return rollback(fmt.Errorf("insert service group import report: %w", err))
	}
	if err := s.appendM2ServiceGroupFactsTx(ctx, tx, group, report, group.CreatedAt); err != nil {
		return rollback(err)
	}
	response, err := json.Marshal(m2ServiceGroupRequestResponse{ServiceGroupID: group.ID, ImportReportID: reportID})
	if err != nil {
		return rollback(fmt.Errorf("encode service group idempotency response: %w", err))
	}
	if err := execExactlyOneTx(ctx, tx, `
		UPDATE m2_service_group_requests
		   SET status='completed',service_group_id=$3,import_report_id=$4,response=$5::jsonb,updated_at=$6
		 WHERE idempotency_key=$1 AND request_digest=$2 AND status='in_progress'
	`, idempotencyKey, requestDigest, group.ID.String(), reportID.String(), response, group.CreatedAt); err != nil {
		return rollback(fmt.Errorf("complete service group idempotency: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return domain.ServiceGroup{}, fmt.Errorf("%w: commit service group: %v", ErrOutcomeUnknown, err)
	}
	return group, nil
}

// CreateM2Release atomically persists a complete release and its provenance
// bindings.  It intentionally does not create an Artifact for a prebuilt
// image: the resolved-image union records the registry digest directly.
func (s *Store) CreateM2Release(ctx context.Context, creation M2ReleaseCreation, now time.Time) (domain.Release, error) {
	if err := s.requireDB(); err != nil {
		return domain.Release{}, err
	}
	if err := creation.validateBasic(); err != nil {
		return domain.Release{}, err
	}
	if now.IsZero() {
		now = s.now()
	}
	now = now.UTC()
	if creation.Release.CreatedAt.IsZero() {
		creation.Release.CreatedAt = now
	} else {
		creation.Release.CreatedAt = creation.Release.CreatedAt.UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Release{}, fmt.Errorf("begin M2 release transaction: %w", err)
	}
	rollback := func(cause error) (domain.Release, error) {
		return domain.Release{}, rollbackTx(tx, cause)
	}
	group, err := loadServiceGroupTx(ctx, tx, creation.Release.ServiceGroupID)
	if err != nil {
		return rollback(fmt.Errorf("load M2 release service group: %w", err))
	}
	identity, err := loadM2ServiceGroupIdentityTx(ctx, tx, creation.Release.ServiceGroupID)
	if err != nil {
		return rollback(fmt.Errorf("load M2 service group identity: %w", err))
	}
	if err := identity.Validate(); err != nil {
		return rollback(domain.ValidationError("M2 release requires a complete service group identity"))
	}
	if err := ValidateM2ReleaseServiceBindings(group, creation.Release, creation.Bindings); err != nil {
		return rollback(err)
	}
	var definitionApplication string
	var definitionVersion int64
	if err := tx.QueryRowContext(ctx, `SELECT application_id,version FROM delivery_definitions WHERE id=$1`, creation.DefinitionID.String()).Scan(&definitionApplication, &definitionVersion); err != nil {
		return rollback(fmt.Errorf("load M2 release definition: %w", err))
	}
	if err := creation.RuntimeSpec.ValidateRelease(creation.Release); err != nil {
		return rollback(fmt.Errorf("validate M2 release runtime specification: %w", err))
	}
	canonicalDigest, err := contracts.CanonicalServiceGroupReleaseDigest(creation.DefinitionID, identity.Version, creation.RuntimeSpec)
	if err != nil {
		return rollback(fmt.Errorf("derive M2 release canonical digest: %w", err))
	}
	if supplied := strings.TrimSpace(creation.CanonicalDigest); supplied != "" && supplied != canonicalDigest {
		return rollback(domain.ValidationError("M2 release canonical digest does not match complete runtime identity"))
	}
	if definitionApplication != creation.Release.ApplicationID.String() || group.ApplicationID != creation.Release.ApplicationID || creation.DefinitionID != identity.DefinitionID || definitionVersion != identity.Version || creation.Release.Version != int(identity.Version) || creation.Release.ConfigDigest != identity.ConfigDigest {
		return rollback(domain.ValidationError("M2 release application does not match definition or service group"))
	}
	creation.CanonicalDigest = canonicalDigest
	if creation.Rollout, err = normalizeM2RolloutPolicy(creation.Rollout); err != nil {
		return rollback(err)
	}
	scalarDigests := make(map[string]string, len(creation.Release.ServiceDigests()))
	for service, image := range creation.Release.ServiceDigests() {
		scalarDigests[service] = image.Digest
	}
	encodedDigests, err := json.Marshal(scalarDigests)
	if err != nil {
		return rollback(fmt.Errorf("encode M2 release digest set: %w", err))
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO releases(id,application_id,definition_id,version,service_digests,service_group_id,config_digest,canonical_digest,release_status,created_at)
		VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,'ready',$9)
	`, creation.Release.ID.String(), creation.Release.ApplicationID.String(), creation.DefinitionID.String(), creation.Release.Version, encodedDigests, creation.Release.ServiceGroupID.String(), creation.Release.ConfigDigest, canonicalDigest, creation.Release.CreatedAt); err != nil {
		return rollback(fmt.Errorf("insert M2 release: %w", err))
	}
	encodedRuntime, err := json.Marshal(creation.RuntimeSpec)
	if err != nil {
		return rollback(fmt.Errorf("encode M2 release runtime specification: %w", err))
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO m2_release_runtime_specs(release_id,schema_version,spec,canonical_digest,created_at) VALUES($1,$2,$3::jsonb,$4,$5)`, creation.Release.ID.String(), creation.RuntimeSpec.SchemaVersion, encodedRuntime, canonicalDigest, now); err != nil {
		return rollback(fmt.Errorf("persist M2 release runtime specification: %w", err))
	}
	bindings := append([]M2ReleaseServiceBinding(nil), creation.Bindings...)
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].ServiceName < bindings[j].ServiceName })
	for _, binding := range bindings {
		switch binding.Kind {
		case M2ReleaseBindingArtifact:
			var repository, digest, state, artifactApplication, artifactService string
			err := tx.QueryRowContext(ctx, `
				SELECT artifact.image_repository,artifact.image_digest,builds.state,source_revisions.application_id,build_plans.service_name
				  FROM artifacts artifact
				  JOIN builds ON builds.id=artifact.build_id
				  JOIN build_plans ON build_plans.id=builds.plan_id
				  JOIN source_revisions ON source_revisions.id=build_plans.source_revision_id
				 WHERE artifact.id=$1
			`, binding.ArtifactID.String()).Scan(&repository, &digest, &state, &artifactApplication, &artifactService)
			if errors.Is(err, sql.ErrNoRows) {
				return rollback(ErrNotFound)
			}
			if err != nil {
				return rollback(fmt.Errorf("load M2 release artifact %q: %w", binding.ArtifactID, err))
			}
			if state != string(domain.BuildSucceeded) {
				return rollback(fmt.Errorf("%w: service %q artifact build is %s", ErrBuildNotSuccessful, binding.ServiceName, state))
			}
			if artifactApplication != creation.Release.ApplicationID.String() {
				return rollback(domain.ValidationError("M2 release artifact belongs to another application"))
			}
			if artifactService != binding.ServiceName {
				return rollback(domain.ValidationError("M2 release artifact provenance belongs to another service"))
			}
			if digest != scalarDigests[binding.ServiceName] {
				return rollback(ErrServiceGroupDigestMismatch)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO release_artifacts(release_id,service_name,artifact_id) VALUES($1,$2,$3)`, creation.Release.ID.String(), binding.ServiceName, binding.ArtifactID.String()); err != nil {
				return rollback(fmt.Errorf("link M2 release artifact: %w", err))
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO m2_release_service_bindings(release_id,service_name,binding_kind,artifact_id,created_at) VALUES($1,$2,'artifact',$3,$4)`, creation.Release.ID.String(), binding.ServiceName, binding.ArtifactID.String(), now); err != nil {
				return rollback(fmt.Errorf("persist M2 artifact binding: %w", err))
			}
		case M2ReleaseBindingResolvedImage:
			resolvedTag := nullableString(binding.Image.ResolvedTag)
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO m2_release_service_bindings(release_id,service_name,binding_kind,image_repository,image_digest,resolved_tag,resolved_from,created_at)
				VALUES($1,$2,'resolved_image',$3,$4,$5,$6,$7)
			`, creation.Release.ID.String(), binding.ServiceName, binding.Image.Repository, binding.Image.Digest, resolvedTag, binding.ResolvedFrom, now); err != nil {
				return rollback(fmt.Errorf("persist M2 resolved image binding: %w", err))
			}
		default:
			return rollback(domain.ValidationError("M2 release binding kind is unsupported"))
		}
	}
	if err := s.persistM2ReleaseReferencesTx(ctx, tx, creation, group, now); err != nil {
		return rollback(err)
	}
	if err := s.appendM2ReleaseFactsTx(ctx, tx, creation, now); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return domain.Release{}, fmt.Errorf("%w: commit M2 release: %v", ErrOutcomeUnknown, err)
	}
	return creation.Release, nil
}

func (c M2ReleaseCreation) validateBasic() error {
	if err := c.Release.Validate(); err != nil {
		return err
	}
	if !c.Release.IsImmutable() || c.Release.Status != domain.ReleaseReady {
		return domain.ValidationError("M2 persists only immutable ready releases")
	}
	if err := domain.RequireID(c.DefinitionID, "release definition id"); err != nil {
		return err
	}
	return c.RuntimeSpec.ValidateRelease(c.Release)
}

func normalizeM2RolloutPolicy(policy M2ReleaseRollout) (M2ReleaseRollout, error) {
	if strings.TrimSpace(policy.Mode) == "" {
		policy.Mode = "initial"
	}
	switch policy.Mode {
	case "initial":
		if !policy.PreviousReleaseID.Empty() || !policy.PreviousDeploymentID.Empty() || policy.PreserveOldUntilHealthy || policy.DowntimeApproved {
			return M2ReleaseRollout{}, domain.ValidationError("initial M2 rollout cannot reference a previous deployment")
		}
	case "rolling":
		if policy.PreviousReleaseID.Empty() || policy.PreviousDeploymentID.Empty() || !policy.PreserveOldUntilHealthy || policy.DowntimeApproved {
			return M2ReleaseRollout{}, domain.ValidationError("rolling M2 rollout requires old-release preservation")
		}
	case "recreate":
		if policy.PreviousReleaseID.Empty() || policy.PreviousDeploymentID.Empty() || policy.PreserveOldUntilHealthy || !policy.DowntimeApproved {
			return M2ReleaseRollout{}, domain.ValidationError("recreate M2 rollout requires explicit downtime approval")
		}
	default:
		return M2ReleaseRollout{}, domain.ValidationError("M2 rollout mode is unsupported")
	}
	return policy, nil
}

func (s *Store) persistM2ReleaseReferencesTx(ctx context.Context, tx *sql.Tx, creation M2ReleaseCreation, group domain.ServiceGroup, now time.Time) error {
	claims, err := loadM2ServiceGroupClaimsTx(ctx, tx, group.ID)
	if err != nil {
		return fmt.Errorf("load M2 release volume claims: %w", err)
	}
	for _, claim := range claims {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO m2_release_volume_claims(release_id,claim_id,name,size_bytes,retain,created_at)
			VALUES($1,$2,$3,$4,$5,$6)
		`, creation.Release.ID.String(), claim.ID.String(), claim.Name, claim.SizeBytes, claim.Retain, now); err != nil {
			return fmt.Errorf("persist M2 release volume claim %q: %w", claim.Name, err)
		}
	}
	rollout, err := normalizeM2RolloutPolicy(creation.Rollout)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO m2_release_rollouts(release_id,mode,previous_release_id,previous_deployment_id,preserve_old_until_healthy,downtime_approved,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)
	`, creation.Release.ID.String(), rollout.Mode, nullableID(rollout.PreviousReleaseID), nullableID(rollout.PreviousDeploymentID), rollout.PreserveOldUntilHealthy, rollout.DowntimeApproved, now); err != nil {
		return fmt.Errorf("persist M2 release rollout: %w", err)
	}
	protections := append([]M2ImageProtectionReference(nil), creation.ImageProtections...)
	if len(protections) == 0 {
		for _, binding := range creation.Bindings {
			protection := M2ImageProtectionReference{Reason: "release:" + creation.Release.ID.String()}
			if binding.Kind == M2ReleaseBindingResolvedImage {
				protection.Repository, protection.Digest = binding.Image.Repository, binding.Image.Digest
			} else {
				if err := tx.QueryRowContext(ctx, `SELECT image_repository,image_digest FROM artifacts WHERE id=$1`, binding.ArtifactID.String()).Scan(&protection.Repository, &protection.Digest); err != nil {
					return fmt.Errorf("load M2 artifact protection %q: %w", binding.ServiceName, err)
				}
			}
			protections = append(protections, protection)
		}
	}
	seen := make(map[string]struct{}, len(protections))
	for _, protection := range protections {
		protection.Repository = strings.TrimSpace(protection.Repository)
		protection.Digest = strings.TrimSpace(protection.Digest)
		protection.Reason = strings.TrimSpace(protection.Reason)
		if protection.Repository == "" || !validM2SHA256(protection.Digest) || protection.Reason == "" {
			return domain.ValidationError("M2 image protection reference is invalid")
		}
		key := protection.Repository + "\x00" + protection.Digest
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO m2_release_image_protections(release_id,image_repository,image_digest,reason,protected_until,created_at)
			VALUES($1,$2,$3,$4,$5,$6)
		`, creation.Release.ID.String(), protection.Repository, protection.Digest, protection.Reason, protection.ProtectedUntil, now); err != nil {
			return fmt.Errorf("persist M2 image protection: %w", err)
		}
	}
	return nil
}

func nullableID(id domain.ID) any {
	if id.Empty() {
		return nil
	}
	return id.String()
}

// ValidateM2ReleaseServiceBindings validates the exact artifact/resolved-image
// union before SQL is reached.  The database trigger repeats this check at
// commit so concurrent or direct SQL writers cannot bypass it.
func ValidateM2ReleaseServiceBindings(group domain.ServiceGroup, release domain.Release, bindings []M2ReleaseServiceBinding) error {
	if err := ValidateReleaseDigestSet(group, release); err != nil {
		return err
	}
	if len(bindings) != len(group.Services) {
		return ErrServiceGroupDigestMismatch
	}
	services := make(map[string]domain.ServiceSpec, len(group.Services))
	for _, service := range group.Services {
		services[service.Name] = service
	}
	seen := make(map[string]struct{}, len(bindings))
	digests := release.ServiceDigests()
	for _, binding := range bindings {
		binding.ServiceName = strings.TrimSpace(binding.ServiceName)
		service, ok := services[binding.ServiceName]
		if !ok {
			return ErrServiceGroupDigestMismatch
		}
		if _, exists := seen[binding.ServiceName]; exists {
			return ErrServiceGroupDigestMismatch
		}
		seen[binding.ServiceName] = struct{}{}
		expectedDigest := digests[binding.ServiceName].Digest
		switch binding.Kind {
		case M2ReleaseBindingArtifact:
			if service.Source.Kind == domain.ServicePrebuilt || binding.ArtifactID.Empty() || binding.ResolvedFrom != "" || binding.Image.Repository != "" || binding.Image.Digest != "" {
				return ErrServiceGroupDigestMismatch
			}
		case M2ReleaseBindingResolvedImage:
			if service.Source.Kind != domain.ServicePrebuilt || binding.ArtifactID.String() != "" || strings.TrimSpace(binding.ResolvedFrom) == "" || binding.Image.Validate() != nil || binding.Image.Digest != expectedDigest {
				return ErrServiceGroupDigestMismatch
			}
		default:
			return domain.ValidationError("M2 release binding kind is unsupported")
		}
	}
	if len(seen) != len(services) {
		return ErrServiceGroupDigestMismatch
	}
	return nil
}

// GetServiceGroup reconstructs a normalized group in deterministic order and
// validates the persisted shape before returning it to an API adapter.
func (s *Store) GetServiceGroup(ctx context.Context, id domain.ID) (domain.ServiceGroup, error) {
	if err := s.requireDB(); err != nil {
		return domain.ServiceGroup{}, err
	}
	if err := domain.RequireID(id, "service group id"); err != nil {
		return domain.ServiceGroup{}, err
	}
	return loadServiceGroupQuery(ctx, s.db, id)
}

// GetServiceGroupRecord returns the group and its immutable import report.
func (s *Store) GetServiceGroupRecord(ctx context.Context, id domain.ID) (ServiceGroupRecord, error) {
	if err := s.requireDB(); err != nil {
		return ServiceGroupRecord{}, err
	}
	group, err := s.GetServiceGroup(ctx, id)
	if err != nil {
		return ServiceGroupRecord{}, err
	}
	report, err := s.GetServiceGroupImportReport(ctx, id)
	if err != nil {
		return ServiceGroupRecord{}, err
	}
	identity, err := s.GetServiceGroupIdentity(ctx, id)
	if err != nil {
		return ServiceGroupRecord{}, err
	}
	claims, err := s.ListServiceGroupVolumeClaims(ctx, id)
	if err != nil {
		return ServiceGroupRecord{}, err
	}
	return ServiceGroupRecord{Group: group, ImportReport: report, Identity: identity, VolumeClaims: claims}, nil
}

// GetServiceGroupIdentity reads the immutable definition revision metadata.
func (s *Store) GetServiceGroupIdentity(ctx context.Context, id domain.ID) (M2ServiceGroupIdentity, error) {
	if err := s.requireDB(); err != nil {
		return M2ServiceGroupIdentity{}, err
	}
	if err := domain.RequireID(id, "service group id"); err != nil {
		return M2ServiceGroupIdentity{}, err
	}
	var identity M2ServiceGroupIdentity
	var definitionID, configDigest, canonicalDigest sql.NullString
	var version sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT definition_id,version,config_digest,canonical_digest
		  FROM service_groups WHERE id=$1
	`, id.String()).Scan(&definitionID, &version, &configDigest, &canonicalDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return M2ServiceGroupIdentity{}, ErrNotFound
	}
	if err != nil {
		return M2ServiceGroupIdentity{}, fmt.Errorf("get service group identity: %w", err)
	}
	if !definitionID.Valid && !version.Valid && !configDigest.Valid && !canonicalDigest.Valid {
		// Rows created by the pre-M2 checkout remain readable. They cannot be
		// used to create a new M2 release because the SQL identity trigger and
		// CreateM2Release both require a complete revision identity.
		return M2ServiceGroupIdentity{}, nil
	}
	identity.DefinitionID = domain.ID(definitionID.String)
	identity.Version = version.Int64
	identity.ConfigDigest = configDigest.String
	identity.CanonicalDigest = canonicalDigest.String
	if err := identity.Validate(); err != nil {
		return M2ServiceGroupIdentity{}, fmt.Errorf("invalid persisted service group identity: %w", err)
	}
	return identity, nil
}

// ListServiceGroupVolumeClaims returns the immutable named-volume facts for a
// group in deterministic claim-name order.
func (s *Store) ListServiceGroupVolumeClaims(ctx context.Context, groupID domain.ID) ([]M2ServiceGroupVolumeClaim, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if err := domain.RequireID(groupID, "service group id"); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT claim_id,name,size_bytes,retain
		  FROM service_group_volume_claims
		 WHERE service_group_id=$1 ORDER BY name,claim_id
	`, groupID.String())
	if err != nil {
		return nil, fmt.Errorf("list service group volume claims: %w", err)
	}
	defer rows.Close()
	claims := make([]M2ServiceGroupVolumeClaim, 0)
	for rows.Next() {
		var claim M2ServiceGroupVolumeClaim
		if err := rows.Scan(&claim.ID, &claim.Name, &claim.SizeBytes, &claim.Retain); err != nil {
			return nil, fmt.Errorf("scan service group volume claim: %w", err)
		}
		claims = append(claims, claim)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate service group volume claims: %w", err)
	}
	if len(claims) == 0 {
		var exists bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM service_groups WHERE id=$1)`, groupID.String()).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check service group for volume claims: %w", err)
		}
		if !exists {
			return nil, ErrNotFound
		}
	}
	return claims, nil
}

// GetServiceSpec reads one immutable normalized specification.
func (s *Store) GetServiceSpec(ctx context.Context, groupID domain.ID, serviceName string) (domain.ServiceSpec, error) {
	if err := s.requireDB(); err != nil {
		return domain.ServiceSpec{}, err
	}
	if err := domain.RequireID(groupID, "service group id"); err != nil {
		return domain.ServiceSpec{}, err
	}
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		return domain.ServiceSpec{}, domain.ValidationError("service name is required")
	}
	return loadServiceSpecQuery(ctx, s.db.QueryRowContext(ctx, `
		SELECT spec FROM service_group_specs
		 WHERE service_group_id=$1 AND service_name=$2
	`, groupID.String(), serviceName))
}

// ListServiceSpecs returns immutable specs in the persisted deterministic
// order.  The returned slice is owned by the caller.
func (s *Store) ListServiceSpecs(ctx context.Context, groupID domain.ID) ([]domain.ServiceSpec, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if err := domain.RequireID(groupID, "service group id"); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT spec FROM service_group_specs
		 WHERE service_group_id=$1
		 ORDER BY sort_order,service_name
	`, groupID.String())
	if err != nil {
		return nil, fmt.Errorf("list service specs: %w", err)
	}
	defer rows.Close()
	items := make([]domain.ServiceSpec, 0)
	for rows.Next() {
		item, err := scanServiceSpec(rows)
		if err != nil {
			return nil, fmt.Errorf("scan service spec: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate service specs: %w", err)
	}
	if len(items) == 0 {
		var exists bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM service_groups WHERE id=$1)`, groupID.String()).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check service group: %w", err)
		}
		if !exists {
			return nil, ErrNotFound
		}
	}
	return items, nil
}

// GetServiceGroupImportReport reads the report linked to a group.
func (s *Store) GetServiceGroupImportReport(ctx context.Context, groupID domain.ID) (domain.ComposeImportReport, error) {
	if err := s.requireDB(); err != nil {
		return domain.ComposeImportReport{}, err
	}
	if err := domain.RequireID(groupID, "service group id"); err != nil {
		return domain.ComposeImportReport{}, err
	}
	var mapped, warnings []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT mapped_fields,warnings FROM service_group_import_reports WHERE service_group_id=$1
	`, groupID.String()).Scan(&mapped, &warnings)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ComposeImportReport{}, ErrNotFound
	}
	if err != nil {
		return domain.ComposeImportReport{}, fmt.Errorf("get service group import report: %w", err)
	}
	var report domain.ComposeImportReport
	if err := json.Unmarshal(mapped, &report.MappedFields); err != nil {
		return domain.ComposeImportReport{}, fmt.Errorf("%w: invalid mapped fields", ErrIdempotencyCorrupt)
	}
	if err := json.Unmarshal(warnings, &report.Warnings); err != nil {
		return domain.ComposeImportReport{}, fmt.Errorf("%w: invalid warnings", ErrIdempotencyCorrupt)
	}
	if err := validateM2ImportReport(report); err != nil {
		return domain.ComposeImportReport{}, fmt.Errorf("invalid persisted import report: %w", err)
	}
	return report, nil
}

// GetImportReport is a short compatibility alias for API adapters.
func (s *Store) GetImportReport(ctx context.Context, groupID domain.ID) (domain.ComposeImportReport, error) {
	return s.GetServiceGroupImportReport(ctx, groupID)
}

// ListServiceGroups lists immutable groups for one application.
func (s *Store) ListServiceGroups(ctx context.Context, applicationID domain.ID, limit int) ([]domain.ServiceGroup, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if err := domain.RequireID(applicationID, "application id"); err != nil {
		return nil, err
	}
	limit, err := normalizeLimit(limit)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id FROM service_groups
		 WHERE application_id=$1
		 ORDER BY created_at DESC,id DESC
		 LIMIT $2
	`, applicationID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("list service groups: %w", err)
	}
	defer rows.Close()
	ids := make([]domain.ID, 0)
	for rows.Next() {
		var id domain.ID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan service group id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate service groups: %w", err)
	}
	items := make([]domain.ServiceGroup, 0, len(ids))
	for _, id := range ids {
		item, err := s.GetServiceGroup(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("load service group %q: %w", id, err)
		}
		items = append(items, item)
	}
	return items, nil
}

// ValidateReleaseDigestSet verifies the complete M2 release invariant for a
// value already loaded by a caller.  Legacy M1 releases remain valid.
func ValidateReleaseDigestSet(group domain.ServiceGroup, release domain.Release) error {
	if err := group.Validate(); err != nil {
		return err
	}
	if err := release.Validate(); err != nil {
		return err
	}
	if release.ServiceGroupID.String() == "legacy" {
		return nil
	}
	if release.ServiceGroupID != group.ID {
		return ErrServiceGroupDigestMismatch
	}
	if release.ApplicationID != group.ApplicationID {
		return ErrServiceGroupDigestMismatch
	}
	digests := release.ServiceDigests()
	if len(digests) != len(group.Services) {
		return ErrServiceGroupDigestMismatch
	}
	for _, service := range group.Services {
		if _, ok := digests[service.Name]; !ok {
			return ErrServiceGroupDigestMismatch
		}
	}
	for service := range digests {
		found := false
		for _, expected := range group.Services {
			if expected.Name == service {
				found = true
				break
			}
		}
		if !found {
			return ErrServiceGroupDigestMismatch
		}
	}
	return nil
}

// ValidatePersistedReleaseDigestSet reads both immutable facts and applies
// the same check used by the SQL deferred constraint trigger.
func (s *Store) ValidatePersistedReleaseDigestSet(ctx context.Context, releaseID domain.ID) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	release, err := s.loadM2CompleteReleaseProjection(ctx, releaseID)
	if err != nil {
		return err
	}
	if release.ServiceGroupID.String() == "legacy" {
		return nil
	}
	group, err := s.GetServiceGroup(ctx, release.ServiceGroupID)
	if err != nil {
		return err
	}
	identity, err := s.GetServiceGroupIdentity(ctx, release.ServiceGroupID)
	if err != nil {
		return err
	}
	if err := identity.Validate(); err != nil {
		return domain.ValidationError("persisted M2 release references a legacy service group identity")
	}
	var definitionID, canonicalDigest string
	var version int
	if err := s.db.QueryRowContext(ctx, `SELECT definition_id,version,canonical_digest FROM releases WHERE id=$1`, releaseID.String()).Scan(&definitionID, &version, &canonicalDigest); err != nil {
		return fmt.Errorf("load persisted M2 release identity: %w", err)
	}
	if domain.ID(definitionID) != identity.DefinitionID || int64(version) != identity.Version || !validM2SHA256(canonicalDigest) || release.ConfigDigest != identity.ConfigDigest {
		return domain.ValidationError("persisted M2 release identity does not match service group")
	}
	return ValidateReleaseDigestSet(group, release)
}

// GetCompleteRelease is a read API with the M2 complete-set invariant
// enforced.  GetRelease remains unchanged for N-1/legacy compatibility.
func (s *Store) GetCompleteRelease(ctx context.Context, releaseID domain.ID) (domain.Release, error) {
	if err := s.requireDB(); err != nil {
		return domain.Release{}, err
	}
	release, err := s.loadM2CompleteReleaseProjection(ctx, releaseID)
	if err != nil {
		return domain.Release{}, err
	}
	if err := s.ValidatePersistedReleaseDigestSet(ctx, releaseID); err != nil {
		return domain.Release{}, err
	}
	return release, nil
}

// GetM2ReleaseServiceBindings returns the immutable provenance union used by a
// mixed release.  Legacy M1 releases have no M2 binding rows and return an
// empty slice after their release identity is confirmed.
func (s *Store) GetM2ReleaseServiceBindings(ctx context.Context, releaseID domain.ID) ([]M2ReleaseServiceBinding, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if err := domain.RequireID(releaseID, "release id"); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT binding.service_name,binding.binding_kind,COALESCE(binding.artifact_id,''),
		       COALESCE(artifact.image_repository,''),COALESCE(artifact.image_digest,''),
		       COALESCE(artifact.resolved_tag,''),COALESCE(binding.image_repository,''),
		       COALESCE(binding.image_digest,''),COALESCE(binding.resolved_tag,''),COALESCE(binding.resolved_from,'')
		  FROM m2_release_service_bindings binding
		  LEFT JOIN artifacts artifact ON artifact.id=binding.artifact_id
		 WHERE binding.release_id=$1
		 ORDER BY binding.service_name
	`, releaseID.String())
	if err != nil {
		return nil, fmt.Errorf("list M2 release service bindings: %w", err)
	}
	defer rows.Close()
	items := make([]M2ReleaseServiceBinding, 0)
	for rows.Next() {
		var item M2ReleaseServiceBinding
		var kind, artifactID, artifactRepository, artifactDigest, artifactTag string
		var imageRepository, imageDigest, imageTag, resolvedFrom string
		if err := rows.Scan(&item.ServiceName, &kind, &artifactID, &artifactRepository, &artifactDigest, &artifactTag, &imageRepository, &imageDigest, &imageTag, &resolvedFrom); err != nil {
			return nil, fmt.Errorf("scan M2 release service binding: %w", err)
		}
		item.Kind = M2ReleaseServiceBindingKind(kind)
		item.ArtifactID = domain.ID(artifactID)
		item.ResolvedFrom = resolvedFrom
		switch item.Kind {
		case M2ReleaseBindingArtifact:
			image, err := domain.ParseImageDigest(artifactRepository, artifactDigest)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid artifact binding image", ErrIdempotencyCorrupt)
			}
			image.ResolvedTag = artifactTag
			item.Image = image
		case M2ReleaseBindingResolvedImage:
			image, err := domain.ParseImageDigest(imageRepository, imageDigest)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid resolved image binding", ErrIdempotencyCorrupt)
			}
			image.ResolvedTag = imageTag
			item.Image = image
		default:
			return nil, fmt.Errorf("%w: unsupported M2 binding kind %q", ErrIdempotencyCorrupt, kind)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate M2 release service bindings: %w", err)
	}
	if len(items) == 0 {
		var exists bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM releases WHERE id=$1)`, releaseID.String()).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check M2 release: %w", err)
		}
		if !exists {
			return nil, ErrNotFound
		}
	}
	return items, nil
}

func (s *Store) ListM2ReleaseVolumeClaims(ctx context.Context, releaseID domain.ID) ([]M2ServiceGroupVolumeClaim, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if err := domain.RequireID(releaseID, "release id"); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT claim_id,name,size_bytes,retain
		  FROM m2_release_volume_claims
		 WHERE release_id=$1 ORDER BY name,claim_id
	`, releaseID.String())
	if err != nil {
		return nil, fmt.Errorf("list M2 release volume claims: %w", err)
	}
	defer rows.Close()
	claims := make([]M2ServiceGroupVolumeClaim, 0)
	for rows.Next() {
		var claim M2ServiceGroupVolumeClaim
		if err := rows.Scan(&claim.ID, &claim.Name, &claim.SizeBytes, &claim.Retain); err != nil {
			return nil, fmt.Errorf("scan M2 release volume claim: %w", err)
		}
		claims = append(claims, claim)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate M2 release volume claims: %w", err)
	}
	if len(claims) == 0 {
		var exists bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM releases WHERE id=$1)`, releaseID.String()).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check M2 release for volume claims: %w", err)
		}
		if !exists {
			return nil, ErrNotFound
		}
	}
	return claims, nil
}

func (s *Store) GetM2ReleaseRollout(ctx context.Context, releaseID domain.ID) (M2ReleaseRollout, error) {
	if err := s.requireDB(); err != nil {
		return M2ReleaseRollout{}, err
	}
	if err := domain.RequireID(releaseID, "release id"); err != nil {
		return M2ReleaseRollout{}, err
	}
	var rollout M2ReleaseRollout
	var previousRelease, previousDeployment sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT mode,previous_release_id,previous_deployment_id,preserve_old_until_healthy,downtime_approved
		  FROM m2_release_rollouts WHERE release_id=$1
	`, releaseID.String()).Scan(&rollout.Mode, &previousRelease, &previousDeployment, &rollout.PreserveOldUntilHealthy, &rollout.DowntimeApproved)
	if errors.Is(err, sql.ErrNoRows) {
		return M2ReleaseRollout{}, ErrNotFound
	}
	if err != nil {
		return M2ReleaseRollout{}, fmt.Errorf("get M2 release rollout: %w", err)
	}
	rollout.PreviousReleaseID, rollout.PreviousDeploymentID = domain.ID(previousRelease.String), domain.ID(previousDeployment.String)
	if _, err := normalizeM2RolloutPolicy(rollout); err != nil {
		return M2ReleaseRollout{}, fmt.Errorf("invalid persisted M2 rollout: %w", err)
	}
	return rollout, nil
}

func (s *Store) GetM2ReleaseRuntimeSpec(ctx context.Context, releaseID domain.ID) (contracts.ServiceGroupRuntimeSpec, string, error) {
	if err := domain.RequireID(releaseID, "M2 runtime release id"); err != nil {
		return contracts.ServiceGroupRuntimeSpec{}, "", err
	}
	var encoded []byte
	var canonical string
	if err := s.db.QueryRowContext(ctx, `SELECT spec,canonical_digest FROM m2_release_runtime_specs WHERE release_id=$1`, releaseID.String()).Scan(&encoded, &canonical); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return contracts.ServiceGroupRuntimeSpec{}, "", ErrNotFound
		}
		return contracts.ServiceGroupRuntimeSpec{}, "", err
	}
	var spec contracts.ServiceGroupRuntimeSpec
	if err := json.Unmarshal(encoded, &spec); err != nil {
		return contracts.ServiceGroupRuntimeSpec{}, "", fmt.Errorf("decode M2 release runtime specification: %w", err)
	}
	release, err := s.GetCompleteRelease(ctx, releaseID)
	if err != nil {
		return contracts.ServiceGroupRuntimeSpec{}, "", err
	}
	if err := spec.ValidateRelease(release); err != nil {
		return contracts.ServiceGroupRuntimeSpec{}, "", fmt.Errorf("validate persisted M2 runtime specification: %w", err)
	}
	identity, err := s.GetServiceGroupIdentity(ctx, release.ServiceGroupID)
	if err != nil {
		return contracts.ServiceGroupRuntimeSpec{}, "", err
	}
	derived, err := contracts.CanonicalServiceGroupReleaseDigest(identity.DefinitionID, identity.Version, spec)
	if err != nil || derived != canonical {
		return contracts.ServiceGroupRuntimeSpec{}, "", domain.ValidationError("persisted M2 runtime canonical digest mismatch")
	}
	return spec, canonical, nil
}

func (s *Store) GetDefaultEnvironmentID(ctx context.Context, applicationID domain.ID) (domain.ID, error) {
	if err := domain.RequireID(applicationID, "M2 application id"); err != nil {
		return "", err
	}
	var id string
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM environments WHERE application_id=$1 ORDER BY (name='production') DESC,created_at,id LIMIT 1`, applicationID.String()).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return domain.ID(id), nil
}

func (s *Store) GetDeploymentOperationID(ctx context.Context, deploymentID domain.ID) (domain.ID, error) {
	if err := domain.RequireID(deploymentID, "M2 deployment id"); err != nil {
		return "", err
	}
	var id string
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM operations WHERE deployment_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, deploymentID.String()).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return domain.ID(id), nil
}

func (s *Store) ListM2ReleaseImageProtections(ctx context.Context, releaseID domain.ID) ([]M2ImageProtectionReference, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if err := domain.RequireID(releaseID, "release id"); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT image_repository,image_digest,reason,protected_until
		  FROM m2_release_image_protections
		 WHERE release_id=$1 ORDER BY image_repository,image_digest
	`, releaseID.String())
	if err != nil {
		return nil, fmt.Errorf("list M2 release image protections: %w", err)
	}
	defer rows.Close()
	items := make([]M2ImageProtectionReference, 0)
	for rows.Next() {
		var item M2ImageProtectionReference
		var protectedUntil sql.NullTime
		if err := rows.Scan(&item.Repository, &item.Digest, &item.Reason, &protectedUntil); err != nil {
			return nil, fmt.Errorf("scan M2 image protection: %w", err)
		}
		if protectedUntil.Valid {
			value := protectedUntil.Time.UTC()
			item.ProtectedUntil = &value
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate M2 image protections: %w", err)
	}
	if len(items) == 0 {
		var exists bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM releases WHERE id=$1)`, releaseID.String()).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check M2 release for image protections: %w", err)
		}
		if !exists {
			return nil, ErrNotFound
		}
	}
	return items, nil
}

func (s *Store) loadM2CompleteReleaseProjection(ctx context.Context, releaseID domain.ID) (domain.Release, error) {
	if err := domain.RequireID(releaseID, "release id"); err != nil {
		return domain.Release{}, err
	}
	var serviceGroupID string
	if err := s.db.QueryRowContext(ctx, `SELECT service_group_id FROM releases WHERE id=$1`, releaseID.String()).Scan(&serviceGroupID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Release{}, ErrNotFound
		}
		return domain.Release{}, fmt.Errorf("load release service group: %w", err)
	}
	if serviceGroupID == "legacy" {
		return s.GetRelease(ctx, releaseID)
	}
	bindings, err := s.GetM2ReleaseServiceBindings(ctx, releaseID)
	if err != nil {
		return domain.Release{}, err
	}
	if len(bindings) == 0 {
		// An all-artifact M1 write can be associated with an M2 group during the
		// compatibility window; its old release reader remains authoritative.
		return s.GetRelease(ctx, releaseID)
	}
	var releaseIDValue, applicationID, configDigest, status string
	var version int
	var createdAt time.Time
	if err := s.db.QueryRowContext(ctx, `SELECT id,application_id,version,config_digest,release_status,created_at FROM releases WHERE id=$1`, releaseID.String()).Scan(&releaseIDValue, &applicationID, &version, &configDigest, &status, &createdAt); err != nil {
		return domain.Release{}, fmt.Errorf("load complete release: %w", err)
	}
	digests := make(map[string]domain.ImageDigest, len(bindings))
	for _, binding := range bindings {
		digests[binding.ServiceName] = binding.Image
	}
	payload, err := json.Marshal(struct {
		ID             domain.ID                     `json:"id"`
		ApplicationID  domain.ID                     `json:"application_id"`
		ServiceGroupID domain.ID                     `json:"service_group_id"`
		Version        int                           `json:"version"`
		ConfigDigest   string                        `json:"config_digest"`
		Status         domain.ReleaseStatus          `json:"status"`
		ServiceDigests map[string]domain.ImageDigest `json:"service_digests"`
		CreatedAt      time.Time                     `json:"created_at"`
		Immutable      bool                          `json:"immutable"`
	}{domain.ID(releaseIDValue), domain.ID(applicationID), domain.ID(serviceGroupID), version, configDigest, domain.ReleaseStatus(status), digests, createdAt.UTC(), true})
	if err != nil {
		return domain.Release{}, err
	}
	var release domain.Release
	if err := json.Unmarshal(payload, &release); err != nil {
		return domain.Release{}, fmt.Errorf("invalid complete M2 release: %w", err)
	}
	return release, nil
}

func validateM2ServiceGroup(group domain.ServiceGroup, report domain.ComposeImportReport, idempotencyKey string) error {
	if err := group.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(group.Name) == "" {
		return domain.ValidationError("service group name is required")
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return domain.ValidationError("service group idempotency key is required")
	}
	return validateM2ImportReport(report)
}

func validateM2ImportReport(report domain.ComposeImportReport) error {
	for _, field := range report.MappedFields {
		if strings.TrimSpace(field) == "" || strings.ContainsAny(field, "\x00\r\n") {
			return domain.ValidationError("import report mapped field is invalid")
		}
	}
	for _, warning := range report.Warnings {
		if strings.TrimSpace(warning) == "" || strings.ContainsAny(warning, "\x00\r\n") {
			return domain.ValidationError("import report warning is invalid")
		}
	}
	return nil
}

func cloneM2ServiceGroupInput(group domain.ServiceGroup, report domain.ComposeImportReport) (domain.ServiceGroup, domain.ComposeImportReport) {
	group.Services = append([]domain.ServiceSpec(nil), group.Services...)
	for index := range group.Services {
		group.Services[index].Dependencies = append([]domain.ServiceDependency(nil), group.Services[index].Dependencies...)
		group.Services[index].Entrypoint = append([]string(nil), group.Services[index].Entrypoint...)
		group.Services[index].Command = append([]string(nil), group.Services[index].Command...)
		group.Services[index].Networks = append([]string(nil), group.Services[index].Networks...)
		group.Services[index].Ports = append([]int(nil), group.Services[index].Ports...)
		group.Services[index].Volumes = append([]domain.VolumeMount(nil), group.Services[index].Volumes...)
		if group.Services[index].Environment != nil {
			group.Services[index].Environment = cloneStringMap(group.Services[index].Environment)
		}
	}
	report.MappedFields = append([]string(nil), report.MappedFields...)
	report.Warnings = append([]string(nil), report.Warnings...)
	return group, report
}

func cloneStringMap(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func m2ServiceGroupDigest(group domain.ServiceGroup, report domain.ComposeImportReport) (string, error) {
	payload, err := json.Marshal(struct {
		Group        domain.ServiceGroup        `json:"service_group"`
		ImportReport domain.ComposeImportReport `json:"import_report"`
	}{Group: group, ImportReport: report})
	if err != nil {
		return "", err
	}
	return m1Digest(payload), nil
}

func loadServiceGroupTx(ctx context.Context, tx *sql.Tx, id domain.ID) (domain.ServiceGroup, error) {
	return loadServiceGroupQuery(ctx, tx, id)
}

func loadM2ServiceGroupIdentityTx(ctx context.Context, tx *sql.Tx, id domain.ID) (M2ServiceGroupIdentity, error) {
	var identity M2ServiceGroupIdentity
	var definitionID, configDigest, canonicalDigest sql.NullString
	var version sql.NullInt64
	err := tx.QueryRowContext(ctx, `
		SELECT definition_id,version,config_digest,canonical_digest
		  FROM service_groups WHERE id=$1
	`, id.String()).Scan(&definitionID, &version, &configDigest, &canonicalDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return M2ServiceGroupIdentity{}, ErrNotFound
	}
	if err != nil {
		return M2ServiceGroupIdentity{}, err
	}
	identity.DefinitionID = domain.ID(definitionID.String)
	identity.Version = version.Int64
	identity.ConfigDigest = configDigest.String
	identity.CanonicalDigest = canonicalDigest.String
	return identity, nil
}

func loadM2ServiceGroupClaimsTx(ctx context.Context, tx *sql.Tx, id domain.ID) ([]M2ServiceGroupVolumeClaim, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT claim_id,name,size_bytes,retain
		  FROM service_group_volume_claims
		 WHERE service_group_id=$1 ORDER BY name,claim_id
	`, id.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	claims := make([]M2ServiceGroupVolumeClaim, 0)
	for rows.Next() {
		var claim M2ServiceGroupVolumeClaim
		if err := rows.Scan(&claim.ID, &claim.Name, &claim.SizeBytes, &claim.Retain); err != nil {
			return nil, err
		}
		claims = append(claims, claim)
	}
	return claims, rows.Err()
}

func loadServiceGroupQuery(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, id domain.ID) (domain.ServiceGroup, error) {
	var group domain.ServiceGroup
	var createdAt time.Time
	if err := queryer.QueryRowContext(ctx, `SELECT id,application_id,name,created_at FROM service_groups WHERE id=$1`, id.String()).Scan(&group.ID, &group.ApplicationID, &group.Name, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ServiceGroup{}, ErrNotFound
		}
		return domain.ServiceGroup{}, fmt.Errorf("get service group: %w", err)
	}
	rows, err := queryer.QueryContext(ctx, `
		SELECT spec FROM service_group_specs
		 WHERE service_group_id=$1
		 ORDER BY sort_order,service_name
	`, id.String())
	if err != nil {
		return domain.ServiceGroup{}, fmt.Errorf("list persisted service specs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		item, err := scanServiceSpec(rows)
		if err != nil {
			return domain.ServiceGroup{}, fmt.Errorf("decode persisted service spec: %w", err)
		}
		group.Services = append(group.Services, item)
	}
	if err := rows.Err(); err != nil {
		return domain.ServiceGroup{}, fmt.Errorf("iterate persisted service specs: %w", err)
	}
	group.CreatedAt = createdAt.UTC()
	if err := group.Validate(); err != nil {
		return domain.ServiceGroup{}, fmt.Errorf("invalid persisted service group: %w", err)
	}
	return group, nil
}

func loadServiceSpecQuery(ctx context.Context, row *sql.Row) (domain.ServiceSpec, error) {
	var payload []byte
	if err := row.Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ServiceSpec{}, ErrNotFound
		}
		return domain.ServiceSpec{}, fmt.Errorf("get service spec: %w", err)
	}
	return decodeM2ServiceSpec(payload)
}

func scanServiceSpec(scanner interface{ Scan(...any) error }) (domain.ServiceSpec, error) {
	var payload []byte
	if err := scanner.Scan(&payload); err != nil {
		return domain.ServiceSpec{}, err
	}
	return decodeM2ServiceSpec(payload)
}

func decodeM2ServiceSpec(payload []byte) (domain.ServiceSpec, error) {
	var spec domain.ServiceSpec
	if err := json.Unmarshal(payload, &spec); err != nil {
		return domain.ServiceSpec{}, fmt.Errorf("%w: service spec JSON is invalid", ErrIdempotencyCorrupt)
	}
	if err := spec.Validate(); err != nil {
		return domain.ServiceSpec{}, fmt.Errorf("%w: persisted service spec is invalid: %v", ErrIdempotencyCorrupt, err)
	}
	return spec, nil
}

// appendM2ServiceGroupFactsTx writes the audit digest and outbox event in the
// caller's transaction.  The audit input contains the exact immutable request
// for tamper evidence; the event body is a safe projection that omits mutable
// environment values and other service configuration details.
func (s *Store) appendM2ServiceGroupFactsTx(ctx context.Context, tx *sql.Tx, group domain.ServiceGroup, report domain.ComposeImportReport, now time.Time) error {
	auditPayload, err := json.Marshal(struct {
		Group        domain.ServiceGroup        `json:"service_group"`
		ImportReport domain.ComposeImportReport `json:"import_report"`
	}{Group: group, ImportReport: report})
	if err != nil {
		return fmt.Errorf("encode service group audit payload: %w", err)
	}
	if err := s.appendM1AuditTx(ctx, tx, "service_group.created", auditPayload, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "open-card-outbox:service_group:"+group.ID.String()); err != nil {
		return fmt.Errorf("serialize service group outbox sequence: %w", err)
	}
	var sequence int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM outbox_events WHERE aggregate_type='service_group' AND aggregate_id=$1`, group.ID.String()).Scan(&sequence); err != nil {
		return fmt.Errorf("allocate service group outbox sequence: %w", err)
	}
	stream, err := s.nextStreamSequence(ctx, tx)
	if err != nil {
		return err
	}
	serviceNames := make([]string, 0, len(group.Services))
	serviceRoles := make(map[string]string, len(group.Services))
	serviceSources := make(map[string]string, len(group.Services))
	for _, service := range group.Services {
		serviceNames = append(serviceNames, service.Name)
		serviceRoles[service.Name] = string(service.Role)
		serviceSources[service.Name] = string(service.Source.Kind)
	}
	sort.Strings(serviceNames)
	eventPayload, err := json.Marshal(map[string]any{
		"schema_version": "1.1",
		"aggregate_type": "service_group",
		"aggregate_id":   group.ID.String(),
		"event_type":     "service_group.created",
		"data": map[string]any{
			"service_group_id": group.ID.String(),
			"application_id":   group.ApplicationID.String(),
			"name":             group.Name,
			"service_names":    serviceNames,
			"service_roles":    serviceRoles,
			"service_sources":  serviceSources,
			"import_report":    report,
		},
	})
	if err != nil {
		return fmt.Errorf("encode service group outbox payload: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO outbox_events
			(id,aggregate_type,aggregate_id,aggregate_version,sequence,stream_sequence,event_type,payload,created_at,payload_version)
		VALUES($1,'service_group',$2,1,$3,$4,'service_group.created',$5::jsonb,$6,'1.1')
	`, "evt-"+formatSequence(uint64(stream)), group.ID.String(), sequence, stream, eventPayload, now.UTC()); err != nil {
		return fmt.Errorf("insert service group outbox event: %w", err)
	}
	return nil
}

func (s *Store) appendM2ReleaseFactsTx(ctx context.Context, tx *sql.Tx, creation M2ReleaseCreation, now time.Time) error {
	payload, err := json.Marshal(struct {
		Release  domain.Release            `json:"release"`
		Bindings []M2ReleaseServiceBinding `json:"bindings"`
	}{Release: creation.Release, Bindings: creation.Bindings})
	if err != nil {
		return fmt.Errorf("encode M2 release audit payload: %w", err)
	}
	if err := s.appendM1AuditTx(ctx, tx, "release.created", payload, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "open-card-outbox:release:"+creation.Release.ID.String()); err != nil {
		return fmt.Errorf("serialize M2 release outbox sequence: %w", err)
	}
	var sequence int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM outbox_events WHERE aggregate_type='release' AND aggregate_id=$1`, creation.Release.ID.String()).Scan(&sequence); err != nil {
		return fmt.Errorf("allocate M2 release outbox sequence: %w", err)
	}
	stream, err := s.nextStreamSequence(ctx, tx)
	if err != nil {
		return err
	}
	serviceNames := make([]string, 0, len(creation.Bindings))
	bindingKinds := make(map[string]string, len(creation.Bindings))
	for _, binding := range creation.Bindings {
		serviceNames = append(serviceNames, binding.ServiceName)
		bindingKinds[binding.ServiceName] = string(binding.Kind)
	}
	sort.Strings(serviceNames)
	eventPayload, err := json.Marshal(map[string]any{
		"schema_version": "1.1",
		"aggregate_type": "release",
		"aggregate_id":   creation.Release.ID.String(),
		"event_type":     "release.created",
		"data": map[string]any{
			"release_id":       creation.Release.ID.String(),
			"application_id":   creation.Release.ApplicationID.String(),
			"service_group_id": creation.Release.ServiceGroupID.String(),
			"service_names":    serviceNames,
			"binding_kinds":    bindingKinds,
			"config_digest":    creation.Release.ConfigDigest,
			"canonical_digest": strings.TrimSpace(creation.CanonicalDigest),
			"rollout_mode":     creation.Rollout.Mode,
		},
	})
	if err != nil {
		return fmt.Errorf("encode M2 release outbox payload: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO outbox_events
			(id,aggregate_type,aggregate_id,aggregate_version,sequence,stream_sequence,event_type,payload,created_at,payload_version)
		VALUES($1,'release',$2,1,$3,$4,'release.created',$5::jsonb,$6,'1.1')
	`, "evt-"+formatSequence(uint64(stream)), creation.Release.ID.String(), sequence, stream, eventPayload, now); err != nil {
		return fmt.Errorf("insert M2 release outbox event: %w", err)
	}
	return nil
}
