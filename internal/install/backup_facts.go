package install

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PlatformBackupFactCanonicalization identifies the only row serialization
// accepted by PlatformBackupV3 facts. It is deliberately a wire constant.
const PlatformBackupFactCanonicalization = "sha256(postgresql-16-to_jsonb-text-ndjson-v1)"

type TableDigest struct {
	Name       string   `json:"name"`
	RowCount   int64    `json:"row_count"`
	RowsSHA256 string   `json:"rows_sha256"`
	OrderBy    []string `json:"order_by"`
}

func (d TableDigest) valid(name string, order []string) bool {
	return d.Name == name && d.RowCount >= 0 && validSHA(d.RowsSHA256) && equalStrings(d.OrderBy, order)
}

type PlatformBackupRuntimeSettingV1 struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type PlatformBackupRuntimeConfigV1 struct {
	SchemaVersion int                              `json:"schema_version"`
	Server        []PlatformBackupRuntimeSettingV1 `json:"server"`
	Agent         []PlatformBackupRuntimeSettingV1 `json:"agent"`
}

var platformBackupServerRuntimeKeys = []string{
	"OPEN_CARD_AGENT_DISPATCH_INSTANCE_ID", "OPEN_CARD_AGENT_DISPATCH_NODE_ID", "OPEN_CARD_AGENT_GATEWAY_ADDR", "OPEN_CARD_AGENT_IDENTITIES_JSON", "OPEN_CARD_AUTH_ORIGIN", "OPEN_CARD_BUILDKIT_ADDRESS", "OPEN_CARD_BUILDKIT_COMMAND", "OPEN_CARD_BUILDKIT_WORKER", "OPEN_CARD_BUILD_WORK_ROOT", "OPEN_CARD_CADDY_ADMIN_URL", "OPEN_CARD_CADDY_LISTEN", "OPEN_CARD_LOG_MAX_FILE_BYTES", "OPEN_CARD_LOG_MAX_TOTAL_BYTES", "OPEN_CARD_LOG_ROOT", "OPEN_CARD_M1_ENABLED", "OPEN_CARD_M2_ENABLED", "OPEN_CARD_M2_REGISTRY_BASE_URL", "OPEN_CARD_M3_COMPOSITION", "OPEN_CARD_M3_ENABLED", "OPEN_CARD_M4_ENABLED", "OPEN_CARD_M4_LOG_COLLECTION_INTERVAL", "OPEN_CARD_M4_ROLLOUT_ENABLED", "OPEN_CARD_M4_ROLLOUT_INTERVAL", "OPEN_CARD_M5_ENABLED", "OPEN_CARD_M5_STORAGE_CAPACITY_BYTES", "OPEN_CARD_M5_STORAGE_HARD_RESERVE_BYTES", "OPEN_CARD_M6_ENABLED", "OPEN_CARD_M6_WORKSPACE_ROOT", "OPEN_CARD_OCI_STORE_ROOT", "OPEN_CARD_RUNTIME_TASK_PREFIX", "OPEN_CARD_SERVER_ADDR", "OPEN_CARD_SOURCE_GIT_RESOLVERS", "OPEN_CARD_SOURCE_UPLOAD_ROOT", "OPEN_CARD_SOURCE_WORKSPACE_ROOT", "OPEN_CARD_STATIC_RUNTIME_DIGEST", "OPEN_CARD_STATIC_SERVER_BINARY",
}
var platformBackupAgentRuntimeKeys = []string{
	"OPEN_CARD_AGENT_VERSION", "OPEN_CARD_CONTROL_PLANE_SERVER_NAME", "OPEN_CARD_CONTROL_PLANE_URL", "OPEN_CARD_INSTANCE_ID", "OPEN_CARD_M2_ENABLED", "OPEN_CARD_M4_ENABLED", "OPEN_CARD_NODE_ID", "OPEN_CARD_OCI_STORE_ROOT", "OPEN_CARD_RUNTIME_ENABLED", "OPEN_CARD_RUNTIME_GROUP_NETWORK", "OPEN_CARD_RUNTIME_NETWORK", "OPEN_CARD_RUNTIME_RESERVE_MEMORY_BYTES", "OPEN_CARD_RUNTIME_TASK_PREFIX", "OPEN_CARD_RUNTIME_WORK_ROOT", "OPEN_CARD_WORKER_NETWORK_ISOLATED",
}
var platformBackupForbiddenGitPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("2620:4f:8000::/48"), netip.MustParsePrefix("3fff::/20"), netip.MustParsePrefix("5f00::/16"),
}

func (c PlatformBackupRuntimeConfigV1) Validate() error {
	if c.SchemaVersion != 1 || !runtimeSettingsValid(c.Server, platformBackupServerRuntimeKeys, true) || !runtimeSettingsValid(c.Agent, platformBackupAgentRuntimeKeys, false) {
		return ErrPlatformBackupPackage
	}
	server, agent := runtimeSettingsMap(c.Server), runtimeSettingsMap(c.Agent)
	for _, key := range []string{"OPEN_CARD_AGENT_DISPATCH_INSTANCE_ID", "OPEN_CARD_AGENT_DISPATCH_NODE_ID", "OPEN_CARD_M2_ENABLED", "OPEN_CARD_M4_ENABLED", "OPEN_CARD_RUNTIME_TASK_PREFIX"} {
		if _, ok := server[key]; !ok {
			return ErrPlatformBackupPackage
		}
	}
	for _, key := range []string{"OPEN_CARD_INSTANCE_ID", "OPEN_CARD_NODE_ID", "OPEN_CARD_M2_ENABLED", "OPEN_CARD_M4_ENABLED", "OPEN_CARD_RUNTIME_TASK_PREFIX"} {
		if _, ok := agent[key]; !ok {
			return ErrPlatformBackupPackage
		}
	}
	if server["OPEN_CARD_AGENT_DISPATCH_INSTANCE_ID"] != agent["OPEN_CARD_INSTANCE_ID"] || server["OPEN_CARD_AGENT_DISPATCH_NODE_ID"] != agent["OPEN_CARD_NODE_ID"] || server["OPEN_CARD_M2_ENABLED"] != agent["OPEN_CARD_M2_ENABLED"] || server["OPEN_CARD_M4_ENABLED"] != agent["OPEN_CARD_M4_ENABLED"] || server["OPEN_CARD_RUNTIME_TASK_PREFIX"] != agent["OPEN_CARD_RUNTIME_TASK_PREFIX"] {
		return ErrPlatformBackupPackage
	}
	if !runtimeFeatureHierarchy(server) {
		return ErrPlatformBackupPackage
	}
	return nil
}
func MarshalPlatformBackupRuntimeConfigV1(v PlatformBackupRuntimeConfigV1) ([]byte, error) {
	return marshalBackupFact(v, v.Validate())
}
func ParsePlatformBackupRuntimeConfigV1(raw []byte) (PlatformBackupRuntimeConfigV1, error) {
	var v PlatformBackupRuntimeConfigV1
	if err := parseBackupFact(raw, &v, []string{"schema_version", "server", "agent"}, func() error { return v.Validate() }); err != nil {
		return PlatformBackupRuntimeConfigV1{}, ErrPlatformBackupPackage
	}
	return v, nil
}

type PlatformBackupRoutesV1 struct {
	SchemaVersion          int           `json:"schema_version"`
	DatabaseSnapshotSHA256 string        `json:"database_snapshot_sha256"`
	Canonicalization       string        `json:"canonicalization"`
	Tables                 []TableDigest `json:"tables"`
}

var platformBackupRouteTables = []struct {
	name  string
	order []string
}{
	{"dns_change_owned_records", []string{"owner_key"}}, {"dns_change_plans", []string{"id"}}, {"dns_change_reconcile_state", []string{"scope"}}, {"m3_application_domains", []string{"id"}}, {"m3_certificate_references", []string{"id"}}, {"m3_desired_routes", []string{"id"}}, {"m3_domain_convergence_requests", []string{"id"}}, {"m3_platform_domains", []string{"id"}}, {"m3_port_leases", []string{"id"}}, {"m3_route_pointers", []string{"route_id"}}, {"m3_traffic_switches", []string{"id"}}, {"m4_rollout_coordinations", []string{"operation_id"}}, {"m4_rollout_phase_events", []string{"operation_id", "sequence"}}, {"m4_rollout_route_set_entries", []string{"rollout_operation_id", "route_id"}}, {"m4_rollout_route_sets", []string{"rollout_operation_id"}},
}

func (v PlatformBackupRoutesV1) Validate() error {
	if v.SchemaVersion != 1 || !validSHA(v.DatabaseSnapshotSHA256) || v.Canonicalization != PlatformBackupFactCanonicalization || len(v.Tables) != len(platformBackupRouteTables) {
		return ErrPlatformBackupPackage
	}
	for i, expected := range platformBackupRouteTables {
		if !v.Tables[i].valid(expected.name, expected.order) {
			return ErrPlatformBackupPackage
		}
	}
	return nil
}
func MarshalPlatformBackupRoutesV1(v PlatformBackupRoutesV1) ([]byte, error) {
	return marshalBackupFact(v, v.Validate())
}
func ParsePlatformBackupRoutesV1(raw []byte) (PlatformBackupRoutesV1, error) {
	var v PlatformBackupRoutesV1
	if err := parseBackupFact(raw, &v, []string{"schema_version", "database_snapshot_sha256", "canonicalization", "tables"}, func() error { return v.Validate() }); err != nil {
		return PlatformBackupRoutesV1{}, ErrPlatformBackupPackage
	}
	return v, nil
}

type PlatformBackupSequenceV1 struct {
	Relation  string `json:"relation"`
	LastValue int64  `json:"last_value"`
	IsCalled  bool   `json:"is_called"`
}
type PlatformBackupAuditV1 struct {
	SchemaVersion          int                      `json:"schema_version"`
	DatabaseSnapshotSHA256 string                   `json:"database_snapshot_sha256"`
	Canonicalization       string                   `json:"canonicalization"`
	Table                  TableDigest              `json:"table"`
	Sequence               PlatformBackupSequenceV1 `json:"sequence"`
	FirstSequence          *int64                   `json:"first_sequence"`
	LastSequence           *int64                   `json:"last_sequence"`
	ChainHead              *string                  `json:"chain_head"`
	LinkContinuity         bool                     `json:"link_continuity"`
}

func (v PlatformBackupAuditV1) Validate() error {
	// LinkContinuity and ChainHead are producer assertions over the canonical
	// rows digest, not standalone proof. B3 must recompute them post-restore.
	if v.SchemaVersion != 1 || !validSHA(v.DatabaseSnapshotSHA256) || v.Canonicalization != PlatformBackupFactCanonicalization || !v.Table.valid("audit_evidence", []string{"sequence"}) || v.Sequence.Relation != "public.audit_evidence_sequence_seq" || v.Sequence.LastValue < 0 || !v.LinkContinuity || v.Sequence.LastValue == 0 && v.Sequence.IsCalled {
		return ErrPlatformBackupPackage
	}
	if v.Table.RowCount == 0 {
		if v.FirstSequence != nil || v.LastSequence != nil || v.ChainHead != nil {
			return ErrPlatformBackupPackage
		}
		return nil
	}
	if v.FirstSequence == nil || v.LastSequence == nil || v.ChainHead == nil || !v.Sequence.IsCalled || *v.FirstSequence <= 0 || *v.LastSequence < *v.FirstSequence || v.Sequence.LastValue < *v.LastSequence || !strings.HasPrefix(*v.ChainHead, "sha256:") || !validSHA(strings.TrimPrefix(*v.ChainHead, "sha256:")) {
		return ErrPlatformBackupPackage
	}
	return nil
}
func MarshalPlatformBackupAuditV1(v PlatformBackupAuditV1) ([]byte, error) {
	return marshalBackupFact(v, v.Validate())
}
func ParsePlatformBackupAuditV1(raw []byte) (PlatformBackupAuditV1, error) {
	var v PlatformBackupAuditV1
	if err := parseBackupFactNullable(raw, &v, []string{"schema_version", "database_snapshot_sha256", "canonicalization", "table", "sequence", "first_sequence", "last_sequence", "chain_head", "link_continuity"}, func() error { return v.Validate() }); err != nil {
		return PlatformBackupAuditV1{}, ErrPlatformBackupPackage
	}
	return v, nil
}

type PlatformBackupReleaseActivationV1 struct {
	ActivationID           string    `json:"activation_id"`
	ActivationJSONSHA256   string    `json:"activation_json_sha256"`
	Origin                 string    `json:"origin"`
	CreatedAt              time.Time `json:"created_at"`
	CreatedByTransactionID string    `json:"created_by_transaction_id"`
	DatabaseEnvSHA256      string    `json:"database_env_sha256"`
}
type PlatformBackupReleaseDatabaseV1 struct {
	DatabaseV1
	CurrentDatabase            string `json:"current_database"`
	SchemaMigrationsCount      int64  `json:"schema_migrations_count"`
	SchemaMigrationsRowsSHA256 string `json:"schema_migrations_rows_sha256"`
}
type PlatformBackupReleasePointersV1 struct {
	ActiveTarget            string  `json:"active_target"`
	CurrentTarget           string  `json:"current_target"`
	ActivationReleaseTarget string  `json:"activation_release_target"`
	PreviousActiveTarget    *string `json:"previous_active_target,omitempty"`
}
type PlatformBackupReleaseV1 struct {
	SchemaVersion          int                               `json:"schema_version"`
	DatabaseSnapshotSHA256 string                            `json:"database_snapshot_sha256"`
	Activation             PlatformBackupReleaseActivationV1 `json:"activation"`
	Release                ReleaseV1                         `json:"release"`
	Database               PlatformBackupReleaseDatabaseV1   `json:"database"`
	Pointers               PlatformBackupReleasePointersV1   `json:"pointers"`
}

func (v PlatformBackupReleaseV1) Validate() error {
	a, d, p := v.Activation, v.Database, v.Pointers
	if v.SchemaVersion != 1 || !validSHA(v.DatabaseSnapshotSHA256) || !validID(a.ActivationID) || !validSHA(a.ActivationJSONSHA256) || !validID(a.Origin) || a.CreatedAt.IsZero() || a.CreatedAt.Location() != time.UTC || !validID(a.CreatedByTransactionID) || !validSHA(a.DatabaseEnvSHA256) || !v.Release.valid() || !d.DatabaseV1.valid() || d.CurrentDatabase != d.Name || d.SchemaMigrationsCount < 0 || !validSHA(d.SchemaMigrationsRowsSHA256) || d.SchemaMigrationsRowsSHA256 != d.SchemaMigrationsSHA256 || p.ActiveTarget != "activations/"+a.ActivationID || p.CurrentTarget != "active/release" || p.ActivationReleaseTarget != "../../releases/"+v.Release.ID {
		return ErrPlatformBackupPackage
	}
	if p.PreviousActiveTarget != nil && (!strings.HasPrefix(*p.PreviousActiveTarget, "activations/") || !validID(strings.TrimPrefix(*p.PreviousActiveTarget, "activations/")) || strings.TrimPrefix(*p.PreviousActiveTarget, "activations/") == a.ActivationID) {
		return ErrPlatformBackupPackage
	}
	return nil
}
func MarshalPlatformBackupReleaseV1(v PlatformBackupReleaseV1) ([]byte, error) {
	return marshalBackupFact(v, v.Validate())
}
func ParsePlatformBackupReleaseV1(raw []byte) (PlatformBackupReleaseV1, error) {
	var v PlatformBackupReleaseV1
	if err := parseBackupFact(raw, &v, []string{"schema_version", "database_snapshot_sha256", "activation", "release", "database", "pointers"}, func() error { return v.Validate() }); err != nil {
		return PlatformBackupReleaseV1{}, ErrPlatformBackupPackage
	}
	return v, nil
}

type PlatformBackupRowsDigestV1 struct {
	RowCount   int64    `json:"row_count"`
	RowsSHA256 string   `json:"rows_sha256"`
	OrderBy    []string `json:"order_by"`
}
type PlatformBackupPendingOutboxV1 struct {
	PlatformBackupRowsDigestV1
	FirstStreamSequence *int64 `json:"first_stream_sequence,omitempty"`
	LastStreamSequence  *int64 `json:"last_stream_sequence,omitempty"`
}

func (d PlatformBackupPendingOutboxV1) valid() bool {
	if !d.PlatformBackupRowsDigestV1.valid([]string{"stream_sequence"}) {
		return false
	}
	return d.RowCount == 0 && d.FirstStreamSequence == nil && d.LastStreamSequence == nil || d.RowCount > 0 && d.FirstStreamSequence != nil && d.LastStreamSequence != nil && *d.FirstStreamSequence > 0 && *d.LastStreamSequence >= *d.FirstStreamSequence
}

type PlatformBackupRecoverableTasksV1 struct {
	PlatformBackupRowsDigestV1
	FirstCreatedAt *time.Time `json:"first_created_at,omitempty"`
	LastCreatedAt  *time.Time `json:"last_created_at,omitempty"`
}

func (d PlatformBackupRecoverableTasksV1) valid() bool {
	if !d.PlatformBackupRowsDigestV1.valid([]string{"created_at", "task_id"}) {
		return false
	}
	return d.RowCount == 0 && d.FirstCreatedAt == nil && d.LastCreatedAt == nil || d.RowCount > 0 && d.FirstCreatedAt != nil && d.LastCreatedAt != nil && d.FirstCreatedAt.Location() == time.UTC && d.LastCreatedAt.Location() == time.UTC && !d.LastCreatedAt.Before(*d.FirstCreatedAt)
}

func (d PlatformBackupRowsDigestV1) valid(order []string) bool {
	return d.RowCount >= 0 && validSHA(d.RowsSHA256) && equalStrings(d.OrderBy, order)
}

type PlatformBackupTasksOutboxV1 struct {
	SchemaVersion          int                              `json:"schema_version"`
	DatabaseSnapshotSHA256 string                           `json:"database_snapshot_sha256"`
	Canonicalization       string                           `json:"canonicalization"`
	Tables                 []TableDigest                    `json:"tables"`
	OutboxSequence         PlatformBackupSequenceV1         `json:"outbox_sequence"`
	PendingOutbox          PlatformBackupPendingOutboxV1    `json:"pending_outbox"`
	RecoverableTasks       PlatformBackupRecoverableTasksV1 `json:"recoverable_tasks"`
}

func (v PlatformBackupTasksOutboxV1) Validate() error {
	expected := []struct {
		name  string
		order []string
	}{{"outbox_events", []string{"stream_sequence"}}, {"task_agent_events", []string{"task_id", "sequence"}}, {"task_leases", []string{"created_at", "task_id"}}}
	if v.SchemaVersion != 1 || !validSHA(v.DatabaseSnapshotSHA256) || v.Canonicalization != PlatformBackupFactCanonicalization || len(v.Tables) != len(expected) || v.OutboxSequence.Relation != "public.outbox_events_stream_sequence" || v.OutboxSequence.LastValue < 0 || v.OutboxSequence.LastValue == 0 && v.OutboxSequence.IsCalled || !v.PendingOutbox.valid() || !v.RecoverableTasks.valid() {
		return ErrPlatformBackupPackage
	}
	for i, e := range expected {
		if !v.Tables[i].valid(e.name, e.order) {
			return ErrPlatformBackupPackage
		}
	}
	if v.PendingOutbox.RowCount > v.Tables[0].RowCount || v.RecoverableTasks.RowCount > v.Tables[2].RowCount || v.Tables[0].RowCount > 0 && !v.OutboxSequence.IsCalled || v.PendingOutbox.RowCount > 0 && (!v.OutboxSequence.IsCalled || *v.PendingOutbox.LastStreamSequence > v.OutboxSequence.LastValue) {
		return ErrPlatformBackupPackage
	}
	return nil
}
func MarshalPlatformBackupTasksOutboxV1(v PlatformBackupTasksOutboxV1) ([]byte, error) {
	return marshalBackupFact(v, v.Validate())
}
func ParsePlatformBackupTasksOutboxV1(raw []byte) (PlatformBackupTasksOutboxV1, error) {
	var v PlatformBackupTasksOutboxV1
	if err := parseBackupFact(raw, &v, []string{"schema_version", "database_snapshot_sha256", "canonicalization", "tables", "outbox_sequence", "pending_outbox", "recoverable_tasks"}, func() error { return v.Validate() }); err != nil {
		return PlatformBackupTasksOutboxV1{}, ErrPlatformBackupPackage
	}
	return v, nil
}

type PlatformBackupTLSReferenceV1 struct {
	CertificateReferenceID string     `json:"certificate_reference_id"`
	OwnerKind              string     `json:"owner_kind"`
	OwnerID                string     `json:"owner_id"`
	SecretReferenceID      *string    `json:"secret_reference_id"`
	SubjectHostname        string     `json:"subject_hostname"`
	Issuer                 string     `json:"issuer"`
	Status                 string     `json:"status"`
	NotBefore              *time.Time `json:"not_before,omitempty"`
	NotAfter               *time.Time `json:"not_after,omitempty"`
	RenewalDueAt           *time.Time `json:"renewal_due_at,omitempty"`
}
type PlatformBackupTLSV1 struct {
	SchemaVersion          int                            `json:"schema_version"`
	DatabaseSnapshotSHA256 string                         `json:"database_snapshot_sha256"`
	MaterialIncluded       bool                           `json:"material_included"`
	RestorePolicy          string                         `json:"restore_policy"`
	References             []PlatformBackupTLSReferenceV1 `json:"references"`
}

func (v PlatformBackupTLSV1) Validate() error {
	if v.SchemaVersion != 1 || !validSHA(v.DatabaseSnapshotSHA256) || v.MaterialIncluded || v.RestorePolicy != "resolve-or-reissue" || len(v.References) > 4096 {
		return ErrPlatformBackupPackage
	}
	for i, r := range v.References {
		if !r.valid() || i > 0 && !tlsRefLess(v.References[i-1], r) {
			return ErrPlatformBackupPackage
		}
	}
	return nil
}
func (r PlatformBackupTLSReferenceV1) valid() bool {
	if !validID(r.CertificateReferenceID) || (r.OwnerKind != "platform_domain" && r.OwnerKind != "application_domain") || !validID(r.OwnerID) || (r.SecretReferenceID != nil && !validID(*r.SecretReferenceID)) || !normalizedConsoleHostname(r.SubjectHostname) || !validID(r.Issuer) || (r.Status != "pending" && r.Status != "ready" && r.Status != "renewal_due" && r.Status != "failed" && r.Status != "revoked") {
		return false
	}
	for _, t := range []*time.Time{r.NotBefore, r.NotAfter, r.RenewalDueAt} {
		if t != nil && (t.IsZero() || t.Location() != time.UTC) {
			return false
		}
	}
	return (r.NotBefore == nil && r.NotAfter == nil) || (r.NotBefore != nil && r.NotAfter != nil && r.NotAfter.After(*r.NotBefore) && (r.RenewalDueAt == nil || (r.RenewalDueAt.After(*r.NotBefore) && r.RenewalDueAt.Before(*r.NotAfter))))
}
func tlsRefLess(a, b PlatformBackupTLSReferenceV1) bool {
	if a.CertificateReferenceID != b.CertificateReferenceID {
		return a.CertificateReferenceID < b.CertificateReferenceID
	}
	return a.SubjectHostname < b.SubjectHostname
}
func MarshalPlatformBackupTLSV1(v PlatformBackupTLSV1) ([]byte, error) {
	return marshalBackupFact(v, v.Validate())
}
func ParsePlatformBackupTLSV1(raw []byte) (PlatformBackupTLSV1, error) {
	var v PlatformBackupTLSV1
	if err := parseBackupFact(raw, &v, []string{"schema_version", "database_snapshot_sha256", "material_included", "restore_policy", "references"}, func() error { return v.Validate() }); err != nil {
		return PlatformBackupTLSV1{}, ErrPlatformBackupPackage
	}
	return v, nil
}

// ValidatePlatformBackupFacts proves the typed members describe the manifest
// being archived. Caddy files are intentionally outside this fact layer.
func ValidatePlatformBackupFacts(manifest PlatformBackupV3, members map[string][]byte) error {
	if manifest.Validate() != nil || members == nil {
		return ErrPlatformBackupPackage
	}
	runtime, err := ParsePlatformBackupRuntimeConfigV1(members["config/runtime.json"])
	if err != nil {
		return ErrPlatformBackupPackage
	}
	_ = runtime
	routes, err := ParsePlatformBackupRoutesV1(members["facts/routes.json"])
	if err != nil {
		return ErrPlatformBackupPackage
	}
	audit, err := ParsePlatformBackupAuditV1(members["facts/audit.json"])
	if err != nil {
		return ErrPlatformBackupPackage
	}
	keys, err := ParsePlatformBackupKeyReferencesV1(members["facts/key-references.json"])
	if err != nil {
		return ErrPlatformBackupPackage
	}
	release, err := ParsePlatformBackupReleaseV1(members["facts/release.json"])
	if err != nil {
		return ErrPlatformBackupPackage
	}
	tasks, err := ParsePlatformBackupTasksOutboxV1(members["facts/tasks-outbox.json"])
	if err != nil {
		return ErrPlatformBackupPackage
	}
	tls, err := ParsePlatformBackupTLSV1(members["edge/tls.json"])
	if err != nil {
		return ErrPlatformBackupPackage
	}
	if routes.DatabaseSnapshotSHA256 != manifest.DatabaseSnapshotSHA256 || audit.DatabaseSnapshotSHA256 != manifest.DatabaseSnapshotSHA256 || release.DatabaseSnapshotSHA256 != manifest.DatabaseSnapshotSHA256 || tasks.DatabaseSnapshotSHA256 != manifest.DatabaseSnapshotSHA256 || tls.DatabaseSnapshotSHA256 != manifest.DatabaseSnapshotSHA256 || release.Activation.ActivationID != manifest.SourceActivationID || release.Activation.ActivationJSONSHA256 != manifest.SourceActivationJSONSHA256 || release.Release != manifest.SourceRelease || release.Database.DatabaseV1 != manifest.SourceDatabase || release.Database.SchemaMigrationsRowsSHA256 != manifest.SourceDatabase.SchemaMigrationsSHA256 {
		return ErrPlatformBackupPackage
	}
	if keys.DatabaseSnapshotSHA256 != manifest.DatabaseSnapshotSHA256 {
		return ErrPlatformBackupPackage
	}
	localKeys := 0
	for _, ref := range keys.References {
		if ref.Provider != "control-plane-secret" && ref.Provider != "local-backup-key" {
			return ErrPlatformBackupPackage
		}
		if ref.Provider == "local-backup-key" {
			localKeys++
		}
	}
	if localKeys != 1 {
		return ErrPlatformBackupPackage
	}
	return nil
}

func marshalBackupFact(v any, validation error) ([]byte, error) {
	if validation != nil {
		return nil, ErrPlatformBackupPackage
	}
	return json.Marshal(v)
}
func parseBackupFact(raw []byte, value any, fields []string, validate func() error) error {
	if decodeStrict(raw, value) != nil || requireStrictFields(raw, fields) != nil || validate() != nil {
		return ErrPlatformBackupPackage
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrPlatformBackupPackage
	}
	return nil
}
func parseBackupFactNullable(raw []byte, value any, fields []string, validate func() error) error {
	if decodeStrict(raw, value) != nil || requireFieldsPresent(raw, fields) != nil || validate() != nil {
		return ErrPlatformBackupPackage
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrPlatformBackupPackage
	}
	return nil
}
func requireFieldsPresent(raw []byte, required []string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return ErrPlatformBackupPackage
		}
	}
	return nil
}
func equalStrings(a, b []string) bool {
	return len(a) == len(b) && strings.Join(a, "\x00") == strings.Join(b, "\x00")
}
func runtimeSettingsMap(v []PlatformBackupRuntimeSettingV1) map[string]string {
	out := make(map[string]string, len(v))
	for _, s := range v {
		out[s.Key] = s.Value
	}
	return out
}
func runtimeSettingsValid(v []PlatformBackupRuntimeSettingV1, allowed []string, server bool) bool {
	if len(v) == 0 {
		return false
	}
	for i, s := range v {
		index := sort.SearchStrings(allowed, s.Key)
		if (i > 0 && v[i-1].Key >= s.Key) || index == len(allowed) || allowed[index] != s.Key || !runtimeValueValid(s.Key, s.Value, server) {
			return false
		}
	}
	return true
}
func runtimeValueValid(key, value string, server bool) bool {
	upper := strings.ToUpper(key)
	if strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "TOKEN") || strings.Contains(upper, "CREDENTIAL") || strings.Contains(upper, "TLS") || strings.Contains(upper, "SECRET") || strings.Contains(upper, "PRIVATE") || strings.Contains(upper, "ACCESS_KEY") || strings.HasSuffix(upper, "_KEY") || strings.Contains(upper, "PROXY") || strings.Contains(upper, "DOCKER") || strings.Contains(upper, "CANDIDATE") || strings.Contains(upper, "FD") || strings.Contains(upper, "FIXTURE") || strings.Contains(upper, "TEST") || strings.Contains(upper, "FAILURE") || strings.Contains(strings.ToLower(value), "postgres") {
		return false
	}
	if strings.HasSuffix(key, "_ENABLED") || key == "OPEN_CARD_RUNTIME_ENABLED" || key == "OPEN_CARD_WORKER_NETWORK_ISOLATED" {
		return value == "true" || value == "false"
	}
	switch key {
	case "OPEN_CARD_SERVER_ADDR", "OPEN_CARD_AGENT_GATEWAY_ADDR", "OPEN_CARD_CADDY_LISTEN":
		return validLoopbackAddr(value)
	case "OPEN_CARD_CADDY_ADMIN_URL":
		return validLoopbackURL(value, "http")
	case "OPEN_CARD_AUTH_ORIGIN":
		return validHTTPSOrigin(value)
	case "OPEN_CARD_CONTROL_PLANE_URL":
		return validLoopbackURL(value, "http") || validLoopbackURL(value, "https")
	case "OPEN_CARD_AGENT_DISPATCH_INSTANCE_ID", "OPEN_CARD_AGENT_DISPATCH_NODE_ID", "OPEN_CARD_INSTANCE_ID", "OPEN_CARD_NODE_ID", "OPEN_CARD_AGENT_VERSION", "OPEN_CARD_RUNTIME_TASK_PREFIX", "OPEN_CARD_RUNTIME_NETWORK", "OPEN_CARD_RUNTIME_GROUP_NETWORK":
		return validID(value)
	case "OPEN_CARD_AGENT_IDENTITIES_JSON":
		return validCanonicalIDsJSON(value)
	case "OPEN_CARD_M3_COMPOSITION":
		return value == "production"
	case "OPEN_CARD_M4_ROLLOUT_INTERVAL":
		return validDuration(value, time.Second, 30*time.Second)
	case "OPEN_CARD_M4_LOG_COLLECTION_INTERVAL":
		return validDuration(value, time.Second, 5*time.Minute)
	case "OPEN_CARD_LOG_MAX_FILE_BYTES", "OPEN_CARD_LOG_MAX_TOTAL_BYTES", "OPEN_CARD_M5_STORAGE_CAPACITY_BYTES", "OPEN_CARD_M5_STORAGE_HARD_RESERVE_BYTES", "OPEN_CARD_RUNTIME_RESERVE_MEMORY_BYTES":
		return validCanonicalUint(value)
	case "OPEN_CARD_STATIC_RUNTIME_DIGEST":
		return strings.HasPrefix(value, "sha256:") && validSHA(strings.TrimPrefix(value, "sha256:"))
	case "OPEN_CARD_M2_REGISTRY_BASE_URL":
		return validLoopbackURL(value, "http")
	case "OPEN_CARD_SOURCE_GIT_RESOLVERS":
		return validResolverList(value)
	case "OPEN_CARD_CONTROL_PLANE_SERVER_NAME":
		return normalizedConsoleHostname(value)
	case "OPEN_CARD_BUILDKIT_WORKER":
		return validID(value)
	case "OPEN_CARD_BUILDKIT_COMMAND", "OPEN_CARD_STATIC_SERVER_BINARY":
		return validProductPath(value)
	case "OPEN_CARD_BUILD_WORK_ROOT", "OPEN_CARD_LOG_ROOT", "OPEN_CARD_OCI_STORE_ROOT", "OPEN_CARD_SOURCE_UPLOAD_ROOT", "OPEN_CARD_SOURCE_WORKSPACE_ROOT", "OPEN_CARD_M6_WORKSPACE_ROOT", "OPEN_CARD_RUNTIME_WORK_ROOT":
		return validProductPath(value)
	case "OPEN_CARD_BUILDKIT_ADDRESS":
		return validLoopbackAddr(value) || value == "unix:///run/open-card-buildkit/buildkitd.sock"
	}
	return false
}
func validCanonicalUint(v string) bool {
	n, err := strconv.ParseUint(v, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == v
}
func validDuration(v string, min, max time.Duration) bool {
	d, err := time.ParseDuration(v)
	return err == nil && d >= min && d <= max && d.String() == v
}
func validLoopbackAddr(v string) bool {
	host, port, err := net.SplitHostPort(v)
	if err != nil || !validCanonicalUint(port) {
		return false
	}
	p, _ := strconv.ParseUint(port, 10, 16)
	return p > 0 && (host == "127.0.0.1" || host == "::1" || host == "[::1]")
}
func validLoopbackURL(v, scheme string) bool {
	u, err := url.Parse(v)
	return err == nil && u.Scheme == scheme && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Path == "" || u.Path == "/") && validLoopbackAddr(u.Host)
}
func validHTTPSOrigin(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && strings.ToLower(u.Host) == u.Host
}
func validProductPath(v string) bool {
	if !filepath.IsAbs(v) || filepath.Clean(v) != v || strings.ContainsAny(v, "\x00\r\n") {
		return false
	}
	for _, root := range []string{"/opt/open-card", "/var/lib/open-card", "/var/lib/open-card-agent", "/var/log/open-card", "/run/open-card-buildkit"} {
		if v == root || strings.HasPrefix(v, root+"/") {
			return true
		}
	}
	return false
}

type platformBackupAgentIdentityV1 struct {
	CertificateID string `json:"certificate_id"`
	InstanceID    string `json:"instance_id"`
	NodeID        string `json:"node_id"`
}

func validCanonicalIDsJSON(v string) bool {
	var ids []platformBackupAgentIdentityV1
	if decodeStrict([]byte(v), &ids) != nil || len(ids) == 0 {
		return false
	}
	raw, err := json.Marshal(ids)
	if err != nil || string(raw) != v {
		return false
	}
	for i, id := range ids {
		if !validID(id.CertificateID) || !validID(id.InstanceID) || !validID(id.NodeID) || i > 0 && (ids[i-1].CertificateID > id.CertificateID || ids[i-1].CertificateID == id.CertificateID && (ids[i-1].InstanceID > id.InstanceID || ids[i-1].InstanceID == id.InstanceID && ids[i-1].NodeID >= id.NodeID)) {
			return false
		}
	}
	return true
}
func validResolverList(value string) bool {
	if value == "" {
		return false
	}
	parts := strings.Split(value, ",")
	if len(parts) < 2 {
		return false
	}
	for i, part := range parts {
		if strings.TrimSpace(part) != part || !validPublicAddr(part) || i > 0 && parts[i-1] >= part {
			return false
		}
	}
	return true
}
func validPublicAddr(value string) bool {
	addr, err := netip.ParseAddrPort(value)
	if err != nil || addr.Port() == 0 {
		return false
	}
	ip := addr.Addr()
	if !ip.IsGlobalUnicast() || ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range platformBackupForbiddenGitPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return addr.String() == value
}
func runtimeFeatureHierarchy(values map[string]string) bool {
	flag := func(key string) bool { return values[key] == "true" }
	m1, m2, m3, m4, rollout, m5, m6 := flag("OPEN_CARD_M1_ENABLED"), flag("OPEN_CARD_M2_ENABLED"), flag("OPEN_CARD_M3_ENABLED"), flag("OPEN_CARD_M4_ENABLED"), flag("OPEN_CARD_M4_ROLLOUT_ENABLED"), flag("OPEN_CARD_M5_ENABLED"), flag("OPEN_CARD_M6_ENABLED")
	return (!m2 || m1) && (!m3 || m1 && m2) && (!m4 || m1 && m2) && (!rollout || m4 && m3) && (!m5 || m4) && (!m6 || m4 && m5)
}
