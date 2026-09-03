package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	InactiveSubstrateReceiptV1Schema = 1
	AcornFoxSubstrateLayoutV1        = 1
	AcornFoxSubstrateTreeV1Schema    = 1
)

const (
	AcornFoxUpgradeHelperPath = "opt/acornfox/upgrade-tools/acornfox-upgrade"
)

func AcornFoxHealthcheckHelperPath(receipt AcornFoxStageReceiptV1) string {
	return "opt/acornfox/releases/" + receipt.ReleaseID + "/bin/acornfox-healthcheck"
}

// OwnerRole is a fixed role label, never a uid/gid. Receipts deliberately do
// not carry host identity data.
type OwnerRole string

const (
	OwnerRoleRoot     OwnerRole = "root"
	OwnerRoleServer   OwnerRole = "server"
	OwnerRoleAgent    OwnerRole = "agent"
	OwnerRoleBuildKit OwnerRole = "buildkit"
	OwnerRoleCaddy    OwnerRole = "caddy"
	OwnerRoleEdge     OwnerRole = "edge"
)

type SubstrateEntryKind string

const (
	SubstrateEntryFile      SubstrateEntryKind = "file"
	SubstrateEntryDirectory SubstrateEntryKind = "directory"
)

// SubstrateEntry names a relative, candidate-owned entry. Absolute paths,
// credentials, uid/gid values, and device nodes have no representation here.
type SubstrateEntry struct {
	Path   string             `json:"path"`
	Kind   SubstrateEntryKind `json:"kind"`
	Mode   uint32             `json:"mode"`
	Role   OwnerRole          `json:"role"`
	Size   int64              `json:"size"`
	SHA256 string             `json:"sha256"`
}

type AcornFoxSubstrateTreeEnvelopeV1 struct {
	SchemaVersion int              `json:"schema_version"`
	Entries       []SubstrateEntry `json:"entries"`
}

// InactiveSubstrateReceiptV1 records only verified candidate and tree digests.
// Binding, manifest, archive, and receipt digests are external references: do
// not embed any of those binaries into a digest-bearing contract, or the hash
// topology becomes circular.
type InactiveSubstrateReceiptV1 struct {
	SchemaVersion       int                    `json:"schema_version"`
	State               string                 `json:"state"`
	LayoutVersion       int                    `json:"layout_version"`
	CandidateReceipt    AcornFoxStageReceiptV1 `json:"candidate_receipt"`
	ReleaseTreeSHA256   string                 `json:"release_tree_sha256"`
	InstalledTreeSHA256 string                 `json:"installed_tree_sha256"`
	UpgradeHelperSHA256 string                 `json:"upgrade_helper_sha256"`
	HealthHelperSHA256  string                 `json:"health_helper_sha256"`
	Entries             []SubstrateEntry       `json:"entries"`
}

func (r InactiveSubstrateReceiptV1) Validate() error {
	if r.SchemaVersion != InactiveSubstrateReceiptV1Schema || r.State != "inactive_complete" || r.LayoutVersion != AcornFoxSubstrateLayoutV1 {
		return errors.New("AcornFox inactive substrate receipt identity is invalid")
	}
	if r.CandidateReceipt.Validate() != nil {
		return errors.New("AcornFox inactive substrate candidate receipt is invalid")
	}
	for _, digest := range []string{r.ReleaseTreeSHA256, r.InstalledTreeSHA256, r.UpgradeHelperSHA256, r.HealthHelperSHA256} {
		if !digestPattern.MatchString(digest) {
			return errors.New("AcornFox inactive substrate digest is invalid")
		}
	}
	if r.ReleaseTreeSHA256 != r.CandidateReceipt.TreeSHA256 {
		return errors.New("AcornFox inactive substrate release tree is not candidate-bound")
	}
	if err := validateAcornFoxV1SubstrateInventory(r.CandidateReceipt, r.Entries); err != nil {
		return err
	}
	computed, err := ComputeAcornFoxSubstrateTreeSHA256(r.Entries)
	if err != nil || r.InstalledTreeSHA256 != computed {
		return errors.New("AcornFox inactive substrate installed tree digest is invalid")
	}
	upgrade, health := substrateEntryAt(r.Entries, AcornFoxUpgradeHelperPath), substrateEntryAt(r.Entries, AcornFoxHealthcheckHelperPath(r.CandidateReceipt))
	if upgrade == nil || health == nil || upgrade.SHA256 != r.UpgradeHelperSHA256 || health.SHA256 != r.HealthHelperSHA256 {
		return errors.New("AcornFox inactive substrate helper entries are invalid")
	}
	return nil
}

func (e AcornFoxSubstrateTreeEnvelopeV1) Validate() error {
	if e.SchemaVersion != AcornFoxSubstrateTreeV1Schema {
		return errors.New("AcornFox substrate tree schema is invalid")
	}
	return validateAcornFoxSubstrateEntries(e.Entries)
}

func ParseAcornFoxSubstrateTreeEnvelopeV1(raw []byte) (AcornFoxSubstrateTreeEnvelopeV1, error) {
	var envelope AcornFoxSubstrateTreeEnvelopeV1
	if err := strictCanonicalJSON(raw, &envelope, "AcornFox substrate tree envelope"); err != nil {
		return AcornFoxSubstrateTreeEnvelopeV1{}, err
	}
	if err := envelope.Validate(); err != nil {
		return AcornFoxSubstrateTreeEnvelopeV1{}, err
	}
	return envelope, nil
}

func MarshalAcornFoxSubstrateTreeEnvelopeV1(envelope AcornFoxSubstrateTreeEnvelopeV1) ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

// ComputeAcornFoxSubstrateTreeSHA256 is the single tree digest definition for
// inactive substrate contracts. The envelope bytes are canonical and entries
// are already required to be strictly sorted; no caller-controlled hash shape
// exists here.
func ComputeAcornFoxSubstrateTreeSHA256(entries []SubstrateEntry) (string, error) {
	raw, err := MarshalAcornFoxSubstrateTreeEnvelopeV1(AcornFoxSubstrateTreeEnvelopeV1{SchemaVersion: AcornFoxSubstrateTreeV1Schema, Entries: entries})
	if err != nil {
		return "", err
	}
	return sha256Hex(raw), nil
}

func MarshalInactiveSubstrateReceiptV1(receipt InactiveSubstrateReceiptV1) ([]byte, error) {
	if err := receipt.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(receipt)
}

func ParseInactiveSubstrateReceiptV1(raw []byte) (InactiveSubstrateReceiptV1, error) {
	var receipt InactiveSubstrateReceiptV1
	if err := strictCanonicalJSON(raw, &receipt, "AcornFox inactive substrate receipt"); err != nil {
		return InactiveSubstrateReceiptV1{}, err
	}
	if err := receipt.Validate(); err != nil {
		return InactiveSubstrateReceiptV1{}, err
	}
	return receipt, nil
}

func validateAcornFoxSubstrateEntries(entries []SubstrateEntry) error {
	if len(entries) == 0 || len(entries) > 256 {
		return errors.New("AcornFox substrate entry count is invalid")
	}
	for index, entry := range entries {
		if err := validateAcornFoxSubstrateEntry(entry); err != nil {
			return fmt.Errorf("AcornFox substrate entry %d: %w", index, err)
		}
		if index > 0 && entries[index-1].Path >= entry.Path {
			return errors.New("AcornFox substrate entries are not strictly sorted")
		}
	}
	return nil
}

func validateAcornFoxSubstrateEntry(entry SubstrateEntry) error {
	if err := validateRelativePath(entry.Path); err != nil || strings.HasPrefix(entry.Path, "release/") || strings.Contains(entry.Path, "..") {
		return errors.New("path is invalid")
	}
	if entry.Kind != SubstrateEntryFile && entry.Kind != SubstrateEntryDirectory {
		return errors.New("kind is invalid")
	}
	if entry.Mode > 0o777 || entry.Mode&0o022 != 0 || !validAcornFoxOwnerRole(entry.Role) || entry.Size < 0 {
		return errors.New("metadata is invalid")
	}
	if entry.Kind == SubstrateEntryDirectory {
		if entry.Size != 0 || entry.SHA256 != "" || (entry.Mode != 0o700 && entry.Mode != 0o750 && entry.Mode != 0o755) {
			return errors.New("directory metadata is invalid")
		}
		return nil
	}
	if !digestPattern.MatchString(entry.SHA256) || !validAcornFoxSubstrateFileMode(entry.Mode) {
		return errors.New("file metadata is invalid")
	}
	return nil
}

func validAcornFoxOwnerRole(role OwnerRole) bool {
	switch role {
	case OwnerRoleRoot, OwnerRoleServer, OwnerRoleAgent, OwnerRoleBuildKit, OwnerRoleCaddy, OwnerRoleEdge:
		return true
	default:
		return false
	}
}

func validAcornFoxSubstrateFileMode(mode uint32) bool {
	return mode == 0o600 || mode == 0o640 || mode == 0o644 || mode == 0o700 || mode == 0o750 || mode == 0o755
}

func substrateEntryAt(entries []SubstrateEntry, path string) *SubstrateEntry {
	for index := range entries {
		if entries[index].Path == path {
			return &entries[index]
		}
	}
	return nil
}

// validateAcornFoxV1SubstrateInventory validates the complete inactive V1
// layout. The publisher must separately verify each release member's digest
// against the pinned manifest before constructing this receipt; this contract
// binds that verified tree through CandidateReceipt.TreeSHA256, exact member
// count, and the closed installed-path/mapping inventory below.
func validateAcornFoxV1SubstrateInventory(candidate AcornFoxStageReceiptV1, entries []SubstrateEntry) error {
	if err := validateAcornFoxSubstrateEntries(entries); err != nil {
		return err
	}
	byPath := make(map[string]SubstrateEntry, len(entries))
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	releasePrefix := "opt/acornfox/releases/" + candidate.ReleaseID + "/"
	releaseMembers := 0
	seenRequired := map[string]bool{}
	for path, entry := range byPath {
		if strings.HasPrefix(path, releasePrefix) {
			relative := strings.TrimPrefix(path, releasePrefix)
			if err := validateAcornFoxReleaseMember(candidate, relative, entry); err != nil {
				return err
			}
			releaseMembers++
			for _, required := range AcornFoxV1RequiredFiles() {
				if relative == required.Path {
					seenRequired[relative] = true
				}
			}
			continue
		}
		if _, ok := acornFoxFixedSubstrateEntry(candidate, path); !ok {
			return fmt.Errorf("AcornFox substrate path is not allowed: %s", path)
		}
	}
	for _, required := range AcornFoxV1RequiredFiles() {
		if !seenRequired[required.Path] {
			return fmt.Errorf("AcornFox substrate misses release member: %s", required.Path)
		}
	}
	// AcornFoxStageReceiptV1.FileCount is the pinned manifest.Files count;
	// manifest.json is the one additional release-tree member.
	if releaseMembers != candidate.FileCount+1 {
		return errors.New("AcornFox substrate release member count is invalid")
	}
	for path, want := range acornFoxFixedSubstrateEntries(candidate) {
		got, ok := byPath[path]
		if !ok || got.Kind != want.Kind || got.Mode != want.Mode || got.Role != want.Role || (got.Kind == SubstrateEntryDirectory && (got.Size != want.Size || got.SHA256 != want.SHA256)) {
			return fmt.Errorf("AcornFox substrate fixed entry is invalid: %s", path)
		}
		if source := acornFoxInstalledSource(candidate, path); source != "" {
			member, ok := byPath[releasePrefix+source]
			if !ok || got.SHA256 != member.SHA256 || got.Size != member.Size {
				return fmt.Errorf("AcornFox substrate installed mapping is invalid: %s", path)
			}
		}
	}
	return nil
}

func validateAcornFoxReleaseMember(candidate AcornFoxStageReceiptV1, relative string, entry SubstrateEntry) error {
	if entry.Kind != SubstrateEntryFile || entry.Role != OwnerRoleRoot {
		return errors.New("AcornFox release member metadata is invalid")
	}
	if relative == "manifest.json" {
		if entry.Mode != 0o644 || entry.SHA256 != candidate.ManifestSHA256 {
			return errors.New("AcornFox release manifest is invalid")
		}
		return nil
	}
	for _, required := range AcornFoxV1RequiredFiles() {
		if relative == required.Path {
			if entry.Mode != required.Mode {
				return errors.New("AcornFox release member mode is invalid")
			}
			return nil
		}
	}
	if strings.HasPrefix(relative, "web/dist/assets/") && validAcornFoxV1WebAsset(relative) && entry.Mode == 0o644 {
		return nil
	}
	return fmt.Errorf("AcornFox release member is not allowed: %s", relative)
}

func acornFoxFixedSubstrateEntry(candidate AcornFoxStageReceiptV1, path string) (SubstrateEntry, bool) {
	entry, ok := acornFoxFixedSubstrateEntries(candidate)[path]
	return entry, ok
}

func acornFoxFixedSubstrateEntries(candidate AcornFoxStageReceiptV1) map[string]SubstrateEntry {
	directory := func(path string, mode uint32, role OwnerRole) SubstrateEntry {
		return SubstrateEntry{Path: path, Kind: SubstrateEntryDirectory, Mode: mode, Role: role}
	}
	file := func(path string, mode uint32, role OwnerRole) SubstrateEntry {
		return SubstrateEntry{Path: path, Kind: SubstrateEntryFile, Mode: mode, Role: role}
	}
	entries := map[string]SubstrateEntry{}
	for _, path := range []string{"opt", "opt/acornfox", "opt/acornfox/releases", "opt/acornfox/releases/" + candidate.ReleaseID, "opt/acornfox/upgrade-tools", "etc", "etc/systemd", "etc/systemd/system", "etc/acornfox", "var", "var/lib", "var/lib/acornfox", "var/log", "var/log/acornfox"} {
		entries[path] = directory(path, 0o755, OwnerRoleRoot)
	}
	for _, service := range []struct {
		name string
		role OwnerRole
	}{{"server", OwnerRoleServer}, {"agent", OwnerRoleAgent}, {"buildkit", OwnerRoleBuildKit}, {"caddy", OwnerRoleCaddy}, {"edge", OwnerRoleEdge}} {
		for _, base := range []string{"var/lib/acornfox/", "var/log/acornfox/"} {
			path := base + service.name
			entries[path] = directory(path, 0o750, service.role)
		}
	}
	entries[AcornFoxUpgradeHelperPath] = file(AcornFoxUpgradeHelperPath, 0o755, OwnerRoleRoot)
	for _, unit := range acornFoxV1Units {
		path := "etc/systemd/system/" + strings.TrimPrefix(unit, "systemd/")
		entries[path] = file(path, 0o644, OwnerRoleRoot)
	}
	for destination := range map[string]string{"etc/acornfox/Caddyfile": "caddy/acornfox.Caddyfile.example", "etc/acornfox/acornfox-edge.Caddyfile": "caddy/acornfox-edge.Caddyfile.example", "etc/acornfox/acornfox-edge.env": "caddy/acornfox-edge.env.example", "etc/acornfox/buildkitd.toml": "config/acornfox-buildkitd.toml"} {
		mode := uint32(0o644)
		if strings.HasSuffix(destination, ".env") {
			mode = 0o640
		}
		entries[destination] = file(destination, mode, OwnerRoleRoot)
	}
	return entries
}

func acornFoxInstalledSource(candidate AcornFoxStageReceiptV1, path string) string {
	if path == AcornFoxUpgradeHelperPath {
		return "bin/acornfox-upgrade"
	}
	if strings.HasPrefix(path, "etc/systemd/system/") {
		return "systemd/" + strings.TrimPrefix(path, "etc/systemd/system/")
	}
	return map[string]string{"etc/acornfox/Caddyfile": "caddy/acornfox.Caddyfile.example", "etc/acornfox/acornfox-edge.Caddyfile": "caddy/acornfox-edge.Caddyfile.example", "etc/acornfox/acornfox-edge.env": "caddy/acornfox-edge.env.example", "etc/acornfox/buildkitd.toml": "config/acornfox-buildkitd.toml"}[path]
}

type AcornFoxInactiveSubstrateIntentV1 struct {
	SchemaVersion               int                    `json:"schema_version"`
	LayoutVersion               int                    `json:"layout_version"`
	CandidateReceipt            AcornFoxStageReceiptV1 `json:"candidate_receipt"`
	ExpectedEntryEnvelopeSHA256 string                 `json:"expected_entry_envelope_sha256"`
}

func (i AcornFoxInactiveSubstrateIntentV1) Validate() error {
	if i.SchemaVersion != InactiveSubstrateReceiptV1Schema || i.LayoutVersion != AcornFoxSubstrateLayoutV1 || i.CandidateReceipt.Validate() != nil || !digestPattern.MatchString(i.ExpectedEntryEnvelopeSHA256) {
		return errors.New("AcornFox inactive substrate intent is invalid")
	}
	return nil
}

func ParseAcornFoxInactiveSubstrateIntentV1(raw []byte) (AcornFoxInactiveSubstrateIntentV1, error) {
	var intent AcornFoxInactiveSubstrateIntentV1
	if err := strictCanonicalJSON(raw, &intent, "AcornFox inactive substrate intent"); err != nil {
		return AcornFoxInactiveSubstrateIntentV1{}, err
	}
	return intent, intent.Validate()
}

func MarshalAcornFoxInactiveSubstrateIntentV1(intent AcornFoxInactiveSubstrateIntentV1) ([]byte, error) {
	if err := intent.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(intent)
}

type AcornFoxReconciliationOutcome string

const (
	AcornFoxReconcileAbsent           AcornFoxReconciliationOutcome = "absent"
	AcornFoxReconcileResume           AcornFoxReconciliationOutcome = "resume"
	AcornFoxReconcileCompleted        AcornFoxReconciliationOutcome = "completed"
	AcornFoxReconcileRecoveryRequired AcornFoxReconciliationOutcome = "recovery_required"
	AcornFoxReconcileConflict         AcornFoxReconciliationOutcome = "conflict"
	AcornFoxReconcileCommitUnknown    AcornFoxReconciliationOutcome = "commit_unknown"
	AcornFoxReconcileCleanupUnknown   AcornFoxReconciliationOutcome = "cleanup_unknown"
)

func (o AcornFoxReconciliationOutcome) Validate() error {
	switch o {
	case AcornFoxReconcileAbsent, AcornFoxReconcileResume, AcornFoxReconcileCompleted, AcornFoxReconcileRecoveryRequired, AcornFoxReconcileConflict, AcornFoxReconcileCommitUnknown, AcornFoxReconcileCleanupUnknown:
		return nil
	default:
		return errors.New("AcornFox reconciliation outcome is invalid")
	}
}
