package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
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
type GroupRole string

const (
	OwnerRoleRoot     OwnerRole = "root"
	OwnerRoleServer   OwnerRole = "server"
	OwnerRoleAgent    OwnerRole = "agent"
	OwnerRoleBuildKit OwnerRole = "buildkit"
	OwnerRoleCaddy    OwnerRole = "caddy"
	OwnerRoleEdge     OwnerRole = "edge"
)

const (
	GroupRoleRoot     GroupRole = "root"
	GroupRoleServer   GroupRole = "server"
	GroupRoleAgent    GroupRole = "agent"
	GroupRoleBuildKit GroupRole = "buildkit"
	GroupRoleCaddy    GroupRole = "caddy"
	GroupRoleEdge     GroupRole = "edge"
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
	Group  GroupRole          `json:"group"`
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
	computedRelease, err := ComputeAcornFoxReleaseTreeSHA256(r.CandidateReceipt, r.Entries)
	if err != nil || computedRelease != r.ReleaseTreeSHA256 {
		return errors.New("AcornFox inactive substrate release tree digest is invalid")
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

// ComputeAcornFoxReleaseTreeSHA256 is intentionally congruent with the stage
// receipt tree: manifest.json is first, then manifest.Files paths sorted by
// relative release path. The publisher verifies source bytes against the pinned
// manifest before emitting entries; this contract recomputes their tree shape.
func ComputeAcornFoxReleaseTreeSHA256(candidate AcornFoxStageReceiptV1, entries []SubstrateEntry) (string, error) {
	prefix := "opt/acornfox/releases/" + candidate.ReleaseID + "/"
	files := make([]SubstrateEntry, 0, candidate.FileCount)
	var manifest *SubstrateEntry
	for index := range entries {
		entry := &entries[index]
		if !strings.HasPrefix(entry.Path, prefix) || entry.Kind != SubstrateEntryFile {
			continue
		}
		relative := strings.TrimPrefix(entry.Path, prefix)
		if relative == "manifest.json" {
			manifest = entry
			continue
		}
		files = append(files, *entry)
	}
	if manifest == nil || manifest.Mode != 0o644 || manifest.SHA256 != candidate.ManifestSHA256 || len(files) != candidate.FileCount {
		return "", errors.New("AcornFox release tree members are invalid")
	}
	sort.Slice(files, func(i, j int) bool {
		return strings.TrimPrefix(files[i].Path, prefix) < strings.TrimPrefix(files[j].Path, prefix)
	})
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "manifest.json\x00%04o\x00%s\n", 0o644, candidate.ManifestSHA256)
	for _, entry := range files {
		relative := strings.TrimPrefix(entry.Path, prefix)
		_, _ = fmt.Fprintf(hash, "%s\x00%04o\x00%s\n", relative, entry.Mode, entry.SHA256)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
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
	if entry.Mode > 0o777 || entry.Mode&0o022 != 0 || !validAcornFoxOwnerRole(entry.Role) || !validAcornFoxGroupRole(entry.Group) || entry.Size < 0 {
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

func validAcornFoxGroupRole(role GroupRole) bool {
	switch role {
	case GroupRoleRoot, GroupRoleServer, GroupRoleAgent, GroupRoleBuildKit, GroupRoleCaddy, GroupRoleEdge:
		return true
	default:
		return false
	}
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
	releaseDirectories := map[string]struct{}{"opt/acornfox/releases/" + candidate.ReleaseID: {}}
	seenRequired := map[string]bool{}
	for path, entry := range byPath {
		if strings.HasPrefix(path, releasePrefix) {
			if entry.Kind == SubstrateEntryDirectory {
				continue
			}
			relative := strings.TrimPrefix(path, releasePrefix)
			if err := validateAcornFoxReleaseMember(candidate, relative, entry); err != nil {
				return err
			}
			releaseMembers++
			for parent := parentDirectory(path); strings.HasPrefix(parent, "opt/acornfox/releases/"+candidate.ReleaseID); parent = parentDirectory(parent) {
				releaseDirectories[parent] = struct{}{}
				if parent == "opt/acornfox/releases/"+candidate.ReleaseID {
					break
				}
			}
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
	for path := range releaseDirectories {
		entry, ok := byPath[path]
		if !ok || entry.Kind != SubstrateEntryDirectory || entry.Mode != 0o755 || entry.Role != OwnerRoleRoot || entry.Group != GroupRoleRoot || entry.Size != 0 || entry.SHA256 != "" {
			return fmt.Errorf("AcornFox release directory is invalid: %s", path)
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
		if !ok || got.Kind != want.Kind || got.Mode != want.Mode || got.Role != want.Role || got.Group != want.Group || (got.Kind == SubstrateEntryDirectory && (got.Size != want.Size || got.SHA256 != want.SHA256)) {
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

func parentDirectory(path string) string {
	if index := strings.LastIndex(path, "/"); index > 0 {
		return path[:index]
	}
	return ""
}

func validateAcornFoxReleaseMember(candidate AcornFoxStageReceiptV1, relative string, entry SubstrateEntry) error {
	if entry.Kind != SubstrateEntryFile || entry.Role != OwnerRoleRoot || entry.Group != GroupRoleRoot {
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
	directory := func(path string, mode uint32, role OwnerRole, group GroupRole) SubstrateEntry {
		return SubstrateEntry{Path: path, Kind: SubstrateEntryDirectory, Mode: mode, Role: role, Group: group}
	}
	file := func(path string, mode uint32, role OwnerRole, group GroupRole) SubstrateEntry {
		return SubstrateEntry{Path: path, Kind: SubstrateEntryFile, Mode: mode, Role: role, Group: group}
	}
	entries := map[string]SubstrateEntry{}
	for _, path := range []string{"opt", "opt/acornfox", "opt/acornfox/releases", "opt/acornfox/releases/" + candidate.ReleaseID, "opt/acornfox/upgrade-tools", "etc", "etc/acornfox", "etc/systemd", "etc/systemd/system", "etc/systemd/system/acornfox-edge.service.d", "var", "var/lib", "var/lib/acornfox", "var/lib/acornfox/install", "var/lib/acornfox/install/releases", "var/log", "var/log/acornfox"} {
		entries[path] = directory(path, 0o755, OwnerRoleRoot, GroupRoleRoot)
	}
	for _, path := range []string{"var/lib/acornfox/uploads", "var/lib/acornfox/workspaces", "var/lib/acornfox/build-work", "var/lib/acornfox/oci", "var/log/acornfox/server"} {
		entries[path] = directory(path, 0o750, OwnerRoleServer, GroupRoleServer)
	}
	for _, path := range []string{"var/lib/acornfox/secrets", "var/lib/acornfox/secret-materials"} {
		entries[path] = directory(path, 0o700, OwnerRoleServer, GroupRoleServer)
	}
	entries["var/lib/acornfox/health-secret-materials"] = directory("var/lib/acornfox/health-secret-materials", 0o700, OwnerRoleRoot, GroupRoleRoot)
	entries["var/lib/acornfox/agent"], entries["var/log/acornfox/agent"] = directory("var/lib/acornfox/agent", 0o750, OwnerRoleAgent, GroupRoleAgent), directory("var/log/acornfox/agent", 0o750, OwnerRoleAgent, GroupRoleAgent)
	entries["var/lib/acornfox/buildkit"] = directory("var/lib/acornfox/buildkit", 0o700, OwnerRoleBuildKit, GroupRoleBuildKit)
	entries["var/lib/acornfox/caddy"], entries["var/log/acornfox/caddy"] = directory("var/lib/acornfox/caddy", 0o750, OwnerRoleCaddy, GroupRoleCaddy), directory("var/log/acornfox/caddy", 0o750, OwnerRoleCaddy, GroupRoleCaddy)
	for _, path := range []string{"var/lib/acornfox/edge", "var/log/acornfox/edge"} {
		entries[path] = directory(path, 0o750, OwnerRoleEdge, GroupRoleEdge)
	}
	for _, path := range []string{"var/lib/acornfox/edge/home", "var/lib/acornfox/edge/data", "var/lib/acornfox/edge/config"} {
		entries[path] = directory(path, 0o700, OwnerRoleEdge, GroupRoleEdge)
	}
	entries["var/lib/acornfox/healthcheck"] = directory("var/lib/acornfox/healthcheck", 0o700, OwnerRoleRoot, GroupRoleRoot)
	entries[AcornFoxUpgradeHelperPath] = file(AcornFoxUpgradeHelperPath, 0o755, OwnerRoleRoot, GroupRoleRoot)
	for _, unit := range acornFoxV1Units {
		path := "etc/systemd/system/" + strings.TrimPrefix(unit, "systemd/")
		entries[path] = file(path, 0o644, OwnerRoleRoot, GroupRoleRoot)
	}
	for destination := range map[string]string{"etc/acornfox/Caddyfile": "caddy/acornfox.Caddyfile.example", "etc/acornfox/acornfox-edge.Caddyfile": "caddy/acornfox-edge.Caddyfile.example", "etc/acornfox/acornfox-edge.env": "caddy/acornfox-edge.env.example", "etc/acornfox/buildkitd.toml": "config/acornfox-buildkitd.toml"} {
		mode, group := uint32(0o644), GroupRoleRoot
		if strings.HasSuffix(destination, ".env") {
			mode, group = 0o640, GroupRoleEdge
		}
		entries[destination] = file(destination, mode, OwnerRoleRoot, group)
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
