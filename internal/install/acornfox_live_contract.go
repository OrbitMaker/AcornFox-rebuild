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

const AcornFoxLiveReceiptV1Schema = 1

const (
	acornFoxLiveDir     = "live"
	acornFoxLiveReceipt = "live/receipt.json"
)

// AcornFoxLiveRole is a closed modeled-account namespace.  It is intentionally
// distinct from a host account: materialization never looks up nor changes a
// host uid or gid.
type AcornFoxLiveRole string

const (
	AcornFoxLiveRootRole     AcornFoxLiveRole = "root"
	AcornFoxLiveServerRole   AcornFoxLiveRole = "acornfox"
	AcornFoxLiveAgentRole    AcornFoxLiveRole = "acornfox-agent"
	AcornFoxLiveBuildKitRole AcornFoxLiveRole = "acornfox-buildkit"
	AcornFoxLiveCaddyRole    AcornFoxLiveRole = "acornfox-caddy"
	AcornFoxLiveEdgeRole     AcornFoxLiveRole = "acornfox-edge"
)

// AcornFoxLiveEntryV1 contains the symbolic requested account plan and the only
// honest physical observation available in task-root preparation: the entry
// is owned by the task-root owner.  It deliberately carries no host uid/gid.
type AcornFoxLiveEntryV1 struct {
	Path                     string             `json:"path"`
	Kind                     SubstrateEntryKind `json:"kind"`
	Mode                     uint32             `json:"mode"`
	Role                     AcornFoxLiveRole   `json:"role"`
	Group                    AcornFoxLiveRole   `json:"group"`
	PhysicalOwnerObservation string             `json:"physical_owner_observation"`
	Size                     int64              `json:"size"`
	SHA256                   string             `json:"sha256"`
}

type acornFoxLiveTreeEnvelopeV1 struct {
	SchemaVersion int                   `json:"schema_version"`
	Entries       []AcornFoxLiveEntryV1 `json:"entries"`
}

type acornFoxLiveStaticEnvelopeV1 struct {
	SchemaVersion int                   `json:"schema_version"`
	Entries       []AcornFoxLiveEntryV1 `json:"entries"`
}

// AcornFoxLiveReceiptV1 is the sealed evidence emitted by task-root-only
// materialization.  It has no activation pointer, account lookup, absolute
// path, DSN, secret, or host uid/gid representation.
type AcornFoxLiveReceiptV1 struct {
	SchemaVersion          int                   `json:"schema_version"`
	State                  string                `json:"state"`
	BindingSHA256          string                `json:"binding_sha256"`
	SubstrateReceiptSHA256 string                `json:"substrate_receipt_sha256"`
	ReleaseID              string                `json:"release_id"`
	LiveTreeSHA256         string                `json:"live_tree_sha256"`
	OwnershipPlanSHA256    string                `json:"ownership_plan_sha256"`
	StaticSetSHA256        string                `json:"static_set_sha256"`
	LayoutSHA256           string                `json:"layout_sha256,omitempty"`
	OwnershipEvidence      string                `json:"ownership_evidence"`
	Entries                []AcornFoxLiveEntryV1 `json:"entries"`
}

func acornFoxLiveRoleFor(entry SubstrateEntry) (AcornFoxLiveRole, bool) {
	return acornFoxLiveRoleForOwner(entry.Role)
}

func acornFoxLiveRoleForOwner(role OwnerRole) (AcornFoxLiveRole, bool) {
	switch role {
	case OwnerRoleRoot:
		return AcornFoxLiveRootRole, true
	case OwnerRoleServer:
		return AcornFoxLiveServerRole, true
	case OwnerRoleAgent:
		return AcornFoxLiveAgentRole, true
	case OwnerRoleBuildKit:
		return AcornFoxLiveBuildKitRole, true
	case OwnerRoleCaddy:
		return AcornFoxLiveCaddyRole, true
	case OwnerRoleEdge:
		return AcornFoxLiveEdgeRole, true
	default:
		return "", false
	}
}

func validAcornFoxLiveRole(role AcornFoxLiveRole) bool {
	switch role {
	case AcornFoxLiveRootRole, AcornFoxLiveServerRole, AcornFoxLiveAgentRole, AcornFoxLiveBuildKitRole, AcornFoxLiveCaddyRole, AcornFoxLiveEdgeRole:
		return true
	default:
		return false
	}
}

func acornFoxLiveEntryFor(entry SubstrateEntry) (AcornFoxLiveEntryV1, error) {
	return acornFoxLiveEntryForLayout(acornFoxInstallLayout{mode: acornFoxInstallLayoutTask}, entry)
}

func acornFoxLiveEntryForLayout(layout acornFoxInstallLayout, entry SubstrateEntry) (AcornFoxLiveEntryV1, error) {
	role, ok := acornFoxLiveRoleFor(entry)
	if !ok {
		return AcornFoxLiveEntryV1{}, errors.New("AcornFox live entry role is invalid")
	}
	group, ok := acornFoxLiveRoleForOwner(OwnerRole(entry.Group))
	if !ok {
		return AcornFoxLiveEntryV1{}, errors.New("AcornFox live entry group is invalid")
	}
	observation := "task_root_owner"
	if layout.mode == acornFoxInstallLayoutProduction {
		observation = "role_uid_gid_verified"
	}
	return AcornFoxLiveEntryV1{Path: entry.Path, Kind: entry.Kind, Mode: entry.Mode, Role: role, Group: group, PhysicalOwnerObservation: observation, Size: entry.Size, SHA256: entry.SHA256}, nil
}

func validateAcornFoxLiveEntries(entries []AcornFoxLiveEntryV1) error {
	if len(entries) == 0 || len(entries) > acornFoxSubstrateMaxEntries+1 {
		return errors.New("AcornFox live entry count is invalid")
	}
	for index, entry := range entries {
		if err := validateRelativePath(entry.Path); err != nil || entry.Mode > 0o777 || entry.Mode&0o022 != 0 || entry.Size < 0 || (entry.PhysicalOwnerObservation != "task_root_owner" && entry.PhysicalOwnerObservation != "role_uid_gid_verified") || (entry.Kind != SubstrateEntryFile && entry.Kind != SubstrateEntryDirectory) {
			return errors.New("AcornFox live entry is invalid")
		}
		if !validAcornFoxLiveRole(entry.Role) {
			return errors.New("AcornFox live entry role is invalid")
		}
		if !validAcornFoxLiveRole(entry.Group) {
			return errors.New("AcornFox live entry group is invalid")
		}
		if entry.Kind == SubstrateEntryDirectory {
			if entry.Size != 0 || entry.SHA256 != "" || (entry.Mode != 0o700 && entry.Mode != 0o750 && entry.Mode != 0o755) {
				return errors.New("AcornFox live directory entry is invalid")
			}
		} else if !validSHA(entry.SHA256) || !validAcornFoxSubstrateFileMode(entry.Mode) {
			return errors.New("AcornFox live file entry is invalid")
		}
		if index > 0 && entries[index-1].Path >= entry.Path {
			return errors.New("AcornFox live entries are not sorted")
		}
	}
	return nil
}

func acornFoxLiveDigest(entries []AcornFoxLiveEntryV1) (string, error) {
	if err := validateAcornFoxLiveEntries(entries); err != nil {
		return "", err
	}
	raw, err := json.Marshal(acornFoxLiveTreeEnvelopeV1{SchemaVersion: AcornFoxLiveReceiptV1Schema, Entries: entries})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func acornFoxLiveOwnershipDigest(entries []AcornFoxLiveEntryV1) (string, error) {
	if err := validateAcornFoxLiveEntries(entries); err != nil {
		return "", err
	}
	type ownership struct {
		Path     string           `json:"path"`
		Role     AcornFoxLiveRole `json:"role"`
		Group    AcornFoxLiveRole `json:"group"`
		Physical string           `json:"physical_owner_observation"`
	}
	values := make([]ownership, len(entries))
	for i, entry := range entries {
		values[i] = ownership{entry.Path, entry.Role, entry.Group, entry.PhysicalOwnerObservation}
	}
	raw, err := json.Marshal(struct {
		SchemaVersion int         `json:"schema_version"`
		Entries       []ownership `json:"entries"`
	}{AcornFoxLiveReceiptV1Schema, values})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func acornFoxLiveStaticDigest(entries []AcornFoxLiveEntryV1) (string, error) {
	static := make([]AcornFoxLiveEntryV1, 0, len(entries))
	for _, entry := range entries {
		if entry.Kind == SubstrateEntryFile && (entry.Path == AcornFoxUpgradeHelperPath || entry.Path == "etc/acornfox/Caddyfile" || entry.Path == "etc/acornfox/acornfox-edge.Caddyfile" || entry.Path == "etc/acornfox/acornfox-edge.env" || entry.Path == "etc/acornfox/buildkitd.toml" || len(entry.Path) > len("etc/systemd/system/") && entry.Path[:len("etc/systemd/system/")] == "etc/systemd/system/") {
			static = append(static, entry)
		}
	}
	// The release-specific health helper has no fixed release prefix in this
	// contract; identify it structurally without accepting arbitrary binaries.
	for _, entry := range entries {
		if entry.Kind == SubstrateEntryFile && len(entry.Path) > len("opt/acornfox/releases//bin/acornfox-healthcheck") && hasAcornFoxLiveHealthPath(entry.Path) {
			found := false
			for _, old := range static {
				if old.Path == entry.Path {
					found = true
				}
			}
			if !found {
				static = append(static, entry)
			}
		}
	}
	sort.Slice(static, func(i, j int) bool { return static[i].Path < static[j].Path })
	if len(static) == 0 {
		return "", errors.New("AcornFox live static set is empty")
	}
	raw, err := json.Marshal(acornFoxLiveStaticEnvelopeV1{SchemaVersion: AcornFoxLiveReceiptV1Schema, Entries: static})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func hasAcornFoxLiveHealthPath(path string) bool {
	const suffix = "/bin/acornfox-healthcheck"
	const prefix = "opt/acornfox/releases/"
	return len(path) > len(prefix)+len(suffix) && len(path) >= len(suffix) && path[:len(prefix)] == prefix && path[len(path)-len(suffix):] == suffix
}

func (r AcornFoxLiveReceiptV1) Validate() error {
	if r.SchemaVersion != AcornFoxLiveReceiptV1Schema || (r.State != "task_live_materialized" && r.State != "host_live_materialized") || !validSHA(r.BindingSHA256) || !validSHA(r.SubstrateReceiptSHA256) || !validID(r.ReleaseID) || !validSHA(r.LiveTreeSHA256) || !validSHA(r.OwnershipPlanSHA256) || !validSHA(r.StaticSetSHA256) || (r.LayoutSHA256 != "" && !validSHA(r.LayoutSHA256)) || (r.State == "task_live_materialized" && (r.LayoutSHA256 != "" || r.OwnershipEvidence != "symbolic")) || (r.State == "host_live_materialized" && (r.LayoutSHA256 == "" || r.OwnershipEvidence != "host_uid_gid_verified")) {
		return errors.New("AcornFox live receipt identity is invalid")
	}
	if err := validateAcornFoxLiveEntries(r.Entries); err != nil {
		return err
	}
	if !acornFoxLiveReleaseEntriesMatch(r.ReleaseID, r.Entries) {
		return errors.New("AcornFox live receipt release entries are invalid")
	}
	if tree, err := acornFoxLiveDigest(r.Entries); err != nil || tree != r.LiveTreeSHA256 {
		return errors.New("AcornFox live receipt tree digest is invalid")
	}
	if plan, err := acornFoxLiveOwnershipDigest(r.Entries); err != nil || plan != r.OwnershipPlanSHA256 {
		return errors.New("AcornFox live receipt ownership plan is invalid")
	}
	if static, err := acornFoxLiveStaticDigest(r.Entries); err != nil || static != r.StaticSetSHA256 {
		return errors.New("AcornFox live receipt static set is invalid")
	}
	return nil
}

func acornFoxLiveReleaseEntriesMatch(releaseID string, entries []AcornFoxLiveEntryV1) bool {
	prefix := "opt/acornfox/releases/"
	releasePrefix := prefix + releaseID + "/"
	health, control := false, false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Path, prefix) {
			rest := strings.TrimPrefix(entry.Path, prefix)
			part := strings.SplitN(rest, "/", 2)[0]
			if part != releaseID || (entry.Path != prefix+releaseID && !strings.HasPrefix(entry.Path, releasePrefix)) {
				return false
			}
			if entry.Path == releasePrefix+"bin/acornfox-healthcheck" && entry.Kind == SubstrateEntryFile {
				health = true
			}
		}
		if entry.Path == "var/lib/acornfox/install/releases/"+releaseID+".json" && entry.Kind == SubstrateEntryFile {
			control = true
		}
	}
	return health && control
}

func MarshalAcornFoxLiveReceiptV1(receipt AcornFoxLiveReceiptV1) ([]byte, error) {
	if err := receipt.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(receipt)
}
func ParseAcornFoxLiveReceiptV1(raw []byte) (AcornFoxLiveReceiptV1, error) {
	var receipt AcornFoxLiveReceiptV1
	if err := strictCanonicalJSON(raw, &receipt, "AcornFox live receipt"); err != nil {
		return receipt, err
	}
	if err := receipt.Validate(); err != nil {
		return receipt, fmt.Errorf("AcornFox live receipt: %w", err)
	}
	return receipt, nil
}
