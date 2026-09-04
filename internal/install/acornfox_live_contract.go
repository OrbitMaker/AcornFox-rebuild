package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
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

type AcornFoxLiveModeledUserV1 struct {
	Role AcornFoxLiveRole `json:"role"`
	UID  int              `json:"uid"`
}
type AcornFoxLiveModeledGroupV1 struct {
	Role AcornFoxLiveRole `json:"role"`
	GID  int              `json:"gid"`
}

// AcornFoxLiveEntryV1 contains the requested modeled identity and the only
// honest physical observation available in task-root preparation: the entry
// is owned by the task-root owner.  It deliberately carries no host uid/gid.
type AcornFoxLiveEntryV1 struct {
	Path                     string                     `json:"path"`
	Kind                     SubstrateEntryKind         `json:"kind"`
	Mode                     uint32                     `json:"mode"`
	Role                     AcornFoxLiveRole           `json:"role"`
	Group                    AcornFoxLiveRole           `json:"group"`
	RequestedModeledUser     AcornFoxLiveModeledUserV1  `json:"requested_modeled_user"`
	RequestedModeledGroup    AcornFoxLiveModeledGroupV1 `json:"requested_modeled_group"`
	PhysicalOwnerObservation string                     `json:"physical_owner_observation"`
	Size                     int64                      `json:"size"`
	SHA256                   string                     `json:"sha256"`
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
	OwnershipEvidence      string                `json:"ownership_evidence"`
	Entries                []AcornFoxLiveEntryV1 `json:"entries"`
}

func acornFoxLiveModeledUser(role AcornFoxLiveRole) (AcornFoxLiveModeledUserV1, bool) {
	// The values are a protocol namespace, not a claim about host accounts.
	ids := map[AcornFoxLiveRole]int{
		AcornFoxLiveRootRole: 0, AcornFoxLiveServerRole: 10001,
		AcornFoxLiveAgentRole: 10002, AcornFoxLiveBuildKitRole: 10003,
		AcornFoxLiveCaddyRole: 10004, AcornFoxLiveEdgeRole: 10005,
	}
	id, ok := ids[role]
	return AcornFoxLiveModeledUserV1{Role: role, UID: id}, ok
}
func acornFoxLiveModeledGroup(role AcornFoxLiveRole) (AcornFoxLiveModeledGroupV1, bool) {
	ids := map[AcornFoxLiveRole]int{AcornFoxLiveRootRole: 0, AcornFoxLiveServerRole: 11001, AcornFoxLiveAgentRole: 11002, AcornFoxLiveBuildKitRole: 11003, AcornFoxLiveCaddyRole: 11004, AcornFoxLiveEdgeRole: 11005}
	id, ok := ids[role]
	return AcornFoxLiveModeledGroupV1{Role: role, GID: id}, ok
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

func acornFoxLiveEntryFor(entry SubstrateEntry) (AcornFoxLiveEntryV1, error) {
	role, ok := acornFoxLiveRoleFor(entry)
	if !ok {
		return AcornFoxLiveEntryV1{}, errors.New("AcornFox live entry role is invalid")
	}
	user, ok := acornFoxLiveModeledUser(role)
	if !ok {
		return AcornFoxLiveEntryV1{}, errors.New("AcornFox live modeled identity is invalid")
	}
	group, ok := acornFoxLiveRoleForOwner(OwnerRole(entry.Group))
	if !ok {
		return AcornFoxLiveEntryV1{}, errors.New("AcornFox live entry group is invalid")
	}
	modeledGroup, ok := acornFoxLiveModeledGroup(group)
	if !ok {
		return AcornFoxLiveEntryV1{}, errors.New("AcornFox live modeled group is invalid")
	}
	return AcornFoxLiveEntryV1{Path: entry.Path, Kind: entry.Kind, Mode: entry.Mode, Role: role, Group: group, RequestedModeledUser: user, RequestedModeledGroup: modeledGroup, PhysicalOwnerObservation: "task_root_owner", Size: entry.Size, SHA256: entry.SHA256}, nil
}

func validateAcornFoxLiveEntries(entries []AcornFoxLiveEntryV1) error {
	if len(entries) == 0 || len(entries) > acornFoxSubstrateMaxEntries+1 {
		return errors.New("AcornFox live entry count is invalid")
	}
	for index, entry := range entries {
		if err := validateRelativePath(entry.Path); err != nil || entry.Mode > 0o777 || entry.Mode&0o022 != 0 || entry.Size < 0 || entry.PhysicalOwnerObservation != "task_root_owner" || (entry.Kind != SubstrateEntryFile && entry.Kind != SubstrateEntryDirectory) {
			return errors.New("AcornFox live entry is invalid")
		}
		user, ok := acornFoxLiveModeledUser(entry.Role)
		if !ok || user != entry.RequestedModeledUser {
			return errors.New("AcornFox live entry modeled identity is invalid")
		}
		group, ok := acornFoxLiveModeledGroup(entry.Group)
		if !ok || group != entry.RequestedModeledGroup {
			return errors.New("AcornFox live entry modeled group is invalid")
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
		Path          string                     `json:"path"`
		Role          AcornFoxLiveRole           `json:"role"`
		Group         AcornFoxLiveRole           `json:"group"`
		User          AcornFoxLiveModeledUserV1  `json:"requested_modeled_user"`
		GroupIdentity AcornFoxLiveModeledGroupV1 `json:"requested_modeled_group"`
		Physical      string                     `json:"physical_owner_observation"`
	}
	values := make([]ownership, len(entries))
	for i, entry := range entries {
		values[i] = ownership{entry.Path, entry.Role, entry.Group, entry.RequestedModeledUser, entry.RequestedModeledGroup, entry.PhysicalOwnerObservation}
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
	if r.SchemaVersion != AcornFoxLiveReceiptV1Schema || r.State != "task_live_materialized" || !validSHA(r.BindingSHA256) || !validSHA(r.SubstrateReceiptSHA256) || !validID(r.ReleaseID) || !validSHA(r.LiveTreeSHA256) || !validSHA(r.OwnershipPlanSHA256) || !validSHA(r.StaticSetSHA256) || r.OwnershipEvidence != "modeled" {
		return errors.New("AcornFox live receipt identity is invalid")
	}
	if err := validateAcornFoxLiveEntries(r.Entries); err != nil {
		return err
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
