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

// OwnerRole is a fixed role label, never a uid/gid. Receipts deliberately do
// not carry host identity data.
type OwnerRole string

const (
	OwnerRoleRoot        OwnerRole = "root"
	OwnerRoleServer      OwnerRole = "server"
	OwnerRoleAgent       OwnerRole = "agent"
	OwnerRoleBuildKit    OwnerRole = "buildkit"
	OwnerRoleCaddy       OwnerRole = "caddy"
	OwnerRoleEdge        OwnerRole = "edge"
	OwnerRoleHealthcheck OwnerRole = "healthcheck"
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
	if !validAcornFoxStageReceipt(r.CandidateReceipt) {
		return errors.New("AcornFox inactive substrate candidate receipt is invalid")
	}
	for _, digest := range []string{r.ReleaseTreeSHA256, r.InstalledTreeSHA256, r.UpgradeHelperSHA256, r.HealthHelperSHA256} {
		if !digestPattern.MatchString(digest) {
			return errors.New("AcornFox inactive substrate digest is invalid")
		}
	}
	return validateAcornFoxSubstrateEntries(r.Entries)
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
	if entry.Mode > 0o777 || entry.Mode&0o022 != 0 || !validAcornFoxOwnerRole(entry.Role) || entry.Size < 0 || !digestPattern.MatchString(entry.SHA256) {
		return errors.New("metadata is invalid")
	}
	if entry.Kind == SubstrateEntryDirectory && (entry.Size != 0 || entry.Mode != 0o700) {
		return errors.New("directory metadata is invalid")
	}
	return nil
}

func validAcornFoxOwnerRole(role OwnerRole) bool {
	switch role {
	case OwnerRoleRoot, OwnerRoleServer, OwnerRoleAgent, OwnerRoleBuildKit, OwnerRoleCaddy, OwnerRoleEdge, OwnerRoleHealthcheck:
		return true
	default:
		return false
	}
}

func validAcornFoxStageReceipt(receipt AcornFoxStageReceiptV1) bool {
	return receipt.SchemaVersion == 1 && receipt.Product == AcornFoxV1Product && digestPattern.MatchString(receipt.ManifestSHA256) && digestPattern.MatchString(receipt.ArchiveSHA256) && digestPattern.MatchString(receipt.TreeSHA256) && receipt.FileCount > 0
}
