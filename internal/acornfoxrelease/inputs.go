package acornfoxrelease

import (
	"encoding/json"
	"regexp"
)

var (
	goVersionText    = regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`)
	gitVersionText   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	nodeVersionText  = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	npmVersionText   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	fixedBuildPolicy = []string{"build_id_empty", "build_vcs_disabled", "cgo_disabled", "trimpath"}
)

type ToolchainInputsV1 struct {
	SchemaVersion   int      `json:"schema_version"`
	Product         string   `json:"product"`
	Architecture    string   `json:"architecture"`
	GoVersion       string   `json:"go_version"`
	GoBinarySHA256  string   `json:"go_binary_sha256"`
	GitVersion      string   `json:"git_version"`
	GitBinarySHA256 string   `json:"git_binary_sha256"`
	NodeVersion     string   `json:"node_version"`
	NPMVersion      string   `json:"npm_version"`
	BuildPolicy     []string `json:"build_policy"`
}
type RuntimeInputsV1 struct {
	SchemaVersion int           `json:"schema_version"`
	Product       string        `json:"product"`
	Architecture  string        `json:"architecture"`
	Files         []FileEntryV1 `json:"files"`
}
type LicenseInputsV1 struct {
	SchemaVersion int           `json:"schema_version"`
	Product       string        `json:"product"`
	Files         []FileEntryV1 `json:"files"`
}

func (v ToolchainInputsV1) Validate() error {
	if v.SchemaVersion != 1 || v.Product != Product || v.Architecture != Architecture || !goVersionText.MatchString(v.GoVersion) || !digestText.MatchString(v.GoBinarySHA256) || !gitVersionText.MatchString(v.GitVersion) || !digestText.MatchString(v.GitBinarySHA256) || !nodeVersionText.MatchString(v.NodeVersion) || !npmVersionText.MatchString(v.NPMVersion) || len(v.BuildPolicy) != len(fixedBuildPolicy) {
		return ErrInputs
	}
	for i, t := range v.BuildPolicy {
		if t != fixedBuildPolicy[i] {
			return ErrInputs
		}
	}
	return nil
}
func (v ToolchainInputsV1) BuildPolicyTokens() []string {
	return append([]string(nil), v.BuildPolicy...)
}
func (v RuntimeInputsV1) Validate() error {
	if v.SchemaVersion != 1 || v.Product != Product || v.Architecture != Architecture {
		return ErrInputs
	}
	return validateEntries(v.Files)
}
func (v LicenseInputsV1) Validate() error {
	if v.SchemaVersion != 1 || v.Product != Product {
		return ErrInputs
	}
	return validateEntries(v.Files)
}

func CanonicalToolchainInputsV1(v ToolchainInputsV1) ([]byte, error) {
	if v.Validate() != nil {
		return nil, ErrInputs
	}
	return json.Marshal(v)
}
func CanonicalRuntimeInputsV1(v RuntimeInputsV1) ([]byte, error) {
	if v.Validate() != nil {
		return nil, ErrInputs
	}
	return json.Marshal(v)
}
func CanonicalLicenseInputsV1(v LicenseInputsV1) ([]byte, error) {
	if v.Validate() != nil {
		return nil, ErrInputs
	}
	return json.Marshal(v)
}
func ParseToolchainInputsV1(w Witness, raw []byte) (ToolchainInputsV1, error) {
	var v ToolchainInputsV1
	if !w.Valid() || parseCanonical(raw, &v) != nil || v.Validate() != nil || sha256Text(raw) != w.decision.ToolchainSHA256 {
		return v, ErrInputs
	}
	return v, nil
}
func ParseRuntimeInputsV1(w Witness, raw []byte) (RuntimeInputsV1, error) {
	var v RuntimeInputsV1
	if !w.Valid() || parseCanonical(raw, &v) != nil || v.Validate() != nil || sha256Text(raw) != w.decision.RuntimeInputSHA256 {
		return v, ErrInputs
	}
	return v, nil
}
func ParseLicenseInputsV1(w Witness, raw []byte) (LicenseInputsV1, error) {
	var v LicenseInputsV1
	if !w.Valid() || parseCanonical(raw, &v) != nil || v.Validate() != nil || sha256Text(raw) != w.decision.LicenseInputSHA256 {
		return v, ErrInputs
	}
	return v, nil
}
func VerifyRuntimeTree(root string, v RuntimeInputsV1) error {
	if v.Validate() != nil {
		return ErrInputs
	}
	return verifyFileTree(root, v.Files, false, treeLimits{runtimeFileBytes, runtimeTreeBytes})
}
func VerifyLicenseTree(root string, v LicenseInputsV1) error {
	if v.Validate() != nil {
		return ErrInputs
	}
	return verifyFileTree(root, v.Files, false, treeLimits{licenseFileBytes, licenseTreeBytes})
}
