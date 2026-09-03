package install

import (
	"encoding/json"
	"errors"
)

const AcornFoxHelperContractV1Schema = 1

// HelperContractEvidenceV1 binds an inactive helper result to external
// digests. It intentionally never embeds the binding, manifest, archive, or
// receipt binary whose SHA-256 is referenced, avoiding circular digests.
type HelperContractEvidenceV1 struct {
	SchemaVersion          int    `json:"schema_version"`
	Helper                 string `json:"helper"`
	CandidateReceiptSHA256 string `json:"candidate_receipt_sha256"`
	InputTreeSHA256        string `json:"input_tree_sha256"`
	OutputSHA256           string `json:"output_sha256"`
}

type HelperContractOutputV1 struct {
	SchemaVersion int              `json:"schema_version"`
	Helper        string           `json:"helper"`
	State         string           `json:"state"`
	TreeSHA256    string           `json:"tree_sha256"`
	Entries       []SubstrateEntry `json:"entries"`
}

func (e HelperContractEvidenceV1) Validate() error {
	if e.SchemaVersion != AcornFoxHelperContractV1Schema || !validAcornFoxHelperName(e.Helper) {
		return errors.New("AcornFox helper evidence identity is invalid")
	}
	for _, digest := range []string{e.CandidateReceiptSHA256, e.InputTreeSHA256, e.OutputSHA256} {
		if !digestPattern.MatchString(digest) {
			return errors.New("AcornFox helper evidence digest is invalid")
		}
	}
	return nil
}

func (o HelperContractOutputV1) Validate() error {
	if o.SchemaVersion != AcornFoxHelperContractV1Schema || !validAcornFoxHelperName(o.Helper) || o.State != "inactive_complete" || !digestPattern.MatchString(o.TreeSHA256) {
		return errors.New("AcornFox helper output identity is invalid")
	}
	return validateAcornFoxSubstrateEntries(o.Entries)
}

func ParseHelperContractEvidenceV1(raw []byte) (HelperContractEvidenceV1, error) {
	var evidence HelperContractEvidenceV1
	if err := strictCanonicalJSON(raw, &evidence, "AcornFox helper evidence"); err != nil {
		return HelperContractEvidenceV1{}, err
	}
	if err := evidence.Validate(); err != nil {
		return HelperContractEvidenceV1{}, err
	}
	return evidence, nil
}

func ParseHelperContractOutputV1(raw []byte) (HelperContractOutputV1, error) {
	var output HelperContractOutputV1
	if err := strictCanonicalJSON(raw, &output, "AcornFox helper output"); err != nil {
		return HelperContractOutputV1{}, err
	}
	if err := output.Validate(); err != nil {
		return HelperContractOutputV1{}, err
	}
	return output, nil
}

func MarshalHelperContractEvidenceV1(evidence HelperContractEvidenceV1) ([]byte, error) {
	if err := evidence.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(evidence)
}

func MarshalHelperContractOutputV1(output HelperContractOutputV1) ([]byte, error) {
	if err := output.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(output)
}

func validAcornFoxHelperName(name string) bool {
	return name == "upgrade" || name == "healthcheck"
}
