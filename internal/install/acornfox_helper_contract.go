package install

import (
	"encoding/json"
	"errors"
	"regexp"
)

const AcornFoxHelperContractV1Schema = 1

type AcornFoxBuildIdentityV1 struct {
	SchemaVersion int    `json:"schema_version"`
	Product       string `json:"product"`
	LayoutVersion int    `json:"layout_version"`
	Role          string `json:"role"`
	Version       string `json:"version"`
	ReleaseID     string `json:"release_id"`
	SourceCommit  string `json:"source_commit"`
}

func (i AcornFoxBuildIdentityV1) Validate() error {
	if i.SchemaVersion != AcornFoxHelperContractV1Schema || i.Product != AcornFoxV1Product || i.LayoutVersion != AcornFoxSubstrateLayoutV1 || (i.Role != "upgrade" && i.Role != "healthcheck") || ParseVersion(i.Version) != nil || i.ReleaseID != "release-"+i.Version || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(i.SourceCommit) {
		return errors.New("AcornFox build identity is invalid")
	}
	return nil
}

type AcornFoxHelperContractResultV1 struct {
	SchemaVersion          int                     `json:"schema_version"`
	OK                     bool                    `json:"ok"`
	Code                   string                  `json:"code"`
	Identity               AcornFoxBuildIdentityV1 `json:"identity"`
	BindingSHA256          string                  `json:"binding_sha256"`
	ExecutableSHA256       string                  `json:"executable_sha256"`
	SubstrateReceiptSHA256 string                  `json:"substrate_receipt_sha256"`
}

func (r AcornFoxHelperContractResultV1) Validate() error {
	if r.SchemaVersion != AcornFoxHelperContractV1Schema || r.Identity.Validate() != nil || !digestPattern.MatchString(r.BindingSHA256) || !digestPattern.MatchString(r.ExecutableSHA256) || !digestPattern.MatchString(r.SubstrateReceiptSHA256) || r.Code == "" {
		return errors.New("AcornFox helper contract result is invalid")
	}
	if r.OK && r.Code != "ok" {
		return errors.New("AcornFox successful helper result code is invalid")
	}
	if !r.OK && r.Code == "ok" {
		return errors.New("AcornFox failed helper result code is invalid")
	}
	return nil
}

func ParseAcornFoxHelperContractResultV1(raw []byte) (AcornFoxHelperContractResultV1, error) {
	var result AcornFoxHelperContractResultV1
	if err := strictCanonicalJSON(raw, &result, "AcornFox helper contract result"); err != nil {
		return AcornFoxHelperContractResultV1{}, err
	}
	return result, result.Validate()
}

func MarshalAcornFoxHelperContractResultV1(result AcornFoxHelperContractResultV1) ([]byte, error) {
	if err := result.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
