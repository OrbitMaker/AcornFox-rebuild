package acornfoxrelease

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"sort"
	"strings"
)

// ErrProductBuildInputs means the immutable inputs for the product-build
// boundary were malformed, drifted, or were paired with the wrong policy.
var ErrProductBuildInputs = errors.New("acornfox product build inputs are invalid")

const (
	productBuildInputsSchemaV1      = 1
	historicalProductArchitectureV1 = "amd64"
)

// ControlledEgressPolicyV1 describes the complete network boundary for the
// download phase. The build phase is deliberately offline and is not a
// configurable exception to this policy.
type ControlledEgressPolicyV1 struct {
	SchemaVersion        int      `json:"schema_version"`
	Product              string   `json:"product"`
	Architecture         string   `json:"architecture"`
	ResolverIPv4         []string `json:"resolver_ipv4"`
	ResolverProtocols    []string `json:"resolver_protocols"`
	ResolverPorts        []int    `json:"resolver_ports"`
	DenyIPv4CIDRs        []string `json:"deny_ipv4_cidrs"`
	DenyIPv6             bool     `json:"deny_ipv6"`
	AllowPublicTCPPorts  []int    `json:"allow_public_ipv4_tcp_ports"`
	DownloadDNSDomains   []string `json:"download_dns_domains"`
	DenyUnexpectedDNS    bool     `json:"deny_unexpected_dns_queries"`
	NoProxy              bool     `json:"no_proxy"`
	NoCredentials        bool     `json:"no_credentials"`
	DenyOtherEgress      bool     `json:"deny_other_egress"`
	DenyIngress          bool     `json:"deny_ingress"`
	OfflineBuildRequired bool     `json:"offline_build_required"`
}

// ProductBuildInputsV1 locks every repository-owned input consumed before a
// guarded builder may be enabled. It contains facts, not a request to build.
type ProductBuildInputsV1 struct {
	SchemaVersion             int                       `json:"schema_version"`
	Product                   string                    `json:"product"`
	Architecture              string                    `json:"architecture"`
	SourceCommit              string                    `json:"source_commit"`
	SourceTree                string                    `json:"source_tree"`
	SourceCommitEpoch         int64                     `json:"source_commit_epoch"`
	TrackedFiles              int                       `json:"tracked_files"`
	TransferArchiveSHA256     string                    `json:"transfer_archive_sha256"`
	LockFiles                 []ProductBuildLockFileV1  `json:"lock_files"`
	Toolchains                []ProductBuildToolchainV1 `json:"toolchains"`
	ControlledEgressPolicySHA string                    `json:"controlled_egress_policy_sha256"`
}

type ProductBuildLockFileV1 struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type ProductBuildToolchainV1 struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	URL               string `json:"url"`
	SHA256            string `json:"sha256"`
	BundledNPMVersion string `json:"bundled_npm_version,omitempty"`
}

var expectedEgressResolversV1 = []string{"1.0.0.1", "1.1.1.1"}
var expectedEgressDenyCIDRsV1 = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.168.0.0/16", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
}
var expectedDownloadDomainsV1 = []string{
	"goproxy.cn", "proxy.golang.org", "registry.npmjs.org", "storage.googleapis.com", "sum.golang.google.cn", "sum.golang.org",
}

func (v ControlledEgressPolicyV1) Validate() error {
	// These records attest the original amd64 product build. They must not
	// follow the CPU of a later release-builder binary.
	if v.SchemaVersion != productBuildInputsSchemaV1 || v.Product != Product || v.Architecture != historicalProductArchitectureV1 || !v.DenyIPv6 || !v.DenyUnexpectedDNS || !v.NoProxy || !v.NoCredentials || !v.DenyOtherEgress || !v.DenyIngress || !v.OfflineBuildRequired {
		return ErrProductBuildInputs
	}
	if !sameSortedStrings(v.ResolverIPv4, expectedEgressResolversV1) || !sameSortedStrings(v.ResolverProtocols, []string{"tcp", "udp"}) || len(v.ResolverPorts) != 1 || v.ResolverPorts[0] != 53 || !sameSortedStrings(v.DenyIPv4CIDRs, expectedEgressDenyCIDRsV1) || !sameSortedStrings(v.DownloadDNSDomains, expectedDownloadDomainsV1) || len(v.AllowPublicTCPPorts) != 2 || v.AllowPublicTCPPorts[0] != 80 || v.AllowPublicTCPPorts[1] != 443 {
		return ErrProductBuildInputs
	}
	return nil
}

func (v ProductBuildInputsV1) Validate() error {
	if v.SchemaVersion != productBuildInputsSchemaV1 || v.Product != Product || v.Architecture != historicalProductArchitectureV1 || v.SourceCommit != "15f3fb979876b6e6ac03b8c6bf68ed9638e4401e" || v.SourceTree != "90211b60c03be63cbb48e51f7c51bd92805fe46b" || v.SourceCommitEpoch != 1788608137 || v.TrackedFiles != 1278 || v.TransferArchiveSHA256 != "c543b62a2254c70ab283c4a9b2c8f4d05b82cb8d517c90cff43e092d2de291b0" || !policyDigestText(v.ControlledEgressPolicySHA) {
		return ErrProductBuildInputs
	}
	if !sameBuildLockFiles(v.LockFiles, expectedBuildLockFilesV1()) || !sameBuildToolchains(v.Toolchains, expectedBuildToolchainsV1()) {
		return ErrProductBuildInputs
	}
	return nil
}

func CanonicalControlledEgressPolicyV1(v ControlledEgressPolicyV1) ([]byte, error) {
	if v.Validate() != nil {
		return nil, ErrProductBuildInputs
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, ErrProductBuildInputs
	}
	return append(raw, '\n'), nil
}

func ControlledEgressPolicyDigestV1(v ControlledEgressPolicyV1) (string, error) {
	raw, err := CanonicalControlledEgressPolicyV1(v)
	if err != nil {
		return "", ErrProductBuildInputs
	}
	return "sha256:" + sha256Text(raw), nil
}

func CanonicalProductBuildInputsV1(v ProductBuildInputsV1) ([]byte, error) {
	if v.Validate() != nil {
		return nil, ErrProductBuildInputs
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, ErrProductBuildInputs
	}
	return append(raw, '\n'), nil
}

// ParseProductBuildInputsV1 accepts only exact canonical files and binds the
// input lock to the bytes of the policy file presented alongside it.
func ParseProductBuildInputsV1(inputsRaw, policyRaw []byte) (ProductBuildInputsV1, ControlledEgressPolicyV1, error) {
	var inputs ProductBuildInputsV1
	var policy ControlledEgressPolicyV1
	if parseCanonicalWithNewline(inputsRaw, &inputs, CanonicalProductBuildInputsV1) != nil || inputs.Validate() != nil || parseCanonicalWithNewline(policyRaw, &policy, CanonicalControlledEgressPolicyV1) != nil || policy.Validate() != nil {
		return inputs, policy, ErrProductBuildInputs
	}
	digest, err := ControlledEgressPolicyDigestV1(policy)
	if err != nil || inputs.ControlledEgressPolicySHA != digest {
		return inputs, policy, ErrProductBuildInputs
	}
	return inputs, policy, nil
}

func parseCanonicalWithNewline[T any](raw []byte, target *T, canonical func(T) ([]byte, error)) error {
	if len(raw) == 0 || len(raw) > maxManifestBytes || raw[len(raw)-1] != '\n' || bytes.Count(raw, []byte{'\n'}) != 1 {
		return ErrProductBuildInputs
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrProductBuildInputs
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrProductBuildInputs
	}
	want, err := canonical(*target)
	if err != nil || !bytes.Equal(raw, want) {
		return ErrProductBuildInputs
	}
	return nil
}

func policyDigestText(v string) bool {
	return strings.HasPrefix(v, "sha256:") && digestText.MatchString(strings.TrimPrefix(v, "sha256:"))
}

func sameSortedStrings(got, want []string) bool {
	return len(got) == len(want) && sort.StringsAreSorted(got) && slicesEqual(got, want)
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func sameBuildLockFiles(got, want []ProductBuildLockFileV1) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] || !validRelativeFile(got[i].Path) || !digestText.MatchString(got[i].SHA256) || (i > 0 && got[i-1].Path >= got[i].Path) {
			return false
		}
	}
	return true
}

func sameBuildToolchains(got, want []ProductBuildToolchainV1) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] || (i > 0 && got[i-1].Name >= got[i].Name) || !validToolchainURL(got[i].URL) || !digestText.MatchString(got[i].SHA256) {
			return false
		}
	}
	return true
}

func validToolchainURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Host == u.Hostname() && u.Hostname() != "" && u.Port() == "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawPath == "" && strings.HasPrefix(u.Path, "/") && !strings.ContainsAny(value, "\r\n\x00")
}

func expectedBuildLockFilesV1() []ProductBuildLockFileV1 {
	return []ProductBuildLockFileV1{
		{Path: "go.mod", SHA256: "a15892c0d65c4e849f9a934482cce8e2de9ef222ab6bf53eb2be0c1dca0b6037"},
		{Path: "go.sum", SHA256: "f371666fda0df0b8312e2bb7148ccb7ab3963d87c0ce2dacf4f3eaf8b5656712"},
		{Path: "web/package-lock.json", SHA256: "b1420c87ff5e4bf0d8bfc23801d0adc8a79477aed65038de60a4c925813bfe4e"},
		{Path: "web/package.json", SHA256: "f91283df87184d0c4579cdd863b81ac5cf21ca9a1e6c384fae6014f5a3a698ba"},
	}
}

func expectedBuildToolchainsV1() []ProductBuildToolchainV1 {
	return []ProductBuildToolchainV1{
		{Name: "go", Version: "go1.25.13", URL: "https://dl.google.com/go/go1.25.13.linux-amd64.tar.gz", SHA256: "39042a078ea9ceebe3ecda4a7188f0f5b96e14a071d27923ba7f40b456e85ae3"},
		{Name: "node", Version: "v22.22.0", URL: "https://nodejs.org/dist/v22.22.0/node-v22.22.0-linux-x64.tar.xz", SHA256: "9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37", BundledNPMVersion: "10.9.4"},
	}
}
