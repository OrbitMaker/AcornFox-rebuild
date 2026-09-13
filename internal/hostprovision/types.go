package hostprovision

import "errors"

var (
	ErrPrivilegeRequired = errors.New("hostprovision: root privileges required")
	ErrInvalidRequest    = errors.New("hostprovision: invalid request")
	ErrProvisionConflict = errors.New("hostprovision: provisioning conflict or mismatch")
	ErrObserveFailed     = errors.New("hostprovision: backend observation failed")
	ErrInsecurePath      = errors.New("hostprovision: insecure path or ownership")
)

// ProvisionRequest encapsulates the verified release inputs passed to the host provisioner.
// No runtime destination root, state root, IndexURL, key, instance, slot, or executable overrides
// are permitted.
type ProvisionRequest struct {
	BootstrapVersion        string // semver e.g. "1.0.0"
	BootstrapBackendBinding string // hex sha256 of backend binding
	StableBootstrapSource   string // clean absolute path to stable bootstrap binary
	ExpectedBootstrapSHA256 string // expected hex sha256 of stable bootstrap binary
	ManagedC0Source         string // clean absolute path to managed C0 binary
	ExpectedC0SHA256        string // expected hex sha256 of managed C0 binary
	PolicySourcePath        string // clean absolute path to host policy JSON file
	ExpectedPolicySHA256    string // expected hex sha256 of host policy JSON file
}

// ProvisionReceipt contains secret-free bounded verification digests returned on success.
// It contains no public keys, URLs, or private tokens.
type ProvisionReceipt struct {
	InstanceID              string `json:"instance_id"`
	BootstrapID             string `json:"bootstrap_id"`
	BootstrapVersion        string `json:"bootstrap_version"`
	BootstrapBackendBinding string `json:"bootstrap_backend_binding"`
	StableBootstrapSHA256   string `json:"stable_bootstrap_sha256"`
	LauncherSHA256          string `json:"launcher_sha256"`
	ControllerSHA256        string `json:"controller_sha256"`
	ConfigSHA256            string `json:"config_sha256"`
	PolicySHA256            string `json:"policy_sha256"`
}
