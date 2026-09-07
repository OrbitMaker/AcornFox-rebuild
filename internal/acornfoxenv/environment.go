// Package acornfoxenv closes the process environment before runtime
// composition reads configuration. The selected embedded identity, rather
// than argv0 or the executable pathname, is the authority for clean mode.
package acornfoxenv

import (
	"errors"
	"os"
	"strings"
)

type Key uint16

const (
	RuntimeMode Key = iota + 1
	ServerAddr
	DatabaseURL
	AgentGatewayAddr
	AuthOrigin
	CandidateListenFD
	M1Enabled
	M2Enabled
	M3Enabled
	M4Enabled
	M4RolloutEnabled
	M5Enabled
	M6Enabled
	AgentDispatchInstanceID
	AgentDispatchNodeID
	SourceUploadRoot
	SourceWorkspaceRoot
	BuildWorkRoot
	LogRoot
	LogMaxFileBytes
	LogMaxTotalBytes
	OCIStoreRoot
	CapacityFixedHostPort
	SecretRoot
	SecretMaterialRoot
	SecretMasterKey
	SourceGitResolvers
	BuildkitCommand
	BuildkitWorker
	BuildkitAddress
	StaticServerBinary
	StaticRuntimeDigest
	RuntimeTaskPrefix
	M2RegistryBaseURL
	CaddyAdminURL
	CaddyListen
	M3Composition
	M3DNSFail
	M3CertFail
	M4AllowLoopbackWebhookFixture
	M4RolloutInterval
	M4LogCollectionInterval
	M5StorageCapacityBytes
	M5StorageHardReserveBytes
	M6WorkspaceRoot
	AgentIdentitiesJSON
	ServerAgentTLSCA
	ServerAgentTLSCert
	ServerAgentTLSKey
	G3ExpectedPublicIP
	G3ConsoleLabel
	G3IngressLabel
	G3AppsLabel
	G3WildcardProbeLabel
	G3PublicDNSResolvers
	SourceUploadMaxTotalBytes
	SourceUploadMaxFileBytes
	SourceUploadMaxFiles
	SourceUploadMaxPathBytes
	SourceUploadMaxManifestBytes
	SourceUploadTTL
	SourceWorkspaceCapacityBytes
	SourceWorkspaceCapacityEntries
	SourceWorkspaceOperationalReserveBytes
	SourceWorkspaceOperationalReserveEntries
	AgentAddr
	InstanceID
	NodeID
	AgentVersion
	ControlPlaneURL
	AgentTLSCA
	AgentTLSCert
	AgentTLSKey
	ControlPlaneServerName
	DockerSocket
	RuntimeEnabled
	WorkerNetworkIsolated
	RuntimeReserveMemoryBytes
	RuntimeWorkRoot
	RuntimeFixedHostPort
	RuntimeNetwork
	RuntimeGroupNetwork
	PublicRoot
	MigrationCompatibility
	AssistantEnabled
	AssistantWorkerSocket
	AssistantToolsSocket
)

type keySpec struct{ legacy, canonical string }

var specs = map[Key]keySpec{
	RuntimeMode:           {canonical: "ACORNFOX_RUNTIME_MODE"},
	AssistantEnabled:      {canonical: "ACORNFOX_ASSISTANT_ENABLED"},
	AssistantWorkerSocket: {canonical: "ACORNFOX_ASSISTANT_WORKER_SOCKET"},
	AssistantToolsSocket:  {canonical: "ACORNFOX_ASSISTANT_TOOLS_SOCKET"},
	ServerAddr:            {"OPEN_CARD_SERVER_ADDR", "ACORNFOX_SERVER_ADDR"}, DatabaseURL: {"OPEN_CARD_DATABASE_URL", "ACORNFOX_DATABASE_URL"}, AgentGatewayAddr: {"OPEN_CARD_AGENT_GATEWAY_ADDR", "ACORNFOX_AGENT_GATEWAY_ADDR"}, AuthOrigin: {"OPEN_CARD_AUTH_ORIGIN", "ACORNFOX_AUTH_ORIGIN"}, CandidateListenFD: {"OPEN_CARD_CANDIDATE_LISTEN_FD", "ACORNFOX_CANDIDATE_LISTEN_FD"},
	M1Enabled: {"OPEN_CARD_M1_ENABLED", "ACORNFOX_M1_ENABLED"}, M2Enabled: {"OPEN_CARD_M2_ENABLED", "ACORNFOX_M2_ENABLED"}, M3Enabled: {"OPEN_CARD_M3_ENABLED", "ACORNFOX_M3_ENABLED"}, M4Enabled: {"OPEN_CARD_M4_ENABLED", "ACORNFOX_M4_ENABLED"}, M4RolloutEnabled: {"OPEN_CARD_M4_ROLLOUT_ENABLED", "ACORNFOX_M4_ROLLOUT_ENABLED"}, M5Enabled: {"OPEN_CARD_M5_ENABLED", "ACORNFOX_M5_ENABLED"}, M6Enabled: {"OPEN_CARD_M6_ENABLED", "ACORNFOX_M6_ENABLED"},
	AgentDispatchInstanceID: {"OPEN_CARD_AGENT_DISPATCH_INSTANCE_ID", "ACORNFOX_AGENT_DISPATCH_INSTANCE_ID"}, AgentDispatchNodeID: {"OPEN_CARD_AGENT_DISPATCH_NODE_ID", "ACORNFOX_AGENT_DISPATCH_NODE_ID"}, SourceUploadRoot: {"OPEN_CARD_SOURCE_UPLOAD_ROOT", "ACORNFOX_SOURCE_UPLOAD_ROOT"}, SourceWorkspaceRoot: {"OPEN_CARD_SOURCE_WORKSPACE_ROOT", "ACORNFOX_SOURCE_WORKSPACE_ROOT"}, BuildWorkRoot: {"OPEN_CARD_BUILD_WORK_ROOT", "ACORNFOX_BUILD_WORK_ROOT"}, LogRoot: {"OPEN_CARD_LOG_ROOT", "ACORNFOX_LOG_ROOT"}, LogMaxFileBytes: {"OPEN_CARD_LOG_MAX_FILE_BYTES", "ACORNFOX_LOG_MAX_FILE_BYTES"}, LogMaxTotalBytes: {"OPEN_CARD_LOG_MAX_TOTAL_BYTES", "ACORNFOX_LOG_MAX_TOTAL_BYTES"}, OCIStoreRoot: {"OPEN_CARD_OCI_STORE_ROOT", "ACORNFOX_OCI_STORE_ROOT"}, CapacityFixedHostPort: {"OPEN_CARD_CAPACITY_FIXED_HOST_PORT", "ACORNFOX_CAPACITY_FIXED_HOST_PORT"}, SecretRoot: {"OPEN_CARD_SECRET_ROOT", "ACORNFOX_SECRET_ROOT"}, SecretMaterialRoot: {"OPEN_CARD_SECRET_MATERIAL_ROOT", "ACORNFOX_SECRET_MATERIAL_ROOT"}, SecretMasterKey: {"OPEN_CARD_SECRET_MASTER_KEY", "ACORNFOX_SECRET_MASTER_KEY"}, SourceGitResolvers: {"OPEN_CARD_SOURCE_GIT_RESOLVERS", "ACORNFOX_SOURCE_GIT_RESOLVERS"}, BuildkitCommand: {"OPEN_CARD_BUILDKIT_COMMAND", "ACORNFOX_BUILDKIT_COMMAND"}, BuildkitWorker: {"OPEN_CARD_BUILDKIT_WORKER", "ACORNFOX_BUILDKIT_WORKER"}, BuildkitAddress: {"OPEN_CARD_BUILDKIT_ADDRESS", "ACORNFOX_BUILDKIT_ADDRESS"}, StaticServerBinary: {"OPEN_CARD_STATIC_SERVER_BINARY", "ACORNFOX_STATIC_SERVER_BINARY"}, StaticRuntimeDigest: {"OPEN_CARD_STATIC_RUNTIME_DIGEST", "ACORNFOX_STATIC_RUNTIME_DIGEST"}, RuntimeTaskPrefix: {"OPEN_CARD_RUNTIME_TASK_PREFIX", "ACORNFOX_RUNTIME_TASK_PREFIX"}, M2RegistryBaseURL: {"OPEN_CARD_M2_REGISTRY_BASE_URL", "ACORNFOX_M2_REGISTRY_BASE_URL"}, CaddyAdminURL: {"OPEN_CARD_CADDY_ADMIN_URL", "ACORNFOX_CADDY_ADMIN_URL"}, CaddyListen: {"OPEN_CARD_CADDY_LISTEN", "ACORNFOX_CADDY_LISTEN"}, M3Composition: {"OPEN_CARD_M3_COMPOSITION", "ACORNFOX_M3_COMPOSITION"}, M3DNSFail: {"OPEN_CARD_M3_DNS_FAIL", "ACORNFOX_M3_DNS_FAIL"}, M3CertFail: {"OPEN_CARD_M3_CERT_FAIL", "ACORNFOX_M3_CERT_FAIL"}, M4AllowLoopbackWebhookFixture: {"OPEN_CARD_M4_ALLOW_LOOPBACK_WEBHOOK_FIXTURE", "ACORNFOX_M4_ALLOW_LOOPBACK_WEBHOOK_FIXTURE"}, M4RolloutInterval: {"OPEN_CARD_M4_ROLLOUT_INTERVAL", "ACORNFOX_M4_ROLLOUT_INTERVAL"}, M4LogCollectionInterval: {"OPEN_CARD_M4_LOG_COLLECTION_INTERVAL", "ACORNFOX_M4_LOG_COLLECTION_INTERVAL"}, M5StorageCapacityBytes: {"OPEN_CARD_M5_STORAGE_CAPACITY_BYTES", "ACORNFOX_M5_STORAGE_CAPACITY_BYTES"}, M5StorageHardReserveBytes: {"OPEN_CARD_M5_STORAGE_HARD_RESERVE_BYTES", "ACORNFOX_M5_STORAGE_HARD_RESERVE_BYTES"}, M6WorkspaceRoot: {"OPEN_CARD_M6_WORKSPACE_ROOT", "ACORNFOX_M6_WORKSPACE_ROOT"}, AgentIdentitiesJSON: {"OPEN_CARD_AGENT_IDENTITIES_JSON", "ACORNFOX_AGENT_IDENTITIES_JSON"}, ServerAgentTLSCA: {"OPEN_CARD_SERVER_AGENT_TLS_CA", "ACORNFOX_SERVER_AGENT_TLS_CA"}, ServerAgentTLSCert: {"OPEN_CARD_SERVER_AGENT_TLS_CERT", "ACORNFOX_SERVER_AGENT_TLS_CERT"}, ServerAgentTLSKey: {"OPEN_CARD_SERVER_AGENT_TLS_KEY", "ACORNFOX_SERVER_AGENT_TLS_KEY"}, G3ExpectedPublicIP: {"OPEN_CARD_G3_EXPECTED_PUBLIC_IP", "ACORNFOX_G3_EXPECTED_PUBLIC_IP"}, G3ConsoleLabel: {"OPEN_CARD_G3_CONSOLE_LABEL", "ACORNFOX_G3_CONSOLE_LABEL"}, G3IngressLabel: {"OPEN_CARD_G3_INGRESS_LABEL", "ACORNFOX_G3_INGRESS_LABEL"}, G3AppsLabel: {"OPEN_CARD_G3_APPS_LABEL", "ACORNFOX_G3_APPS_LABEL"}, G3WildcardProbeLabel: {"OPEN_CARD_G3_WILDCARD_PROBE_LABEL", "ACORNFOX_G3_WILDCARD_PROBE_LABEL"}, G3PublicDNSResolvers: {"OPEN_CARD_G3_PUBLIC_DNS_RESOLVERS", "ACORNFOX_G3_PUBLIC_DNS_RESOLVERS"}, SourceUploadMaxTotalBytes: {"OPEN_CARD_SOURCE_UPLOAD_MAX_TOTAL_BYTES", "ACORNFOX_SOURCE_UPLOAD_MAX_TOTAL_BYTES"}, SourceUploadMaxFileBytes: {"OPEN_CARD_SOURCE_UPLOAD_MAX_FILE_BYTES", "ACORNFOX_SOURCE_UPLOAD_MAX_FILE_BYTES"}, SourceUploadMaxFiles: {"OPEN_CARD_SOURCE_UPLOAD_MAX_FILES", "ACORNFOX_SOURCE_UPLOAD_MAX_FILES"}, SourceUploadMaxPathBytes: {"OPEN_CARD_SOURCE_UPLOAD_MAX_PATH_BYTES", "ACORNFOX_SOURCE_UPLOAD_MAX_PATH_BYTES"}, SourceUploadMaxManifestBytes: {"OPEN_CARD_SOURCE_UPLOAD_MAX_MANIFEST_BYTES", "ACORNFOX_SOURCE_UPLOAD_MAX_MANIFEST_BYTES"}, SourceUploadTTL: {"OPEN_CARD_SOURCE_UPLOAD_TTL", "ACORNFOX_SOURCE_UPLOAD_TTL"}, SourceWorkspaceCapacityBytes: {"OPEN_CARD_SOURCE_WORKSPACE_CAPACITY_BYTES", "ACORNFOX_SOURCE_WORKSPACE_CAPACITY_BYTES"}, SourceWorkspaceCapacityEntries: {"OPEN_CARD_SOURCE_WORKSPACE_CAPACITY_ENTRIES", "ACORNFOX_SOURCE_WORKSPACE_CAPACITY_ENTRIES"}, SourceWorkspaceOperationalReserveBytes: {"OPEN_CARD_SOURCE_WORKSPACE_OPERATIONAL_RESERVE_BYTES", "ACORNFOX_SOURCE_WORKSPACE_OPERATIONAL_RESERVE_BYTES"}, SourceWorkspaceOperationalReserveEntries: {"OPEN_CARD_SOURCE_WORKSPACE_OPERATIONAL_RESERVE_ENTRIES", "ACORNFOX_SOURCE_WORKSPACE_OPERATIONAL_RESERVE_ENTRIES"}, AgentAddr: {"OPEN_CARD_AGENT_ADDR", "ACORNFOX_AGENT_ADDR"}, InstanceID: {"OPEN_CARD_INSTANCE_ID", "ACORNFOX_INSTANCE_ID"}, NodeID: {"OPEN_CARD_NODE_ID", "ACORNFOX_NODE_ID"}, AgentVersion: {"OPEN_CARD_AGENT_VERSION", "ACORNFOX_AGENT_VERSION"}, ControlPlaneURL: {"OPEN_CARD_CONTROL_PLANE_URL", "ACORNFOX_CONTROL_PLANE_URL"}, AgentTLSCA: {"OPEN_CARD_AGENT_TLS_CA", "ACORNFOX_AGENT_TLS_CA"}, AgentTLSCert: {"OPEN_CARD_AGENT_TLS_CERT", "ACORNFOX_AGENT_TLS_CERT"}, AgentTLSKey: {"OPEN_CARD_AGENT_TLS_KEY", "ACORNFOX_AGENT_TLS_KEY"}, ControlPlaneServerName: {"OPEN_CARD_CONTROL_PLANE_SERVER_NAME", "ACORNFOX_CONTROL_PLANE_SERVER_NAME"}, DockerSocket: {"OPEN_CARD_DOCKER_SOCKET", "ACORNFOX_DOCKER_SOCKET"}, RuntimeEnabled: {"OPEN_CARD_RUNTIME_ENABLED", "ACORNFOX_RUNTIME_ENABLED"}, WorkerNetworkIsolated: {"OPEN_CARD_WORKER_NETWORK_ISOLATED", "ACORNFOX_WORKER_NETWORK_ISOLATED"}, RuntimeReserveMemoryBytes: {"OPEN_CARD_RUNTIME_RESERVE_MEMORY_BYTES", "ACORNFOX_RUNTIME_RESERVE_MEMORY_BYTES"}, RuntimeWorkRoot: {"OPEN_CARD_RUNTIME_WORK_ROOT", "ACORNFOX_RUNTIME_WORK_ROOT"}, RuntimeFixedHostPort: {"OPEN_CARD_RUNTIME_FIXED_HOST_PORT", "ACORNFOX_RUNTIME_FIXED_HOST_PORT"}, RuntimeNetwork: {"OPEN_CARD_RUNTIME_NETWORK", "ACORNFOX_RUNTIME_NETWORK"}, RuntimeGroupNetwork: {"OPEN_CARD_RUNTIME_GROUP_NETWORK", "ACORNFOX_RUNTIME_GROUP_NETWORK"},
	PublicRoot: {canonical: "ACORNFOX_PUBLIC_ROOT"}, MigrationCompatibility: {canonical: "ACORNFOX_MIGRATION_COMPATIBILITY"},
}

type Process uint8

const (
	ProcessServer Process = iota + 1
	ProcessAgent
)

type Lookup func(string) (string, bool)
type Environment struct {
	clean  bool
	values map[Key]string
}

func (e Environment) Get(key Key) string { mustSpec(key); return e.values[key] }
func (e Environment) Name(key Key) string {
	spec := mustSpec(key)
	if e.clean || spec.legacy == "" {
		return spec.canonical
	}
	return spec.legacy
}
func (e Environment) ProductLabel() string {
	if e.clean {
		return "AcornFox"
	}
	return "Open Card"
}
func (e Environment) Clean() bool { return e.clean }
func ResolveCurrent(process Process, identity string) (Environment, error) {
	return ResolveEnviron(process, identity, os.Environ())
}

// ResolveEnviron exists so the complete process environment can be captured
// once before policy decisions are made. It is intentionally narrow: callers
// may inject an enumerated environment for deterministic boundary tests.
func ResolveEnviron(process Process, identity string, environ []string) (Environment, error) {
	raw := make(map[string]string, len(environ))
	for _, entry := range environ {
		name, value, found := strings.Cut(entry, "=")
		if !found || name == "" {
			continue
		}
		raw[name] = value
	}
	return resolveSnapshot(process, identity, raw)
}

func Resolve(process Process, identity string, lookup Lookup) (Environment, error) {
	if lookup == nil {
		return Environment{}, cleanError()
	}
	raw := make(map[string]string, len(specs)*2)
	seen := make(map[string]struct{}, len(specs)*2)
	for _, spec := range specs {
		for _, name := range []string{spec.legacy, spec.canonical} {
			if name == "" {
				continue
			}
			if _, alreadyRead := seen[name]; alreadyRead {
				continue
			}
			seen[name] = struct{}{}
			if value, exists := lookup(name); exists {
				raw[name] = value
			}
		}
	}
	return resolveSnapshot(process, identity, raw)
}

func resolveSnapshot(process Process, identity string, raw map[string]string) (Environment, error) {
	if process != ProcessServer && process != ProcessAgent {
		return Environment{}, cleanError()
	}
	clean := identity == "acornfox"
	if !clean && identity != "legacy" {
		return Environment{}, cleanError()
	}
	mode, modeExists := raw[mustSpec(RuntimeMode).canonical]
	if clean {
		if !modeExists || mode != "clean" {
			return Environment{}, cleanError()
		}
		if value, exists := raw[mustSpec(MigrationCompatibility).canonical]; exists && value != "" {
			return Environment{}, cleanError()
		}
		for name := range raw {
			if !knownName(name) && (strings.HasPrefix(name, "OPEN_CARD_") || strings.HasPrefix(name, "ACORNFOX_")) {
				return Environment{}, cleanError()
			}
		}
		for _, spec := range specs {
			if spec.legacy != "" {
				if _, exists := raw[spec.legacy]; exists {
					return Environment{}, cleanError()
				}
			}
		}
	} else if modeExists {
		return Environment{}, cleanError()
	}
	values := make(map[Key]string, len(specs))
	for key, spec := range specs {
		if key == RuntimeMode {
			values[key] = mode
			continue
		}
		name := spec.legacy
		if clean || name == "" {
			name = spec.canonical
		}
		if value, ok := raw[name]; ok {
			values[key] = value
		}
	}
	return Environment{clean: clean, values: values}, nil
}

func knownName(name string) bool {
	for _, spec := range specs {
		if name == spec.legacy || name == spec.canonical {
			return true
		}
	}
	return false
}
func mustSpec(key Key) keySpec {
	spec, ok := specs[key]
	if !ok {
		panic("unknown AcornFox environment key")
	}
	return spec
}
func cleanError() error { return errors.New("AcornFox clean runtime environment is invalid") }
