// Package acornfoxenv closes the process environment before AcornFox runtime
// composition reads configuration. It deliberately snapshots a fixed key set.
package acornfoxenv

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type Lookup func(string) (string, bool)

type Environment struct {
	clean  bool
	values map[string]string
}

func (e Environment) Get(key string) string { return e.values[key] }
func (e Environment) Clean() bool           { return e.clean }

var processKeys = []string{
	"OPEN_CARD_SERVER_ADDR", "OPEN_CARD_DATABASE_URL", "OPEN_CARD_AGENT_GATEWAY_ADDR", "OPEN_CARD_AUTH_ORIGIN", "OPEN_CARD_CANDIDATE_LISTEN_FD",
	"OPEN_CARD_M1_ENABLED", "OPEN_CARD_M2_ENABLED", "OPEN_CARD_M3_ENABLED", "OPEN_CARD_M4_ENABLED", "OPEN_CARD_M4_ROLLOUT_ENABLED", "OPEN_CARD_M5_ENABLED", "OPEN_CARD_M6_ENABLED",
	"OPEN_CARD_AGENT_DISPATCH_INSTANCE_ID", "OPEN_CARD_AGENT_DISPATCH_NODE_ID", "OPEN_CARD_SOURCE_UPLOAD_ROOT", "OPEN_CARD_SOURCE_WORKSPACE_ROOT", "OPEN_CARD_BUILD_WORK_ROOT", "OPEN_CARD_LOG_ROOT", "OPEN_CARD_LOG_MAX_FILE_BYTES", "OPEN_CARD_LOG_MAX_TOTAL_BYTES", "OPEN_CARD_OCI_STORE_ROOT", "OPEN_CARD_CAPACITY_FIXED_HOST_PORT", "OPEN_CARD_SECRET_ROOT", "OPEN_CARD_SECRET_MATERIAL_ROOT", "OPEN_CARD_SECRET_MASTER_KEY", "OPEN_CARD_SOURCE_GIT_RESOLVERS", "OPEN_CARD_BUILDKIT_COMMAND", "OPEN_CARD_BUILDKIT_WORKER", "OPEN_CARD_BUILDKIT_ADDRESS", "OPEN_CARD_STATIC_SERVER_BINARY", "OPEN_CARD_STATIC_RUNTIME_DIGEST", "OPEN_CARD_RUNTIME_TASK_PREFIX", "OPEN_CARD_M2_REGISTRY_BASE_URL", "OPEN_CARD_CADDY_ADMIN_URL", "OPEN_CARD_CADDY_LISTEN", "OPEN_CARD_M3_COMPOSITION", "OPEN_CARD_M3_DNS_FAIL", "OPEN_CARD_M3_CERT_FAIL", "OPEN_CARD_M4_ALLOW_LOOPBACK_WEBHOOK_FIXTURE", "OPEN_CARD_M4_ROLLOUT_INTERVAL", "OPEN_CARD_M4_LOG_COLLECTION_INTERVAL", "OPEN_CARD_M5_STORAGE_CAPACITY_BYTES", "OPEN_CARD_M5_STORAGE_HARD_RESERVE_BYTES", "OPEN_CARD_M6_WORKSPACE_ROOT", "OPEN_CARD_AGENT_IDENTITIES_JSON", "OPEN_CARD_SERVER_AGENT_TLS_CA", "OPEN_CARD_SERVER_AGENT_TLS_CERT", "OPEN_CARD_SERVER_AGENT_TLS_KEY", "OPEN_CARD_G3_EXPECTED_PUBLIC_IP", "OPEN_CARD_G3_CONSOLE_LABEL", "OPEN_CARD_G3_INGRESS_LABEL", "OPEN_CARD_G3_APPS_LABEL", "OPEN_CARD_G3_WILDCARD_PROBE_LABEL", "OPEN_CARD_G3_PUBLIC_DNS_RESOLVERS", "OPEN_CARD_SOURCE_UPLOAD_MAX_TOTAL_BYTES", "OPEN_CARD_SOURCE_UPLOAD_MAX_FILE_BYTES", "OPEN_CARD_SOURCE_UPLOAD_MAX_FILES", "OPEN_CARD_SOURCE_UPLOAD_MAX_PATH_BYTES", "OPEN_CARD_SOURCE_UPLOAD_MAX_MANIFEST_BYTES", "OPEN_CARD_SOURCE_UPLOAD_TTL", "OPEN_CARD_SOURCE_WORKSPACE_CAPACITY_BYTES", "OPEN_CARD_SOURCE_WORKSPACE_CAPACITY_ENTRIES", "OPEN_CARD_SOURCE_WORKSPACE_OPERATIONAL_RESERVE_BYTES", "OPEN_CARD_SOURCE_WORKSPACE_OPERATIONAL_RESERVE_ENTRIES",
	"OPEN_CARD_AGENT_ADDR", "OPEN_CARD_INSTANCE_ID", "OPEN_CARD_NODE_ID", "OPEN_CARD_AGENT_VERSION", "OPEN_CARD_CONTROL_PLANE_URL", "OPEN_CARD_AGENT_TLS_CA", "OPEN_CARD_AGENT_TLS_CERT", "OPEN_CARD_AGENT_TLS_KEY", "OPEN_CARD_CONTROL_PLANE_SERVER_NAME", "OPEN_CARD_DOCKER_SOCKET", "OPEN_CARD_RUNTIME_ENABLED", "OPEN_CARD_WORKER_NETWORK_ISOLATED", "OPEN_CARD_RUNTIME_RESERVE_MEMORY_BYTES", "OPEN_CARD_RUNTIME_WORK_ROOT", "OPEN_CARD_RUNTIME_FIXED_HOST_PORT", "OPEN_CARD_RUNTIME_NETWORK", "OPEN_CARD_RUNTIME_GROUP_NETWORK",
	"ACORNFOX_PUBLIC_ROOT", "ACORNFOX_MIGRATION_COMPATIBILITY",
}

func ResolveCurrent() (Environment, error) {
	executable, err := os.Executable()
	if err != nil {
		return Environment{}, cleanError()
	}
	return Resolve(executable, os.LookupEnv)
}

func Resolve(executable string, lookup Lookup) (Environment, error) {
	if lookup == nil {
		return Environment{}, cleanError()
	}
	base := filepath.Base(executable)
	if base != "open-card-server" && base != "open-card-agent" && base != "acornfox-server" && base != "acornfox-agent" {
		return Environment{}, cleanError()
	}
	clean := strings.HasPrefix(base, "acornfox-")
	values := make(map[string]string, len(processKeys))
	if clean {
		mode, ok := lookup("ACORNFOX_RUNTIME_MODE")
		if !ok || mode != "clean" {
			return Environment{}, cleanError()
		}
		if value, ok := lookup("ACORNFOX_MIGRATION_COMPATIBILITY"); ok && value != "" {
			return Environment{}, cleanError()
		}
		for _, key := range processKeys {
			if strings.HasPrefix(key, "OPEN_CARD_") {
				if _, exists := lookup(key); exists {
					return Environment{}, cleanError()
				}
				if value, ok := lookup("ACORNFOX_" + strings.TrimPrefix(key, "OPEN_CARD_")); ok {
					values[key] = value
				}
			} else if value, ok := lookup(key); ok {
				values[key] = value
			}
		}
		return Environment{clean: true, values: values}, nil
	}
	for _, key := range processKeys {
		if value, ok := lookup(key); ok {
			values[key] = value
		}
	}
	return Environment{values: values}, nil
}

func cleanError() error { return errors.New("AcornFox clean runtime environment is invalid") }
