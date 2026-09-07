// Package piworker provides the single-process Unix-socket boundary between
// the AcornFox control plane and a restricted Pi RPC subprocess.
package piworker

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/pirpc"
)

const (
	ConfigSchemaVersion = 1
	ProtocolVersion     = "acornfox.piworker.v1"
	MaxConfigBytes      = 64 << 10
	MaxHandshakeBytes   = 16 << 10

	DeepSeekProvider = "deepseek"
	DeepSeekModel    = "deepseek-v4-flash"
	DeepSeekThinking = "off"
	CredentialName   = "deepseek_api_key"
)

var (
	ErrInvalidConfig    = errors.New("piworker: invalid configuration")
	ErrInvalidHandshake = errors.New("piworker: invalid handshake")
	ErrScopeMismatch    = errors.New("piworker: session scope mismatch")
	ErrBusy             = errors.New("piworker: worker is busy")
	ErrStartFailed      = errors.New("piworker: Pi start failed")
)

// Config is loaded from the root-controlled systemd pi-config credential.
// It contains no API key or caller-selectable command arguments.
type Config struct {
	SchemaVersion          int      `json:"schema_version"`
	SocketPath             string   `json:"socket_path"`
	SocketMode             string   `json:"socket_mode"`
	PiBinaryPath           string   `json:"pi_binary_path"`
	WorkingDirectory       string   `json:"working_directory"`
	AgentDirectory         string   `json:"agent_directory"`
	PersistSessions        bool     `json:"persist_sessions"`
	SessionRoot            string   `json:"session_root,omitempty"`
	CredentialName         string   `json:"credential_name"`
	Provider               string   `json:"provider"`
	Model                  string   `json:"model"`
	Thinking               string   `json:"thinking"`
	TrustedExtensions      []string `json:"trusted_extensions"`
	EnabledTools           []string `json:"enabled_tools"`
	ToolCallbackSocket     string   `json:"tool_callback_socket,omitempty"`
	HandshakeTimeoutSecond int      `json:"handshake_timeout_seconds"`
	RunTimeoutSecond       int      `json:"run_timeout_seconds"`
	ShutdownTimeoutSecond  int      `json:"shutdown_timeout_seconds"`
}

func (c Config) HandshakeTimeout() time.Duration {
	return time.Duration(c.HandshakeTimeoutSecond) * time.Second
}

func (c Config) RunTimeout() time.Duration {
	return time.Duration(c.RunTimeoutSecond) * time.Second
}

func (c Config) ShutdownTimeout() time.Duration {
	return time.Duration(c.ShutdownTimeoutSecond) * time.Second
}

// LoadConfig reads one regular, non-symlink, bounded JSON file and rejects
// unknown fields. Errors never include its path or content.
func LoadConfig(path string) (Config, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Config{}, ErrInvalidConfig
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxConfigBytes {
		return Config{}, ErrInvalidConfig
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
	if err != nil || len(raw) > MaxConfigBytes {
		return Config{}, ErrInvalidConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, ErrInvalidConfig
	}
	if err := requireJSONEOF(decoder); err != nil || config.Validate() != nil {
		return Config{}, ErrInvalidConfig
	}
	return config, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidConfig
	}
	return nil
}

func (c Config) Validate() error {
	if c.SchemaVersion != ConfigSchemaVersion || c.Provider != DeepSeekProvider || c.Model != DeepSeekModel || c.Thinking != DeepSeekThinking || c.CredentialName != CredentialName {
		return ErrInvalidConfig
	}
	for _, path := range []string{c.SocketPath, c.PiBinaryPath, c.WorkingDirectory, c.AgentDirectory} {
		if !absoluteCleanPath(path) {
			return ErrInvalidConfig
		}
	}
	if c.SocketMode != "0600" && c.SocketMode != "0660" {
		return ErrInvalidConfig
	}
	if c.PersistSessions {
		if !absoluteCleanPath(c.SessionRoot) {
			return ErrInvalidConfig
		}
	} else if c.SessionRoot != "" {
		return ErrInvalidConfig
	}
	if c.ToolCallbackSocket != "" && !absoluteCleanPath(c.ToolCallbackSocket) {
		return ErrInvalidConfig
	}
	seenExtensions := make(map[string]struct{}, len(c.TrustedExtensions))
	for _, extension := range c.TrustedExtensions {
		if !absoluteCleanPath(extension) || filepath.Ext(extension) != ".ts" {
			return ErrInvalidConfig
		}
		if _, exists := seenExtensions[extension]; exists {
			return ErrInvalidConfig
		}
		seenExtensions[extension] = struct{}{}
	}
	seenTools := make(map[string]struct{}, len(c.EnabledTools))
	for _, tool := range c.EnabledTools {
		if !validToolName(tool) {
			return ErrInvalidConfig
		}
		if _, exists := seenTools[tool]; exists {
			return ErrInvalidConfig
		}
		seenTools[tool] = struct{}{}
	}
	if len(c.EnabledTools) > 0 && (len(c.TrustedExtensions) == 0 || c.ToolCallbackSocket == "") {
		return ErrInvalidConfig
	}
	if c.HandshakeTimeoutSecond < 1 || c.HandshakeTimeoutSecond > 30 || c.RunTimeoutSecond < 1 || c.RunTimeoutSecond > 86400 || c.ShutdownTimeoutSecond < 1 || c.ShutdownTimeoutSecond > 30 {
		return ErrInvalidConfig
	}
	return nil
}

func absoluteCleanPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, 0)
}

func validToolName(name string) bool {
	if !strings.HasPrefix(name, "acornfox_") || len(name) > 128 {
		return false
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '_' {
			continue
		}
		return false
	}
	return true
}

func (c Config) processConfig(request OpenRequest, apiKey, sessionFile string) pirpc.ProcessConfig {
	environment := map[string]string{
		"PATH":                       "/usr/bin:/bin",
		"HOME":                       c.AgentDirectory,
		"PI_CODING_AGENT_DIR":        c.AgentDirectory,
		"DEEPSEEK_API_KEY":           apiKey,
		"ACORNFOX_PI_RUN_TOKEN":      request.RunToken,
		"ACORNFOX_PI_RUN_ID":         request.RunID,
		"ACORNFOX_PI_SESSION_ID":     request.SessionID,
		"ACORNFOX_PI_SCOPE_KIND":     request.Scope.Kind,
		"ACORNFOX_PI_APPLICATION_ID": request.Scope.ApplicationID,
	}
	if c.PersistSessions {
		environment["PI_CODING_AGENT_SESSION_DIR"] = c.SessionRoot
	}
	if c.ToolCallbackSocket != "" {
		environment["ACORNFOX_PI_TOOL_SOCKET"] = c.ToolCallbackSocket
	}
	allowedEnvironment := make([]string, 0, len(environment))
	for key := range environment {
		allowedEnvironment = append(allowedEnvironment, key)
	}
	process := pirpc.ProcessConfig{
		BinaryPath: c.PiBinaryPath, WorkingDirectory: c.WorkingDirectory,
		Provider: c.Provider, Model: c.Model, Thinking: c.Thinking,
		AllowedProviders: []string{c.Provider}, AllowedModels: []string{c.Model}, AllowedThinking: []string{c.Thinking},
		TrustedExtensions: c.TrustedExtensions, EnabledTools: c.EnabledTools, AllowedTools: c.EnabledTools,
		Environment: environment, AllowedEnvironmentKeys: allowedEnvironment,
		Paths: pirpc.PathAllowlist{BinaryPaths: []string{c.PiBinaryPath}, WorkingRoots: []string{c.WorkingDirectory}, ExtensionPaths: c.TrustedExtensions},
	}
	if c.PersistSessions {
		process.SessionDirectory = c.SessionRoot
		process.SessionFile = sessionFile
		process.Paths.SessionRoots = []string{c.SessionRoot}
	}
	return process
}
