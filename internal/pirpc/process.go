package pirpc

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// PathAllowlist defines the operator-approved executable and storage roots.
// BinaryPaths use exact cleaned matches. WorkingRoots and SessionRoots allow a
// path equal to or below the configured root.
type PathAllowlist struct {
	BinaryPaths    []string
	WorkingRoots   []string
	SessionRoots   []string
	ExtensionPaths []string
}

// ProcessConfig starts only Pi RPC mode. It has no arbitrary argument field.
// Environment is the complete child environment; the ambient service
// environment is not inherited. Every key must also appear in
// AllowedEnvironmentKeys.
type ProcessConfig struct {
	BinaryPath             string
	WorkingDirectory       string
	SessionDirectory       string
	SessionFile            string
	Provider               string
	Model                  string
	Thinking               string
	AllowedProviders       []string
	AllowedModels          []string
	AllowedThinking        []string
	TrustedExtensions      []string
	EnabledTools           []string
	AllowedTools           []string
	Environment            map[string]string
	AllowedEnvironmentKeys []string
	Paths                  PathAllowlist
	Transport              Options
}

// Process owns a Pi subprocess and its stdio transport.
type Process struct {
	Client    *Client
	Transport *Transport
	cmd       *exec.Cmd
	done      chan struct{}
	waitMu    sync.Mutex
	waitErr   error
	closeOnce sync.Once
}

// Start validates operator-controlled paths/environment and launches
// "pi --mode rpc" with a fixed provider/model/thinking selection, disabled
// discovery/default tools, and either --no-session or an explicit session
// directory.
func Start(ctx context.Context, config ProcessConfig) (*Process, error) {
	cmd, err := prepareCommand(ctx, config)
	if err != nil {
		return nil, err
	}
	return startPreparedProcess(cmd, config.Transport)
}

func prepareCommand(ctx context.Context, config ProcessConfig) (*exec.Cmd, error) {
	if err := validateProcessConfig(config); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, filepath.Clean(config.BinaryPath), processArguments(config)...)
	cmd.Dir = filepath.Clean(config.WorkingDirectory)
	cmd.Env = buildEnvironment(config.Environment)
	return cmd, nil
}

func startPreparedProcess(cmd *exec.Cmd, options Options) (*Process, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("pirpc: create stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("pirpc: create stdout pipe: %w", err)
	}
	// Stderr is intentionally discarded. Forwarding raw Pi stderr would make
	// accidental prompt/provider-error logging possible and can deadlock when
	// an unread StderrPipe fills.
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, fmt.Errorf("pirpc: start process: %w", err)
	}
	transport := NewPipeTransport(stdout, stdin, options)
	process := &Process{
		Client: NewClient(transport), Transport: transport, cmd: cmd, done: make(chan struct{}),
	}
	go process.wait()
	return process, nil
}

func (p *Process) wait() {
	err := p.cmd.Wait()
	p.waitMu.Lock()
	if err != nil {
		p.waitErr = ErrProcessExited
	}
	p.waitMu.Unlock()
	if err != nil {
		p.Transport.stop(ErrProcessExited)
	} else {
		p.Transport.stop(nil)
	}
	close(p.done)
}

// Done closes after the child process has been reaped.
func (p *Process) Done() <-chan struct{} { return p.done }

// PID returns the owned child PID for read-only local resource observation.
// It conveys no authority over unrelated processes.
func (p *Process) PID() int {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

// Wait waits for process exit and returns a content-free status.
func (p *Process) Wait(ctx context.Context) error {
	select {
	case <-p.done:
		p.waitMu.Lock()
		defer p.waitMu.Unlock()
		return p.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close closes stdio so Pi can shut down, then waits. If ctx expires, the
// owned child is killed and reaped. It does not claim to provide user, mount,
// network or resource isolation.
func (p *Process) Close(ctx context.Context) error {
	p.closeOnce.Do(func() { _ = p.Transport.Close() })
	select {
	case <-p.done:
		return p.Wait(context.Background())
	case <-ctx.Done():
		_ = p.cmd.Process.Kill()
		<-p.done
		return ctx.Err()
	}
}

func validateProcessConfig(config ProcessConfig) error {
	if !filepath.IsAbs(config.BinaryPath) || !pathExactlyAllowed(config.BinaryPath, config.Paths.BinaryPaths) {
		return errors.New("pirpc: binary path is not allowlisted")
	}
	if !filepath.IsAbs(config.WorkingDirectory) || !pathWithinAllowedRoot(config.WorkingDirectory, config.Paths.WorkingRoots) {
		return errors.New("pirpc: working directory is not allowlisted")
	}
	if config.SessionDirectory != "" && (!filepath.IsAbs(config.SessionDirectory) || !pathWithinAllowedRoot(config.SessionDirectory, config.Paths.SessionRoots)) {
		return errors.New("pirpc: session directory is not allowlisted")
	}
	if config.SessionFile != "" {
		if config.SessionDirectory == "" || !filepath.IsAbs(config.SessionFile) || filepath.Ext(config.SessionFile) != ".jsonl" || !pathWithinAllowedRoot(config.SessionFile, config.Paths.SessionRoots) || filepath.Dir(filepath.Clean(config.SessionFile)) != filepath.Clean(config.SessionDirectory) {
			return errors.New("pirpc: session file is not allowlisted")
		}
	}
	if !exactValueAllowed(config.Provider, config.AllowedProviders) {
		return errors.New("pirpc: provider is not allowlisted")
	}
	if !exactValueAllowed(config.Model, config.AllowedModels) {
		return errors.New("pirpc: model is not allowlisted")
	}
	if !validThinking(config.Thinking) || !exactValueAllowed(config.Thinking, config.AllowedThinking) {
		return errors.New("pirpc: thinking level is not allowlisted")
	}
	for _, extension := range config.TrustedExtensions {
		if !filepath.IsAbs(extension) || !pathExactlyAllowed(extension, config.Paths.ExtensionPaths) {
			return errors.New("pirpc: extension path is not allowlisted")
		}
	}
	seenTools := make(map[string]struct{}, len(config.EnabledTools))
	for _, tool := range config.EnabledTools {
		if !strings.HasPrefix(tool, "acornfox_") || !exactValueAllowed(tool, config.AllowedTools) {
			return errors.New("pirpc: enabled tool is not allowlisted")
		}
		if _, duplicate := seenTools[tool]; duplicate {
			return errors.New("pirpc: enabled tool is duplicated")
		}
		seenTools[tool] = struct{}{}
	}
	if len(config.EnabledTools) > 0 && len(config.TrustedExtensions) == 0 {
		return errors.New("pirpc: enabled tools require a trusted extension")
	}
	allowedEnvironment := make(map[string]struct{}, len(config.AllowedEnvironmentKeys))
	for _, key := range config.AllowedEnvironmentKeys {
		if !validEnvironmentKey(key) {
			return errors.New("pirpc: invalid environment allowlist key")
		}
		allowedEnvironment[key] = struct{}{}
	}
	for key := range config.Environment {
		if !validEnvironmentKey(key) {
			return errors.New("pirpc: invalid environment key")
		}
		if _, ok := allowedEnvironment[key]; !ok {
			return errors.New("pirpc: environment key is not allowlisted")
		}
	}
	return nil
}

func processArguments(config ProcessConfig) []string {
	args := []string{
		"--mode", "rpc",
		"--provider", config.Provider,
		"--model", config.Model,
		"--thinking", config.Thinking,
		"--no-tools",
		"--no-extensions",
		"--no-skills",
		"--no-prompt-templates",
		"--no-themes",
		"--no-context-files",
		"--no-approve",
	}
	for _, extension := range config.TrustedExtensions {
		// Pi v0.85.1 documents that explicit --extension paths still load
		// while --no-extensions disables discovery.
		args = append(args, "--extension", filepath.Clean(extension))
	}
	if len(config.EnabledTools) > 0 {
		// Pi v0.85.1 gives an explicit --tools allowlist precedence over
		// --no-tools, so no built-in tool becomes active here.
		args = append(args, "--tools", strings.Join(config.EnabledTools, ","))
	}
	if config.SessionFile != "" {
		return append(args, "--session", filepath.Clean(config.SessionFile), "--session-dir", filepath.Clean(config.SessionDirectory))
	}
	if config.SessionDirectory == "" {
		return append(args, "--no-session")
	}
	return append(args, "--session-dir", filepath.Clean(config.SessionDirectory))
}

func exactValueAllowed(value string, allowed []string) bool {
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func validThinking(value string) bool {
	switch value {
	case "off", "minimal", "low", "medium", "high", "xhigh", "max":
		return true
	default:
		return false
	}
}

func pathExactlyAllowed(path string, allowed []string) bool {
	path = filepath.Clean(path)
	for _, candidate := range allowed {
		if filepath.IsAbs(candidate) && path == filepath.Clean(candidate) {
			return true
		}
	}
	return false
}

func pathWithinAllowedRoot(path string, roots []string) bool {
	path = filepath.Clean(path)
	for _, root := range roots {
		if !filepath.IsAbs(root) {
			continue
		}
		root = filepath.Clean(root)
		relative, err := filepath.Rel(root, path)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func validEnvironmentKey(key string) bool {
	if key == "" || strings.ContainsRune(key, '=') || strings.IndexByte(key, 0) >= 0 {
		return false
	}
	return true
}

func buildEnvironment(environment map[string]string) []string {
	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+environment[key])
	}
	return result
}
