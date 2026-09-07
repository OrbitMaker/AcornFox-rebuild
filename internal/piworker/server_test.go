package piworker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/pirpc"
)

func TestServerStartsOnHandshakeAndRelaysPiRPC(t *testing.T) {
	config := testConfig(t)
	server, err := NewServer(config, t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	started := make(chan pirpc.ProcessConfig, 1)
	process := newFakeRelay()
	server.loadKey = func(_, name string) (string, error) {
		if name != CredentialName {
			t.Fatalf("credential name = %q", name)
		}
		return "credential-value", nil
	}
	server.start = func(_ context.Context, processConfig pirpc.ProcessConfig) (relayProcess, error) {
		started <- processConfig
		return process, nil
	}
	socket, stop := serveTestServer(t, server)
	defer stop()

	select {
	case <-started:
		t.Fatal("Pi started while worker was idle")
	default:
	}
	request := validOpenRequest()
	connection, ready, err := Dial(context.Background(), socket, request, time.Second)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	if ready.RunID != request.RunID {
		t.Fatalf("ready = %#v", ready)
	}
	processConfig := <-started
	assertRestrictedProcessConfig(t, processConfig, request)

	go process.serveOnePrompt()
	transport := pirpc.NewTransport(connection, pirpc.Options{})
	client := pirpc.NewClient(transport)
	accepted, err := client.Prompt(context.Background(), "hello")
	if err != nil || accepted.Command != "prompt" {
		t.Fatalf("Prompt() = %#v, %v", accepted, err)
	}
	_ = transport.Close()
	waitFor(t, time.Second, func() bool { return process.closed() && server.activeChildren() == 0 && !server.active.Load() })
}

func TestServerRejectsSecondClientAndReapsOnConnectionLoss(t *testing.T) {
	config := testConfig(t)
	server, err := NewServer(config, t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	var mu sync.Mutex
	var processes []*fakeRelay
	server.loadKey = func(_, _ string) (string, error) { return "credential", nil }
	server.start = func(_ context.Context, _ pirpc.ProcessConfig) (relayProcess, error) {
		process := newFakeRelay()
		mu.Lock()
		processes = append(processes, process)
		mu.Unlock()
		return process, nil
	}
	socket, stop := serveTestServer(t, server)
	defer stop()

	first, _, err := Dial(context.Background(), socket, validOpenRequest(), time.Second)
	if err != nil {
		t.Fatalf("first Dial() error = %v", err)
	}
	secondRequest := validOpenRequest()
	secondRequest.RunID = "run_second"
	secondRequest.SessionID = "session_second"
	second, _, err := Dial(context.Background(), socket, secondRequest, time.Second)
	if second != nil {
		_ = second.Close()
	}
	var openError *OpenError
	if !errors.As(err, &openError) || openError.Code != "busy" {
		t.Fatalf("second Dial() error = %v", err)
	}
	mu.Lock()
	if len(processes) != 1 {
		t.Fatalf("started process count = %d", len(processes))
	}
	firstProcess := processes[0]
	mu.Unlock()

	_ = first.Close()
	waitFor(t, time.Second, func() bool { return firstProcess.closed() && server.activeChildren() == 0 && !server.active.Load() })

	thirdRequest := validOpenRequest()
	thirdRequest.RunID = "run_third"
	thirdRequest.SessionID = "session_third"
	third, _, err := Dial(context.Background(), socket, thirdRequest, time.Second)
	if err != nil {
		t.Fatalf("third Dial() after reap error = %v", err)
	}
	_ = third.Close()
}

func TestInvalidHandshakeNeverStartsPi(t *testing.T) {
	config := testConfig(t)
	server, err := NewServer(config, t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	started := make(chan struct{}, 1)
	server.start = func(context.Context, pirpc.ProcessConfig) (relayProcess, error) {
		started <- struct{}{}
		return newFakeRelay(), nil
	}
	socket, stop := serveTestServer(t, server)
	defer stop()

	connection, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatalf("net.Dial() error = %v", err)
	}
	_, _ = io.WriteString(connection, "{\"protocol\":\"wrong\",\"type\":\"open\"}\n")
	line, err := bufio.NewReader(connection).ReadBytes('\n')
	_ = connection.Close()
	if err != nil || !strings.Contains(string(line), `"code":"invalid_handshake"`) {
		t.Fatalf("invalid handshake response = %q, %v", line, err)
	}
	select {
	case <-started:
		t.Fatal("Pi started for invalid handshake")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestListenAndServeCreatesRestrictedSocketWithoutIdlePi(t *testing.T) {
	config := testConfig(t)
	directory := shortTempDir(t)
	config.SocketPath = filepath.Join(directory, "worker.sock")
	config.SocketMode = "0660"
	server, err := NewServer(config, t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	started := make(chan struct{}, 1)
	server.start = func(context.Context, pirpc.ProcessConfig) (relayProcess, error) {
		started <- struct{}{}
		return newFakeRelay(), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe(ctx) }()
	waitFor(t, time.Second, func() bool {
		info, statErr := os.Lstat(config.SocketPath)
		return statErr == nil && info.Mode()&os.ModeSocket != 0
	})
	info, err := os.Stat(config.SocketPath)
	if err != nil {
		t.Fatalf("socket stat error = %v", err)
	}
	if info.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %v", info.Mode().Perm())
	}
	select {
	case <-started:
		t.Fatal("idle listener started Pi")
	default:
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ListenAndServe() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ListenAndServe() did not stop")
	}
}

func TestServeCancellationWaitsForOwnedChildReap(t *testing.T) {
	config := testConfig(t)
	server, err := NewServer(config, t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	process := newFakeRelay()
	server.loadKey = func(_, _ string) (string, error) { return "credential", nil }
	server.start = func(context.Context, pirpc.ProcessConfig) (relayProcess, error) { return process, nil }
	socket, stop := serveTestServer(t, server)
	connection, _, err := Dial(context.Background(), socket, validOpenRequest(), time.Second)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer connection.Close()
	stop()
	if !process.closed() || server.activeChildren() != 0 || server.active.Load() {
		t.Fatalf("Serve returned before reap: closed=%v children=%d active=%v", process.closed(), server.activeChildren(), server.active.Load())
	}
}

func TestBusyRejectWorkIsBounded(t *testing.T) {
	config := testConfig(t)
	server, err := NewServer(config, t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	server.loadKey = func(_, _ string) (string, error) { return "credential", nil }
	server.start = func(context.Context, pirpc.ProcessConfig) (relayProcess, error) { return newFakeRelay(), nil }
	socket, stop := serveTestServer(t, server)
	first, _, err := Dial(context.Background(), socket, validOpenRequest(), time.Second)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer first.Close()
	var busyConnections []net.Conn
	for index := 0; index < maxBusyRejectors*3; index++ {
		connection, dialErr := net.Dial("unix", socket)
		if dialErr == nil {
			busyConnections = append(busyConnections, connection)
		}
	}
	waitFor(t, time.Second, func() bool { return len(server.rejectSlots) == maxBusyRejectors })
	server.connectionsMu.Lock()
	tracked := len(server.connections)
	server.connectionsMu.Unlock()
	// One active connection, eight bounded reject handlers, and at most the
	// accept-loop connection currently being closed.
	if tracked > maxBusyRejectors+2 {
		t.Fatalf("tracked connection count = %d", tracked)
	}
	for _, connection := range busyConnections {
		_ = connection.Close()
	}
	_ = first.Close()
	stop()
}

func TestDialPreservesBytesAfterReady(t *testing.T) {
	directory := shortTempDir(t)
	socket := filepath.Join(directory, "buffered.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	request := validOpenRequest()
	go func() {
		connection, _ := listener.Accept()
		defer connection.Close()
		_, _ = bufio.NewReader(connection).ReadBytes('\n')
		_, _ = io.WriteString(connection, `{"protocol":"acornfox.piworker.v1","type":"ready","run_id":"run_1"}`+"\n"+`{"type":"agent_start"}`+"\n")
	}()
	connection, _, err := Dial(context.Background(), socket, request, time.Second)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer connection.Close()
	line, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil || line != "{\"type\":\"agent_start\"}\n" {
		t.Fatalf("buffered Pi frame = %q, %v", line, err)
	}
}

func TestPersistentSessionBindsScopeAndDerivesPath(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	request := validOpenRequest()
	path, err := bindSession(root, request)
	if err != nil {
		t.Fatalf("bindSession() error = %v", err)
	}
	want := filepath.Join(root, request.SessionID+".jsonl")
	if path != want {
		t.Fatalf("session path = %q, want %q", path, want)
	}
	bindingPath := filepath.Join(root, request.SessionID+".scope.json")
	info, err := os.Stat(bindingPath)
	if err != nil {
		t.Fatalf("binding stat error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("binding mode = %v", info.Mode().Perm())
	}
	if _, err := bindSession(root, request); err != nil {
		t.Fatalf("same scope reconnect error = %v", err)
	}
	drifted := request
	drifted.Scope.ApplicationID = "app_other"
	if _, err := bindSession(root, drifted); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("scope drift error = %v", err)
	}
}

func TestConfigAndCredentialInputsAreStrictAndContentFree(t *testing.T) {
	directory := t.TempDir()
	config := testConfig(t)
	raw, _ := json.Marshal(config)
	configPath := filepath.Join(directory, "pi-config")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(configPath)
	if err != nil || loaded.Model != DeepSeekModel {
		t.Fatalf("LoadConfig() = %#v, %v", loaded, err)
	}
	if err := os.WriteFile(configPath, append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(configPath); !errors.Is(err, ErrInvalidConfig) || strings.Contains(err.Error(), configPath) {
		t.Fatalf("unknown-field error = %v", err)
	}
	credentialPath := filepath.Join(directory, CredentialName)
	if err := os.WriteFile(credentialPath, []byte("secret-value\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	value, err := loadCredential(directory, CredentialName)
	if err != nil || value != "secret-value" {
		t.Fatalf("loadCredential() value length/error = %d, %v", len(value), err)
	}
}

func TestSystemdResourceAndPrivilegeBoundary(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "acornfox-pi-worker.service"))
	if err != nil {
		t.Fatal(err)
	}
	unit := string(raw)
	for _, required := range []string{
		"User=acornfox-pi", "Group=acornfox", "LoadCredential=pi-config:", "LoadCredential=deepseek_api_key:",
		"MemoryMax=512M", "CPUQuota=100%", "TasksMax=64", "NoNewPrivileges=yes", "ProtectSystem=strict",
		"CapabilityBoundingSet=", "AmbientCapabilities=", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
		"ReadWritePaths=/var/lib/acornfox/pi /run/acornfox-pi", "KillMode=control-group",
	} {
		if !strings.Contains(unit, required) {
			t.Errorf("systemd unit missing %q", required)
		}
	}
	for _, forbidden := range []string{"User=root", "docker.sock", "database.env", "EnvironmentFile="} {
		if strings.Contains(unit, forbidden) {
			t.Errorf("systemd unit contains forbidden %q", forbidden)
		}
	}
}

func testConfig(t *testing.T) Config {
	t.Helper()
	directory := t.TempDir()
	return Config{
		SchemaVersion: ConfigSchemaVersion, SocketPath: filepath.Join(directory, "worker.sock"), SocketMode: "0660",
		PiBinaryPath: "/opt/acornfox/pi/pi", WorkingDirectory: directory, AgentDirectory: filepath.Join(directory, "agent"),
		PersistSessions: false, CredentialName: CredentialName, Provider: DeepSeekProvider, Model: DeepSeekModel, Thinking: DeepSeekThinking,
		TrustedExtensions: []string{}, EnabledTools: []string{}, HandshakeTimeoutSecond: 1, RunTimeoutSecond: 30, ShutdownTimeoutSecond: 1,
	}
}

func validOpenRequest() OpenRequest {
	return OpenRequest{
		Protocol: ProtocolVersion, Type: "open", RunToken: strings.Repeat("a", 32), RunID: "run_1", SessionID: "session_1",
		Scope: Scope{Kind: "app", ApplicationID: "app_1"},
	}
}

func assertRestrictedProcessConfig(t *testing.T, config pirpc.ProcessConfig, request OpenRequest) {
	t.Helper()
	if config.Provider != DeepSeekProvider || config.Model != DeepSeekModel || config.Thinking != DeepSeekThinking || len(config.TrustedExtensions) != 0 || len(config.EnabledTools) != 0 {
		t.Fatalf("process config restriction = %#v", config)
	}
	if config.SessionDirectory != "" || config.SessionFile != "" {
		t.Fatalf("smoke process unexpectedly persisted a session: %#v", config)
	}
	agentDirectory := filepath.Join(config.WorkingDirectory, "agent")
	wantEnvironment := map[string]string{
		"PATH": "/usr/bin:/bin", "HOME": agentDirectory, "PI_CODING_AGENT_DIR": agentDirectory,
		"DEEPSEEK_API_KEY": "credential-value", "ACORNFOX_PI_RUN_TOKEN": request.RunToken, "ACORNFOX_PI_RUN_ID": request.RunID,
		"ACORNFOX_PI_SESSION_ID": request.SessionID, "ACORNFOX_PI_SCOPE_KIND": "app", "ACORNFOX_PI_APPLICATION_ID": "app_1",
	}
	if len(config.Environment) != len(wantEnvironment) {
		t.Fatalf("Pi environment keys = %#v", config.Environment)
	}
	for key, value := range wantEnvironment {
		if config.Environment[key] != value {
			t.Fatalf("Pi environment %s mismatch", key)
		}
	}
	if _, inherited := config.Environment["CREDENTIALS_DIRECTORY"]; inherited {
		t.Fatal("worker environment leaked into Pi")
	}
}

func serveTestServer(t *testing.T, server *Server) (string, func()) {
	t.Helper()
	directory := shortTempDir(t)
	socket := filepath.Join(directory, "server.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	return socket, func() {
		cancel()
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Error("Serve() did not stop")
		}
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "piworker-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

type fakeRelay struct {
	stdinWriter  *io.PipeWriter
	stdinReader  *io.PipeReader
	stdoutReader *io.PipeReader
	stdoutWriter *io.PipeWriter
	done         chan struct{}
	closeOnce    sync.Once
}

func newFakeRelay() *fakeRelay {
	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	return &fakeRelay{stdinWriter: stdinWriter, stdinReader: stdinReader, stdoutReader: stdoutReader, stdoutWriter: stdoutWriter, done: make(chan struct{})}
}

func (p *fakeRelay) Stdin() io.WriteCloser { return p.stdinWriter }
func (p *fakeRelay) Stdout() io.ReadCloser { return p.stdoutReader }
func (p *fakeRelay) Done() <-chan struct{} { return p.done }
func (p *fakeRelay) Close(context.Context) error {
	p.closeOnce.Do(func() {
		_ = p.stdinWriter.Close()
		_ = p.stdinReader.Close()
		_ = p.stdoutWriter.Close()
		_ = p.stdoutReader.Close()
		close(p.done)
	})
	return nil
}
func (p *fakeRelay) closed() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}
func (p *fakeRelay) serveOnePrompt() {
	line, err := bufio.NewReader(p.stdinReader).ReadBytes('\n')
	if err != nil {
		return
	}
	var command struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	if json.Unmarshal(line, &command) != nil {
		return
	}
	_, _ = io.WriteString(p.stdoutWriter, `{"id":"`+command.ID+`","type":"response","command":"`+command.Type+`","success":true}`+"\n")
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not satisfied")
}
