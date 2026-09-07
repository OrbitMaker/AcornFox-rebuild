package pirpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPromptAcceptanceAndAgentEndAreDistinct(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	transport := NewTransport(clientConn, Options{})
	defer transport.Close()
	client := NewClient(transport)
	subscription := client.Subscribe()
	defer subscription.Close()

	serverErrors := make(chan error, 1)
	go func() {
		command, err := readCommand(serverConn)
		if err != nil {
			serverErrors <- err
			return
		}
		if command.Type != "prompt" || command.Message != "hello" {
			serverErrors <- fmt.Errorf("unexpected command: %#v", command)
			return
		}
		if _, err := fmt.Fprintf(serverConn, `{"id":%q,"type":"response","command":"prompt","success":true}`+"\n", command.ID); err != nil {
			serverErrors <- err
			return
		}
		if _, err := io.WriteString(serverConn, "{\"type\":\"agent_end\",\"messages\":[],\"willRetry\":false}\n{\"type\":\"agent_settled\"}\n"); err != nil {
			serverErrors <- err
			return
		}
		serverErrors <- nil
	}()

	accepted, err := client.Prompt(context.Background(), "hello")
	if err != nil {
		t.Fatalf("Prompt() error = %v", err)
	}
	if accepted.Command != "prompt" || accepted.RequestID == "" {
		t.Fatalf("acceptance = %#v", accepted)
	}
	if event := receiveEvent(t, subscription); event.Type != EventAgentEnd {
		t.Fatalf("first event = %#v", event)
	}
	if event := receiveEvent(t, subscription); event.Type != EventAgentSettled {
		t.Fatalf("second event = %#v", event)
	}
	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
}

func TestStrictLFAllowsLiteralUnicodeLineSeparator(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	transport := NewTransport(clientConn, Options{})
	defer transport.Close()
	subscription := transport.Subscribe()
	defer subscription.Close()

	go func() {
		_, _ = io.WriteString(serverConn, "{\"type\":\"message_update\",\"usage\":{},\"assistantMessageEvent\":{\"type\":\"text_delta\",\"contentIndex\":0,\"delta\":\"before\u2028after\"}}\n")
	}()
	event := receiveEvent(t, subscription)
	if event.Text != "before\u2028after" || event.DeltaType != DeltaText {
		t.Fatalf("event = %#v", event)
	}
}

func TestFrameAbove64KiBAndConfiguredLimit(t *testing.T) {
	t.Run("accepted below configured limit", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		transport := NewTransport(clientConn, Options{MaxFrameBytes: 256 << 10, MaxTextBytes: 256 << 10})
		defer transport.Close()
		subscription := transport.Subscribe()
		defer subscription.Close()
		text := strings.Repeat("x", 80<<10)
		go func() {
			frame, _ := json.Marshal(map[string]any{
				"type": "message_update", "usage": map[string]any{},
				"assistantMessageEvent": map[string]any{"type": "text_delta", "contentIndex": 0, "delta": text},
			})
			_, _ = serverConn.Write(append(frame, '\n'))
		}()
		if event := receiveEvent(t, subscription); event.Text != text || event.Truncated {
			t.Fatalf("large event length/truncation = %d/%v", len(event.Text), event.Truncated)
		}
	})

	t.Run("rejected above configured limit", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		transport := NewTransport(clientConn, Options{MaxFrameBytes: 1024})
		defer transport.Close()
		go func() {
			_, _ = io.WriteString(serverConn, strings.Repeat("x", 2048)+"\n")
		}()
		select {
		case <-transport.Done():
			if !errors.Is(transport.Err(), ErrFrameTooLarge) {
				t.Fatalf("transport error = %v", transport.Err())
			}
		case <-time.After(time.Second):
			t.Fatal("transport did not reject oversized frame")
		}
	})
}

func TestWrongIDFailsClosedAndEOFWakesOutstandingRequest(t *testing.T) {
	t.Run("wrong id", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		transport := NewTransport(clientConn, Options{})
		defer transport.Close()
		client := NewClient(transport)
		go func() {
			_, _ = readCommand(serverConn)
			_, _ = io.WriteString(serverConn, "{\"id\":\"wrong\",\"type\":\"response\",\"command\":\"get_state\",\"success\":true,\"data\":{}}\n")
		}()
		_, err := client.GetState(context.Background())
		if !errors.Is(err, ErrProtocol) {
			t.Fatalf("GetState() error = %v", err)
		}
	})

	t.Run("eof", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		transport := NewTransport(clientConn, Options{})
		defer transport.Close()
		client := NewClient(transport)
		go func() {
			_, _ = readCommand(serverConn)
			_ = serverConn.Close()
		}()
		_, err := client.Prompt(context.Background(), "waiting")
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Prompt() error = %v", err)
		}
	})
}

func TestAbortClearsQueueFirst(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	transport := NewTransport(clientConn, Options{})
	defer transport.Close()
	client := NewClient(transport)

	serverErrors := make(chan error, 1)
	go func() {
		clearCommand, err := readCommand(serverConn)
		if err != nil {
			serverErrors <- err
			return
		}
		if clearCommand.Type != "clear_queue" {
			serverErrors <- fmt.Errorf("first command = %s", clearCommand.Type)
			return
		}
		_, _ = fmt.Fprintf(serverConn, `{"id":%q,"type":"response","command":"clear_queue","success":true,"data":{"steering":["s"],"followUp":["f"]}}`+"\n", clearCommand.ID)
		abortCommand, err := readCommand(serverConn)
		if err != nil {
			serverErrors <- err
			return
		}
		if abortCommand.Type != "abort" {
			serverErrors <- fmt.Errorf("second command = %s", abortCommand.Type)
			return
		}
		_, _ = fmt.Fprintf(serverConn, `{"id":%q,"type":"response","command":"abort","success":true}`+"\n", abortCommand.ID)
		serverErrors <- nil
	}()

	cleared, accepted, err := client.Abort(context.Background())
	if err != nil {
		t.Fatalf("Abort() error = %v", err)
	}
	if strings.Join(cleared.Steering, "") != "s" || strings.Join(cleared.FollowUp, "") != "f" || accepted.Command != "abort" {
		t.Fatalf("Abort() = %#v, %#v", cleared, accepted)
	}
	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentCallsAndSlowSubscriberDoNotBlock(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	transport := NewTransport(clientConn, Options{EventQueue: 1, MaxPending: 32})
	defer transport.Close()
	client := NewClient(transport)
	slow := transport.Subscribe()
	healthy := transport.Subscribe()
	defer healthy.Close()

	healthyEvents := make(chan []Event, 1)
	healthyConsumed := make(chan struct{}, 3)
	go func() {
		var events []Event
		for len(events) < 3 {
			select {
			case event, ok := <-healthy.Events:
				if !ok {
					healthyEvents <- events
					return
				}
				events = append(events, event)
				healthyConsumed <- struct{}{}
			case <-time.After(time.Second):
				healthyEvents <- events
				return
			}
		}
		healthyEvents <- events
	}()

	const calls = 12
	serverErrors := make(chan error, 1)
	go func() {
		for index := 0; index < 3; index++ {
			if _, err := io.WriteString(serverConn, "{\"type\":\"agent_start\"}\n"); err != nil {
				serverErrors <- err
				return
			}
			<-healthyConsumed
		}
		for index := 0; index < calls; index++ {
			command, err := readCommand(serverConn)
			if err != nil {
				serverErrors <- err
				return
			}
			if _, err := fmt.Fprintf(serverConn, `{"id":%q,"type":"response","command":%q,"success":true}`+"\n", command.ID, command.Type); err != nil {
				serverErrors <- err
				return
			}
		}
		serverErrors <- nil
	}()

	var wait sync.WaitGroup
	errorsByCall := make(chan error, calls)
	for index := 0; index < calls; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, err := client.Prompt(context.Background(), fmt.Sprintf("message-%d", index))
			errorsByCall <- err
		}(index)
	}
	wait.Wait()
	close(errorsByCall)
	for err := range errorsByCall {
		if err != nil {
			t.Fatalf("concurrent Prompt() error = %v", err)
		}
	}
	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-slow.Done:
		if !errors.Is(err, ErrSubscriberSlow) {
			t.Fatalf("slow subscriber error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("slow subscriber was not detached")
	}
	if events := <-healthyEvents; len(events) != 3 {
		t.Fatalf("healthy subscriber received %d events", len(events))
	}
}

func TestContextCancellationAndShutdown(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	transport := NewTransport(clientConn, Options{})
	client := NewClient(transport)
	commandRead := make(chan struct{})
	go func() {
		_, _ = readCommand(serverConn)
		close(commandRead)
		_, _ = readCommand(serverConn)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.Prompt(ctx, "cancel me")
		result <- err
	}()
	<-commandRead
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Prompt() error = %v", err)
	}
	if err := transport.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-transport.Done():
	case <-time.After(time.Second):
		t.Fatal("transport did not shut down")
	}
}

func TestExtensionUICorrelation(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	transport := NewTransport(clientConn, Options{})
	defer transport.Close()
	client := NewClient(transport)
	subscription := client.Subscribe()
	defer subscription.Close()

	serverErrors := make(chan error, 1)
	go func() {
		if _, err := io.WriteString(serverConn, "{\"type\":\"extension_ui_request\",\"id\":\"ui-1\",\"method\":\"confirm\",\"title\":\"Proceed?\",\"message\":\"Check\"}\n"); err != nil {
			serverErrors <- err
			return
		}
		command, err := readCommand(serverConn)
		if err != nil {
			serverErrors <- err
			return
		}
		if command.Type != "extension_ui_response" || command.ID != "ui-1" || command.Confirmed == nil || !*command.Confirmed {
			serverErrors <- fmt.Errorf("UI response = %#v", command)
			return
		}
		serverErrors <- nil
	}()

	event := receiveEvent(t, subscription)
	if event.UI == nil || event.UI.ID != "ui-1" || event.UI.Method != UIConfirm {
		t.Fatalf("UI event = %#v", event)
	}
	if err := client.RespondUIConfirm(context.Background(), "unknown", true); !errors.Is(err, ErrUIRequest) {
		t.Fatalf("unknown response error = %v", err)
	}
	if err := client.RespondUIConfirm(context.Background(), "ui-1", true); err != nil {
		t.Fatalf("RespondUIConfirm() error = %v", err)
	}
	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
}

func TestUnknownEventAndRejectedCommandFailWithoutRawContent(t *testing.T) {
	t.Run("unknown event", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		transport := NewTransport(clientConn, Options{})
		defer transport.Close()
		go func() { _, _ = io.WriteString(serverConn, "{\"type\":\"future_event\",\"secret\":\"do-not-copy\"}\n") }()
		<-transport.Done()
		if !errors.Is(transport.Err(), ErrProtocol) || strings.Contains(transport.Err().Error(), "do-not-copy") {
			t.Fatalf("transport error = %v", transport.Err())
		}
	})

	t.Run("command rejection", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		transport := NewTransport(clientConn, Options{})
		defer transport.Close()
		client := NewClient(transport)
		go func() {
			command, _ := readCommand(serverConn)
			_, _ = fmt.Fprintf(serverConn, `{"id":%q,"type":"response","command":"prompt","success":false,"error":"secret prompt body"}`+"\n", command.ID)
		}()
		_, err := client.Prompt(context.Background(), "sensitive")
		if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "sensitive") {
			t.Fatalf("Prompt() error = %v", err)
		}
	})
}

func TestSafeStateAndMessageProjections(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	transport := NewTransport(clientConn, Options{})
	defer transport.Close()
	client := NewClient(transport)
	go func() {
		stateCommand, _ := readCommand(serverConn)
		_, _ = fmt.Fprintf(serverConn, `{"id":%q,"type":"response","command":"get_state","success":true,"data":{"model":{"apiKey":"must-not-project"},"thinkingLevel":"off","isStreaming":false,"isCompacting":false,"steeringMode":"one-at-a-time","followUpMode":"one-at-a-time","sessionFile":"/private/session.jsonl","sessionId":"session-1","sessionName":"smoke","autoCompactionEnabled":true,"messageCount":1,"pendingMessageCount":0}}`+"\n", stateCommand.ID)
		messagesCommand, _ := readCommand(serverConn)
		_, _ = fmt.Fprintf(serverConn, `{"id":%q,"type":"response","command":"get_messages","success":true,"data":{"messages":[{"role":"assistant","content":[{"type":"text","text":"visible"},{"type":"thinking","thinking":"private"},{"type":"toolCall","id":"c","name":"x","arguments":{"token":"private"}}],"stopReason":"stop"}]}}`+"\n", messagesCommand.ID)
	}()
	state, err := client.GetState(context.Background())
	if err != nil || state.SessionID != "session-1" || state.SessionName != "smoke" {
		t.Fatalf("GetState() = %#v, %v", state, err)
	}
	messages, err := client.GetMessages(context.Background())
	if err != nil || len(messages) != 1 || messages[0].Text != "visible" {
		t.Fatalf("GetMessages() = %#v, %v", messages, err)
	}
	serialized := fmt.Sprintf("%#v %#v", state, messages)
	if strings.Contains(serialized, "private") || strings.Contains(serialized, "must-not-project") {
		t.Fatalf("safe projection leaked raw fields: %s", serialized)
	}
}

func TestFakePiProcessAndProcessShutdown(t *testing.T) {
	if os.Getenv("ACORNFOX_FAKE_PI") == "1" {
		runFakePiProcess()
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestFakePiProcessAndProcessShutdown")
	cmd.Env = append(os.Environ(), "ACORNFOX_FAKE_PI=1")
	process, err := startPreparedProcess(cmd, Options{})
	if err != nil {
		t.Fatalf("startPreparedProcess() error = %v", err)
	}
	if process.PID() <= 0 {
		t.Fatalf("Process.PID() = %d", process.PID())
	}
	subscription := process.Client.Subscribe()
	defer subscription.Close()
	accepted, err := process.Client.Prompt(context.Background(), "fake process")
	if err != nil || accepted.Command != "prompt" {
		t.Fatalf("Prompt() = %#v, %v", accepted, err)
	}
	if event := receiveEvent(t, subscription); event.Type != EventAgentEnd {
		t.Fatalf("event = %#v", event)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := process.Close(ctx); err != nil {
		t.Fatalf("Process.Close() error = %v", err)
	}
}

func TestProcessConfigRequiresExplicitAllowlists(t *testing.T) {
	config := ProcessConfig{
		BinaryPath: "/opt/acornfox/pi", WorkingDirectory: "/srv/acornfox/work", SessionDirectory: "/var/lib/acornfox/pi/session",
		Provider: "deepseek", Model: "deepseek-v4-flash", Thinking: "off",
		AllowedProviders: []string{"deepseek"}, AllowedModels: []string{"deepseek-v4-flash"}, AllowedThinking: []string{"off"},
		TrustedExtensions: []string{"/opt/acornfox/pi-extensions/acornfox.ts"},
		EnabledTools:      []string{"acornfox_get_status"}, AllowedTools: []string{"acornfox_get_status"},
		Environment: map[string]string{"PATH": "/usr/bin", "TOKEN": "hidden"}, AllowedEnvironmentKeys: []string{"PATH"},
		Paths: PathAllowlist{BinaryPaths: []string{"/opt/acornfox/pi"}, WorkingRoots: []string{"/srv/acornfox"}, SessionRoots: []string{"/var/lib/acornfox/pi"}, ExtensionPaths: []string{"/opt/acornfox/pi-extensions/acornfox.ts"}},
	}
	if err := validateProcessConfig(config); err == nil || strings.Contains(err.Error(), "hidden") {
		t.Fatalf("validateProcessConfig() error = %v", err)
	}
	delete(config.Environment, "TOKEN")
	if err := validateProcessConfig(config); err != nil {
		t.Fatalf("valid config error = %v", err)
	}
	if got := buildEnvironment(config.Environment); len(got) != 1 || got[0] != "PATH=/usr/bin" {
		t.Fatalf("child environment = %#v", got)
	}
	args := processArguments(config)
	want := []string{
		"--mode", "rpc", "--provider", "deepseek", "--model", "deepseek-v4-flash", "--thinking", "off",
		"--no-tools", "--no-extensions", "--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files", "--no-approve",
		"--extension", "/opt/acornfox/pi-extensions/acornfox.ts", "--tools", "acornfox_get_status", "--session-dir", "/var/lib/acornfox/pi/session",
	}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("process arguments = %#v", args)
	}
	config.SessionFile = filepath.Join(config.SessionDirectory, "session_1.jsonl")
	if err := validateProcessConfig(config); err != nil {
		t.Fatalf("persistent session config error = %v", err)
	}
	persistentArgs := processArguments(config)
	wantTail := []string{"--session", config.SessionFile, "--session-dir", config.SessionDirectory}
	if got := persistentArgs[len(persistentArgs)-len(wantTail):]; strings.Join(got, "\x00") != strings.Join(wantTail, "\x00") {
		t.Fatalf("persistent session args tail = %#v", got)
	}
	config.EnabledTools = []string{"bash"}
	config.AllowedTools = []string{"bash"}
	if err := validateProcessConfig(config); err == nil {
		t.Fatal("built-in bash tool was accepted")
	}
}

type testCommand struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Message   string `json:"message"`
	Confirmed *bool  `json:"confirmed"`
}

func readCommand(reader io.Reader) (testCommand, error) {
	line, err := bufio.NewReader(reader).ReadBytes('\n')
	if err != nil {
		return testCommand{}, err
	}
	var command testCommand
	if err := json.Unmarshal(line, &command); err != nil {
		return testCommand{}, err
	}
	return command, nil
}

func receiveEvent(t *testing.T, subscription *Subscription) Event {
	t.Helper()
	select {
	case event, ok := <-subscription.Events:
		if !ok {
			t.Fatalf("subscription closed: %v", <-subscription.Done)
		}
		return event
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
		return Event{}
	}
}

func runFakePiProcess() {
	command, err := readCommand(os.Stdin)
	if err != nil {
		os.Exit(2)
	}
	_, _ = fmt.Fprintf(os.Stdout, `{"id":%q,"type":"response","command":"prompt","success":true}`+"\n", command.ID)
	_, _ = io.WriteString(os.Stdout, "{\"type\":\"agent_end\",\"messages\":[],\"willRetry\":false}\n")
}
