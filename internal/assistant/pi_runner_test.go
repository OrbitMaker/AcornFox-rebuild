package assistant

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fakePiWorker(t *testing.T, mode string) (string, *atomic.Int32, func() []string) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "af-pi-runner-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "worker.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	calls := new(atomic.Int32)
	var mu sync.Mutex
	var commands []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		writer := json.NewEncoder(conn)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var open map[string]any
		if json.Unmarshal(line, &open) != nil {
			return
		}
		_ = writer.Encode(map[string]any{"protocol": "acornfox.piworker.v1", "type": "ready", "run_id": open["run_id"]})
		for {
			line, err = reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var request struct {
				ID      string `json:"id"`
				Type    string `json:"type"`
				Message string `json:"message"`
			}
			if json.Unmarshal(line, &request) != nil {
				return
			}
			mu.Lock()
			commands = append(commands, request.Type)
			mu.Unlock()
			response := map[string]any{"type": "response", "id": request.ID, "command": request.Type, "success": true}
			switch request.Type {
			case "prompt":
				calls.Add(1)
				if mode == "lost_ack" {
					return
				}
				_ = writer.Encode(response)
				if mode == "wait" {
					continue
				}
				_ = writer.Encode(map[string]any{"type": "message_update", "usage": map[string]any{}, "assistantMessageEvent": map[string]any{"type": "text_delta", "contentIndex": 0, "delta": "你好"}})
				_ = writer.Encode(map[string]any{"type": "agent_end", "messages": []any{}, "willRetry": false})
			case "get_messages":
				response["data"] = map[string]any{"messages": []any{map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "text", "text": "你好"}}, "stopReason": "stop"}}}
				_ = writer.Encode(response)
			case "clear_queue":
				response["data"] = map[string]any{"steering": []string{}, "followUp": []string{}}
				_ = writer.Encode(response)
			case "abort":
				_ = writer.Encode(response)
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("fake worker was not disconnected")
		}
		_ = os.RemoveAll(root)
	})
	return path, calls, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), commands...) }
}

func TestPiRunnerStreamsThroughWorkerAndRevokesGrant(t *testing.T) {
	path, calls, _ := fakePiWorker(t, "complete")
	var revoked atomic.Bool
	runner, err := NewPiRunner(PiRunnerConfig{SocketPath: path, Grant: func(run RunnerRun, _ time.Time) (string, func(), error) {
		if run.Actor.AdminID != "admin_1" || run.Scope.Kind != ScopeHost {
			t.Error("grant lost actor/scope")
		}
		return strings.Repeat("a", 43), func() { revoked.Store(true) }, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	var events []RunnerEvent
	handle, err := runner.Start(ctx, ctx, RunnerRun{RunID: "run_1", SessionID: "session_1", Actor: Actor{AdminID: "admin_1"}, Scope: Scope{Kind: ScopeHost}, Message: "hello"}, func(event RunnerEvent) error { events = append(events, event); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err = handle.Wait(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || !revoked.Load() || len(events) != 2 || events[0].Kind != RunnerDelta || events[1].Kind != RunnerMessage || events[1].Text != "你好" {
		t.Fatalf("calls=%d revoke=%v events=%+v", calls.Load(), revoked.Load(), events)
	}
}
func TestPiRunnerLostPromptAcknowledgementIsUnknown(t *testing.T) {
	path, calls, _ := fakePiWorker(t, "lost_ack")
	var revoked atomic.Bool
	runner, _ := NewPiRunner(PiRunnerConfig{SocketPath: path, Grant: func(RunnerRun, time.Time) (string, func(), error) {
		return strings.Repeat("a", 43), func() { revoked.Store(true) }, nil
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	handle, err := runner.Start(ctx, ctx, RunnerRun{RunID: "run_1", SessionID: "session_1", Actor: Actor{AdminID: "admin_1"}, Scope: Scope{Kind: ScopeHost}, Message: "hello"}, func(RunnerEvent) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err = handle.Wait(); !errors.Is(err, ErrRunnerOutcomeUnknown) {
		t.Fatalf("outcome=%v", err)
	}
	if calls.Load() != 1 || !revoked.Load() {
		t.Fatal("unknown run was not stopped and revoked")
	}
}
func TestPiRunnerAbortClearsProviderQueueBeforeAbort(t *testing.T) {
	path, _, commands := fakePiWorker(t, "wait")
	runner, _ := NewPiRunner(PiRunnerConfig{SocketPath: path, Grant: func(RunnerRun, time.Time) (string, func(), error) { return strings.Repeat("a", 43), func() {}, nil }})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	handle, err := runner.Start(ctx, ctx, RunnerRun{RunID: "run_1", SessionID: "session_1", Actor: Actor{AdminID: "admin_1"}, Scope: Scope{Kind: ScopeHost}, Message: "hello"}, func(RunnerEvent) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err = runner.Abort(ctx, RunnerAbort{SessionID: "session_1", ClearQueue: true}); err != nil {
		t.Fatal(err)
	}
	_ = handle.Wait()
	got := commands()
	if len(got) != 3 || got[1] != "clear_queue" || got[2] != "abort" {
		t.Fatalf("commands=%v", got)
	}
}
