package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/acornfox/acornfox/internal/packprotocol"
)

type adapterServer struct {
	packID     string
	version    string
	instanceID string
	mu         sync.Mutex
	tasks      map[string]*taskState
}

type taskState struct {
	req             packprotocol.ObserveTaskRequest
	event           packprotocol.ObserveTaskEvent
	ack             bool
	cancelCh        chan struct{}
	cancelRequested bool
	cancelled       bool
	ready           bool
}

func isMarkerReady(markerPath string) bool {
	fi, err := os.Stat(markerPath)
	if err != nil {
		return false
	}
	return fi.Mode().IsRegular()
}

func main() {
	var socketPath string
	var packID string
	var version string
	var instanceID string
	var stateDir string

	flag.StringVar(&socketPath, "socket", "", "Unix socket path to listen on")
	flag.StringVar(&packID, "pack", "", "Pack ID")
	flag.StringVar(&version, "version", "", "Pack version")
	flag.StringVar(&instanceID, "instance", "", "Instance ID")
	flag.StringVar(&stateDir, "state", "", "State directory")
	flag.Parse()

	flagsSet := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		flagsSet[f.Name] = true
	})

	if !flagsSet["socket"] {
		if env := os.Getenv("ACORNFOX_SOCKET_PATH"); env != "" {
			socketPath = env
		} else if env := os.Getenv("ACORNFOX_SOCKET"); env != "" {
			socketPath = env
		}
	}

	if !flagsSet["pack"] {
		if env := os.Getenv("ACORNFOX_PACK_ID"); env != "" {
			packID = env
		} else if env := os.Getenv("ACORNFOX_PACK"); env != "" {
			packID = env
		} else {
			packID = "fixture-live-pack"
		}
	}

	if !flagsSet["version"] {
		if env := os.Getenv("ACORNFOX_PACK_VERSION"); env != "" {
			version = env
		} else if env := os.Getenv("ACORNFOX_VERSION"); env != "" {
			version = env
		} else {
			version = "1.0.0"
		}
	}

	if !flagsSet["state"] {
		if env := os.Getenv("ACORNFOX_STATE_DIR"); env != "" {
			stateDir = env
		} else if env := os.Getenv("ACORNFOX_STATE"); env != "" {
			stateDir = env
		}
	}

	if !flagsSet["instance"] {
		if env := os.Getenv("ACORNFOX_INSTANCE_ID"); env != "" {
			instanceID = env
		} else if env := os.Getenv("ACORNFOX_INSTANCE"); env != "" {
			instanceID = env
		} else if stateDir != "" {
			// Helper launch: helper derives instance ID as fmt.Sprintf("inst_%s_%d", version, mainPID)
			instanceID = fmt.Sprintf("inst_%s_%d", version, os.Getpid())
		} else {
			instanceID = "inst-live-01"
		}
	}

	if socketPath == "" {
		log.Fatal("missing -socket parameter")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	if stateDir != "" {
		markerPath := filepath.Join(filepath.Clean(stateDir), "readiness.marker")
		if !isMarkerReady(markerPath) {
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			for !isMarkerReady(markerPath) {
				select {
				case <-sigCh:
					log.Println("protocol-adapter: shutdown signal received while waiting for readiness marker")
					return
				case <-ticker.C:
				}
			}
		}
	}

	_ = os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("listen unix %s: %v", socketPath, err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()

	srv := &adapterServer{
		packID:     packID,
		version:    version,
		instanceID: instanceID,
		tasks:      make(map[string]*taskState),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", srv.handleHealth)
	mux.HandleFunc("/v1/tasks/observe", srv.handleObserve)
	mux.HandleFunc("/v1/tasks/events", srv.handleEvents)
	mux.HandleFunc("/v1/tasks/ack", srv.handleAck)
	mux.HandleFunc("/v1/tasks/cancel", srv.handleCancel)

	httpServer := &http.Server{
		Handler: mux,
	}

	go func() {
		<-sigCh
		_ = httpServer.Shutdown(context.Background())
	}()

	if err := httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server exited: %v", err)
	}
}

func (s *adapterServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := packprotocol.HealthResponse{
		Schema:          packprotocol.ProtocolSchemaV1,
		ProtocolVersion: packprotocol.ProtocolVersion1,
		PackID:          s.packID,
		Version:         s.version,
		InstanceID:      s.instanceID,
		Status:          "ok",
		Capabilities:    []string{packprotocol.CapabilityDiagnosticObserve},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *adapterServer) handleObserve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, packprotocol.MaxProtocolMessageBytes))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	req, err := packprotocol.ParseObserveTaskRequest(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	ts := &taskState{
		req:      req,
		cancelCh: make(chan struct{}),
	}
	s.tasks[req.TaskID] = ts
	s.mu.Unlock()

	// Asynchronous computation or delay handling
	go func() {
		delay := 10 * time.Millisecond
		if req.InputContext.Action == "observe.sleep" {
			delay = 500 * time.Millisecond
		}

		select {
		case <-ts.cancelCh:
			// Task cancelled before completion: generate sequence 1 cancelled event
			occurredAt := packprotocol.FormatCanonicalTime(time.Now())
			obs := packprotocol.DiagnosticObservation{
				CheckedAt:   occurredAt,
				InputDigest: req.InputDigest,
				Status:      "cancelled",
				Summary:     "diagnostic check cancelled by operator request",
			}
			obsDigest, _, _ := packprotocol.DigestDiagnosticObservation(obs)
			eventDigest := packprotocol.ComputeEventDigest(
				req.TaskID, req.InstanceID,
				req.CoreGeneration, req.LeaseGeneration, req.InstanceGeneration,
				1, req.Kind, req.InputDigest,
				true, "failed", occurredAt, obsDigest,
			)
			s.mu.Lock()
			ts.event = packprotocol.ObserveTaskEvent{
				Schema:             packprotocol.ProtocolSchemaV1,
				TaskID:             req.TaskID,
				InstanceID:         req.InstanceID,
				CoreGeneration:     req.CoreGeneration,
				LeaseGeneration:    req.LeaseGeneration,
				InstanceGeneration: req.InstanceGeneration,
				Sequence:           1,
				InputDigest:        req.InputDigest,
				EventDigest:        eventDigest,
				Kind:               req.Kind,
				Terminal:           true,
				TerminalStatus:     "failed",
				Observation:        obs,
				OccurredAt:         occurredAt,
			}
			ts.cancelled = true
			ts.ready = true
			s.mu.Unlock()
			return

		case <-time.After(delay):
			// Normal execution completion
			occurredAt := packprotocol.FormatCanonicalTime(time.Now())
			obs := packprotocol.DiagnosticObservation{
				CheckedAt:   occurredAt,
				InputDigest: req.InputDigest,
				Status:      "healthy",
				Summary:     fmt.Sprintf("adapter executed action=%s target=%s successfully", req.InputContext.Action, req.InputContext.Target),
			}
			obsDigest, _, _ := packprotocol.DigestDiagnosticObservation(obs)
			eventDigest := packprotocol.ComputeEventDigest(
				req.TaskID, req.InstanceID,
				req.CoreGeneration, req.LeaseGeneration, req.InstanceGeneration,
				1, req.Kind, req.InputDigest,
				true, "succeeded", occurredAt, obsDigest,
			)
			s.mu.Lock()
			ts.event = packprotocol.ObserveTaskEvent{
				Schema:             packprotocol.ProtocolSchemaV1,
				TaskID:             req.TaskID,
				InstanceID:         req.InstanceID,
				CoreGeneration:     req.CoreGeneration,
				LeaseGeneration:    req.LeaseGeneration,
				InstanceGeneration: req.InstanceGeneration,
				Sequence:           1,
				InputDigest:        req.InputDigest,
				EventDigest:        eventDigest,
				Kind:               req.Kind,
				Terminal:           true,
				TerminalStatus:     "succeeded",
				Observation:        obs,
				OccurredAt:         occurredAt,
			}
			ts.ready = true
			s.mu.Unlock()
		}
	}()

	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"accepted"}`))
}

func (s *adapterServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	taskID := r.URL.Query().Get("task_id")
	if taskID == "" {
		http.Error(w, "missing task_id", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	ts, ok := s.tasks[taskID]
	s.mu.Unlock()

	if !ok || !ts.ready {
		http.Error(w, "event not ready", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ts.event)
}

func (s *adapterServer) handleAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, packprotocol.MaxProtocolMessageBytes))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	ack, err := packprotocol.ParseObserveTaskAck(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	ts, ok := s.tasks[ack.TaskID]
	if ok {
		ts.ack = true
	}
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"acknowledged"}`))
}

func (s *adapterServer) handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, packprotocol.MaxProtocolMessageBytes))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	req, err := packprotocol.ParseCancelTaskRequest(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	ts, ok := s.tasks[req.TaskID]
	if !ok {
		s.mu.Unlock()
		http.Error(w, "task not found", http.StatusNotFound)
		return
	}
	if ts.ready && !ts.cancelled {
		s.mu.Unlock()
		http.Error(w, "task already completed", http.StatusConflict)
		return
	}
	if !ts.cancelRequested {
		ts.cancelRequested = true
		close(ts.cancelCh)
	}
	s.mu.Unlock()

	replyStatus := "cancelling"
	if ts.ready && ts.cancelled {
		replyStatus = "cancelled"
	}

	resp := packprotocol.CancelTaskResponse{
		Schema: packprotocol.ProtocolSchemaV1,
		TaskID: req.TaskID,
		Status: replyStatus,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
