package sourcebuildexecution

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/peer"
)

type ServerConfig struct {
	ArchiveStore contracts.ImageStore
	SocketPath   string
	SocketGID    uint32 // shared IPC group of core and executor
	PeerUID      uint32 // only this account may connect
}

type Server struct {
	server   *http.Server
	listener net.Listener
}

func startServer(c ServerConfig, h http.Handler) (*Server, error) {
	l, err := peer.Listen(c.SocketPath, c.SocketGID, c.PeerUID)
	if err != nil {
		return nil, err
	}
	s := &Server{listener: l, server: &http.Server{Handler: h, ReadHeaderTimeout: 3 * time.Second}}
	go s.server.Serve(s.listener)
	return s, nil
}
func (s *Server) Close() error { return s.server.Close() }
func readCommand(r *http.Request) ([]byte, SourceBuildCommand, error) {
	var command SourceBuildCommand
	if r.Method != http.MethodPost {
		return nil, command, ErrBinding
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, peer.MaxMessageBytes+1))
	if err != nil {
		return nil, command, err
	}
	if err := strictMessage(raw, &command); err != nil {
		return nil, command, err
	}
	return raw, command, nil
}
func NewExecutionServer(c ServerConfig, runtime *Runtime) (*Server, error) {
	if runtime == nil {
		return nil, errors.New("source-build production runtime required")
	}
	mux := http.NewServeMux()
	if c.ArchiveStore != nil {
		mux.HandleFunc("/v1/source-build/open-oci", func(w http.ResponseWriter, r *http.Request) { serveBuiltOCI(w, r, c.ArchiveStore) })
	}
	mux.HandleFunc("/v1/source-build/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"interface":"source-build-execution-v1"}`)
	})
	mux.HandleFunc("/v1/source-build/execute", func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		if err := rc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		raw, command, err := readCommand(r)
		if clearErr := rc.SetReadDeadline(time.Time{}); clearErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		deadline, err := commandDeadline(command)
		if err != nil || !deadline.After(time.Now()) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithDeadline(r.Context(), deadline)
		defer cancel()
		receipt, err := runtime.ExecuteSourceBuild(ctx, raw)
		wire := executionResponse{Receipt: &receipt}
		if err != nil {
			wire.Receipt = nil
			wire.Error = "source-build execution failed"
			wire.OutcomeUnknown = contracts.IsProviderOutcomeUnknown(err) || ctx.Err() != nil
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(wire)
	})
	return startServer(c, mux)
}
func NewAuthorityServer(c ServerConfig, authority SourceBuildAuthority) (*Server, error) {
	if authority == nil {
		return nil, errors.New("durable Core authority required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/source-build/authorize", func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		if err := rc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, command, err := readCommand(r)
		if clearErr := rc.SetReadDeadline(time.Time{}); clearErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, err := commandDeadline(command); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		permit, err := authority.AuthorizeSourceBuild(r.Context(), command)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(permit)
	})
	return startServer(c, mux)
}
