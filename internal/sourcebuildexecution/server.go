package sourcebuildexecution

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/open-card/open-card/internal/artifactio"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/localpeer"
	"github.com/open-card/open-card/internal/packprotocol"
)

type ServerConfig struct {
	ArchiveStore  contracts.ImageStore
	SocketPath    string
	SocketGID     uint32 // Optional unified IPC group; zero retains legacy fixtures.
	ExpectedPID   int32
	ExpectedUID   uint32
	PeerValidator func(int32, uint32) error
}

func verifySourceSocketParent(path string, gid uint32) error {
	if gid == 0 {
		return nil
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0750 || info.Mode()&os.ModeSetgid == 0 || artifactio.CheckFileOwner(info, os.Geteuid(), int(gid)) != nil {
		return errors.New("prepublished source socket parent is missing or unsafe")
	}
	return nil
}
func verifySourceSocket(path string, gid uint32) error {
	if gid == 0 {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 || artifactio.CheckFileOwner(info, os.Geteuid(), int(gid)) != nil {
		return errors.New("source socket did not inherit the prepublished IPC group")
	}
	return nil
}

type Server struct {
	server   *http.Server
	listener net.Listener
}
type verifiedListener struct {
	net.Listener
	cfg ServerConfig
}

func (l *verifiedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		peer, err := localpeer.PeerIdentity(c)
		if err != nil || peer.PID != l.cfg.ExpectedPID || peer.UID != l.cfg.ExpectedUID || l.cfg.PeerValidator(peer.PID, peer.UID) != nil {
			c.Close()
			continue
		}
		return c, nil
	}
}
func startServer(c ServerConfig, h http.Handler) (*Server, error) {
	if !filepath.IsAbs(c.SocketPath) || c.ExpectedPID <= 0 || c.PeerValidator == nil {
		return nil, errors.New("server requires exact attested peer and absolute socket")
	}
	if err := verifySourceSocketParent(c.SocketPath, c.SocketGID); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(c.SocketPath); err == nil || !os.IsNotExist(err) {
		return nil, errors.New("source-build socket path is not absent")
	}
	l, err := net.Listen("unix", c.SocketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(c.SocketPath, 0660); err != nil {
		l.Close()
		_ = os.Remove(c.SocketPath)
		return nil, err
	}
	if err := verifySourceSocket(c.SocketPath, c.SocketGID); err != nil {
		l.Close()
		_ = os.Remove(c.SocketPath)
		return nil, err
	}
	s := &Server{listener: &verifiedListener{Listener: l, cfg: c}, server: &http.Server{Handler: h, ReadHeaderTimeout: 3 * time.Second}}
	go s.server.Serve(s.listener)
	return s, nil
}
func (s *Server) Close() error { return s.server.Close() }
func readCommand(r *http.Request) ([]byte, SourceBuildCommand, error) {
	var command SourceBuildCommand
	if r.Method != http.MethodPost {
		return nil, command, ErrBinding
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, packprotocol.MaxProtocolMessageBytes+1))
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
