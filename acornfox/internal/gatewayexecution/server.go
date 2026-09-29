package gatewayexecution

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

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/artifactio"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/localpeer"
)

type ServerConfig struct {
	SocketPath    string
	SocketGID     uint32
	ExpectedPID   int32
	ExpectedUID   uint32
	PeerValidator func(int32, uint32) error
}

type Server struct {
	server   *http.Server
	listener net.Listener
}

type peerListener struct {
	net.Listener
	cfg ServerConfig
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		peer, err := localpeer.PeerIdentity(conn)
		if err != nil || peer.PID != l.cfg.ExpectedPID || peer.UID != l.cfg.ExpectedUID || l.cfg.PeerValidator(peer.PID, peer.UID) != nil {
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}

func startServer(c ServerConfig, handler http.Handler) (*Server, error) {
	if !filepath.IsAbs(c.SocketPath) || filepath.Clean(c.SocketPath) != c.SocketPath || c.ExpectedPID <= 0 || c.ExpectedUID == 0 || c.PeerValidator == nil {
		return nil, errors.New("Gateway server needs exact attested Unix peers")
	}
	if c.SocketGID != 0 {
		parent, err := os.Lstat(filepath.Dir(c.SocketPath))
		if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm() != 0o750 || parent.Mode()&os.ModeSetgid == 0 || artifactio.CheckFileOwner(parent, os.Geteuid(), int(c.SocketGID)) != nil {
			return nil, errors.New("root-published Gateway socket parent unavailable")
		}
	}
	if _, err := os.Lstat(c.SocketPath); err == nil || !os.IsNotExist(err) {
		return nil, errors.New("Gateway socket path must be absent")
	}
	listener, err := net.Listen("unix", c.SocketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(c.SocketPath, 0o660); err != nil {
		listener.Close()
		return nil, err
	}
	if c.SocketGID != 0 {
		info, err := os.Lstat(c.SocketPath)
		if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o660 || artifactio.CheckFileOwner(info, os.Geteuid(), int(c.SocketGID)) != nil {
			listener.Close()
			return nil, errors.New("Gateway socket owner/group mismatch")
		}
	}
	verified := &peerListener{Listener: listener, cfg: c}
	s := &Server{listener: verified, server: &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 35 * time.Second}}
	go s.server.Serve(verified)
	return s, nil
}

func (s *Server) Close() error { return s.server.Close() }

func readCommand(r *http.Request) (Command, error) {
	var command Command
	if r.Method != http.MethodPost {
		return command, errors.New("Gateway command requires POST")
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxCommandBytes+1))
	if err != nil || strictDecode(raw, maxCommandBytes, &command) != nil || !commandValid(command) {
		return command, errors.New("invalid Gateway command")
	}
	return command, nil
}

func NewExecutionServer(c ServerConfig, runtime *Runtime) (*Server, error) {
	if runtime == nil {
		return nil, errors.New("Gateway runtime required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/gateway/execute", func(w http.ResponseWriter, r *http.Request) {
		command, err := readCommand(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		observation, err := runtime.Execute(r.Context(), command)
		response := ExecutionResponse{}
		if err == nil {
			response.Observation = &observation
		} else {
			response.Error = "Gateway projection unavailable"
			response.OutcomeUnknown = errors.Is(err, appcontracts.ErrOutcomeUnknown) || contracts.IsProviderOutcomeUnknown(err) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})
	mux.HandleFunc("/v1/gateway/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_, _ = io.WriteString(w, `{"interface":"gateway-execution-v1"}`)
	})
	return startServer(c, mux)
}

type AuthorityStore interface {
	AuthorizeImagePublicAccess(context.Context, appcontracts.ImagePublicAccessAuthority) (appcontracts.ImagePublicAccessCommand, error)
	ListImagePublicAccessRoutes(context.Context) ([]appcontracts.ImagePublicAccessRoute, error)
}

func authorityBinding(ctx context.Context, store AuthorityStore, command Command) (appcontracts.ImagePublicAccessCommand, error) {
	approved, err := store.AuthorizeImagePublicAccess(ctx, command.Authority)
	if err != nil || !sameCommand(approved, command.Binding) {
		return approved, errors.New("Core Gateway command authority rejected")
	}
	return approved, nil
}

func routeForCommand(routes []appcontracts.ImagePublicAccessRoute, b appcontracts.ImagePublicAccessCommand) bool {
	for _, r := range routes {
		if r.ApprovalID == b.ApprovalID && r.OperationID == b.OperationID && r.DeploymentID == b.DeploymentID && r.ApplicationID == b.ApplicationID && r.Hostname == b.Hostname && r.EndpointVersion == b.EndpointVersion && r.HostPort == b.HostPort && r.ServiceName == "web" {
			return r.Enabled == (b.Action == appcontracts.ImagePublicAccessEnsure)
		}
	}
	return false
}

func NewAuthorityServer(c ServerConfig, store AuthorityStore) (*Server, error) {
	if store == nil {
		return nil, errors.New("durable Core Gateway authority required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/gateway/authorize", func(w http.ResponseWriter, r *http.Request) {
		command, err := readCommand(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		approved, err := authorityBinding(r.Context(), store, command)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthorityResponse{Binding: approved})
	})
	mux.HandleFunc("/v1/gateway/routes", func(w http.ResponseWriter, r *http.Request) {
		command, err := readCommand(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, err := authorityBinding(r.Context(), store, command); err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		routes, err := store.ListImagePublicAccessRoutes(r.Context())
		if err != nil || !routeForCommand(routes, command.Binding) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		raw, err := json.Marshal(InventoryResponse{Routes: routes})
		if err != nil || len(raw) > maxInventoryBytes {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	})
	mux.HandleFunc("/v1/gateway/check", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxCommandBytes+1))
		var check SnapshotCheck
		if err != nil || strictDecode(raw, maxCommandBytes, &check) != nil || !commandValid(check.Command) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, err := authorityBinding(r.Context(), store, check.Command); err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		routes, err := store.ListImagePublicAccessRoutes(r.Context())
		digest, digestErr := inventoryDigest(routes)
		if err != nil || digestErr != nil || digest != check.Digest || !routeForCommand(routes, check.Command.Binding) {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return startServer(c, mux)
}
