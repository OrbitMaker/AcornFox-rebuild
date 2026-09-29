package gatewayexecution

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/peer"
)

type ServerConfig struct {
	SocketPath string
	SocketGID  uint32 // shared IPC group of core and executor
	PeerUID    uint32 // only this account may connect
}

type Server struct {
	server   *http.Server
	listener net.Listener
}

func startServer(c ServerConfig, handler http.Handler) (*Server, error) {
	listener, err := peer.Listen(c.SocketPath, c.SocketGID, c.PeerUID)
	if err != nil {
		return nil, err
	}
	s := &Server{listener: listener, server: &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 35 * time.Second}}
	go s.server.Serve(listener)
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
