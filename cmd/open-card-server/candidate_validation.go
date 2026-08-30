package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/persistence/postgres"
)

const candidateValidationArgument = "--candidate-validate"

type candidateValidationConfig struct {
	address             string
	databaseURL         string
	inheritedListenerFD bool
}

type candidateListenerDependencies struct {
	openInheritedFile func(uintptr, string) *os.File
	listenerFromFile  func(*os.File) (net.Listener, error)
	listen            func(string, string) (net.Listener, error)
}

func runCandidateValidation(ctx context.Context, args []string, getenv func(string) string) error {
	config, err := parseCandidateValidationConfig(args, getenv)
	if err != nil {
		return err
	}
	connectContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	store, err := postgres.OpenStore(connectContext, config.databaseURL)
	cancel()
	if err != nil {
		return errors.New("candidate validation database is unavailable")
	}
	defer store.Close()
	listener, err := candidateValidationListener(config, candidateListenerDependencies{
		openInheritedFile: os.NewFile,
		listenerFromFile:  net.FileListener,
		listen:            net.Listen,
	})
	if err != nil {
		return err
	}
	return serveCandidateValidationOnListener(ctx, listener, NewServerWithRepository(store))
}

func parseCandidateValidationConfig(args []string, getenv func(string) string) (candidateValidationConfig, error) {
	if len(args) != 1 || args[0] != candidateValidationArgument {
		return candidateValidationConfig{}, errors.New("unsupported server arguments")
	}
	if getenv == nil {
		return candidateValidationConfig{}, errors.New("candidate validation configuration is unavailable")
	}
	address := strings.TrimSpace(getenv("OPEN_CARD_SERVER_ADDR"))
	if err := validateCandidateValidationAddress(address); err != nil {
		return candidateValidationConfig{}, err
	}
	databaseURL := strings.TrimSpace(getenv("OPEN_CARD_DATABASE_URL"))
	if databaseURL == "" {
		return candidateValidationConfig{}, errors.New("candidate validation database is required")
	}
	if strings.TrimSpace(getenv("OPEN_CARD_AGENT_GATEWAY_ADDR")) != "" || strings.TrimSpace(getenv("OPEN_CARD_AUTH_ORIGIN")) != "" {
		return candidateValidationConfig{}, errors.New("candidate validation forbids Agent gateway and authentication origin")
	}
	for _, key := range []string{
		"OPEN_CARD_M1_ENABLED",
		"OPEN_CARD_M2_ENABLED",
		"OPEN_CARD_M3_ENABLED",
		"OPEN_CARD_M4_ENABLED",
		"OPEN_CARD_M4_ROLLOUT_ENABLED",
		"OPEN_CARD_M5_ENABLED",
		"OPEN_CARD_M6_ENABLED",
	} {
		if value := strings.TrimSpace(getenv(key)); value != "" && value != "false" {
			return candidateValidationConfig{}, errors.New("candidate validation requires runtime workers to be disabled")
		}
	}
	listenerFD := getenv("OPEN_CARD_CANDIDATE_LISTEN_FD")
	if listenerFD != "" && listenerFD != "3" {
		return candidateValidationConfig{}, errors.New("candidate validation accepts only inherited listener FD 3")
	}
	return candidateValidationConfig{address: address, databaseURL: databaseURL, inheritedListenerFD: listenerFD == "3"}, nil
}

func validateCandidateValidationAddress(address string) error {
	if address == "" || address == "127.0.0.1:8080" {
		return errors.New("candidate validation requires an explicit non-default loopback address")
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("candidate validation requires an explicit non-default loopback address")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return errors.New("candidate validation requires an explicit non-default loopback address")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return errors.New("candidate validation requires an explicit non-default loopback address")
	}
	return nil
}

func candidateValidationListener(config candidateValidationConfig, dependencies candidateListenerDependencies) (net.Listener, error) {
	if !config.inheritedListenerFD {
		if dependencies.listen == nil {
			return nil, errors.New("candidate validation listener is unavailable")
		}
		listener, err := dependencies.listen("tcp", config.address)
		if err != nil {
			return nil, errors.New("candidate validation listener failed")
		}
		return listener, nil
	}
	if dependencies.openInheritedFile == nil || dependencies.listenerFromFile == nil {
		return nil, errors.New("candidate validation listener is unavailable")
	}
	file := dependencies.openInheritedFile(3, "open-card-candidate-listener")
	if file == nil {
		return nil, errors.New("candidate validation inherited listener is unavailable")
	}
	listener, err := dependencies.listenerFromFile(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		if listener != nil {
			_ = listener.Close()
		}
		return nil, errors.New("candidate validation inherited listener is unavailable")
	}
	if err := validateCandidateValidationListenerAddress(listener, config.address); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func validateCandidateValidationListenerAddress(listener net.Listener, expectedAddress string) error {
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok || tcpListener == nil {
		return errors.New("candidate validation inherited listener is not TCP")
	}
	host, portText, err := net.SplitHostPort(expectedAddress)
	if err != nil {
		return errors.New("candidate validation inherited listener address is invalid")
	}
	expectedIP, err := netip.ParseAddr(host)
	if err != nil {
		return errors.New("candidate validation inherited listener address is invalid")
	}
	expectedPort, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return errors.New("candidate validation inherited listener address is invalid")
	}
	actual := tcpListener.Addr().(*net.TCPAddr)
	actualIP, ok := netip.AddrFromSlice(actual.IP)
	if !ok || actual.Port != int(expectedPort) || actualIP.Unmap() != expectedIP.Unmap() {
		return errors.New("candidate validation inherited listener does not match configured loopback address")
	}
	return nil
}

func candidateValidationHandler(server *Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		candidateValidationHealth(server, writer, request, false)
	})
	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		candidateValidationHealth(server, writer, request, true)
	})
	return mux
}

func candidateValidationHealth(server *Server, writer http.ResponseWriter, request *http.Request, ready bool) {
	if ready && !server.ready.Load() {
		writeJSONError(writer, http.StatusServiceUnavailable, "not_ready", "candidate database is not ready")
		return
	}
	if ready && server.repositoryHealth != nil {
		ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
		err := server.repositoryHealth.PingContext(ctx)
		cancel()
		if err != nil {
			writeJSONError(writer, http.StatusServiceUnavailable, "repository_not_ready", "candidate database is not ready")
			return
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{"status": "ok", "ready": server.ready.Load()})
}

func serveCandidateValidation(ctx context.Context, address string, server *Server) error {
	if server == nil {
		return errors.New("candidate validation server is unavailable")
	}
	listener, err := candidateValidationListener(candidateValidationConfig{address: address}, candidateListenerDependencies{listen: net.Listen})
	if err != nil {
		return errors.New("candidate validation listener failed")
	}
	return serveCandidateValidationOnListener(ctx, listener, server)
}

func serveCandidateValidationOnListener(ctx context.Context, listener net.Listener, server *Server) error {
	if listener == nil || server == nil {
		return errors.New("candidate validation server is unavailable")
	}
	httpServer := &http.Server{
		Handler:           candidateValidationHandler(server),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- httpServer.Serve(listener) }()
	select {
	case err := <-serveResult:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("candidate validation listener failed")
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		shutdownErr := httpServer.Shutdown(shutdownContext)
		cancel()
		if shutdownErr != nil {
			return errors.New("candidate validation shutdown failed")
		}
		err := <-serveResult
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errors.New("candidate validation listener failed")
		}
		return server.Shutdown(context.Background())
	}
}
