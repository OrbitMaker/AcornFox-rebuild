package imageexecution

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/artifactio"
	"github.com/open-card/open-card/internal/localpeer"
	"github.com/open-card/open-card/internal/packprotocol"
)

func decodeStrictJSON(r io.Reader, dst any) error {
	data, err := io.ReadAll(io.LimitReader(r, packprotocol.MaxProtocolMessageBytes+1))
	if err != nil {
		return err
	}
	if len(data) > packprotocol.MaxProtocolMessageBytes {
		return errors.New("request body exceeds protocol limit (64KB)")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("extraneous trailing content after JSON object")
	}
	return nil
}

type peerVerifiedListener struct {
	net.Listener
	expectedUID uint32
	expectedPID int32
	validator   func(pid int32, uid uint32) error
}

func (l *peerVerifiedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		peer, err := localpeer.PeerIdentity(conn)
		if err != nil {
			_ = conn.Close()
			continue
		}
		if peer.UID != l.expectedUID {
			_ = conn.Close()
			continue
		}
		if l.expectedPID > 0 && peer.PID != l.expectedPID {
			_ = conn.Close()
			continue
		}
		if l.validator != nil {
			if err := l.validator(peer.PID, peer.UID); err != nil {
				_ = conn.Close()
				continue
			}
		}
		return conn, nil
	}
}

// ContainerServerConfig configures the Container role Unix RPC server with mutual peer attestation.
type ContainerServerConfig struct {
	EnableLifecycle bool
	Runtime         *ContainerRuntime
	SocketPath      string
	SocketGID       uint32 // Optional unified IPC group; zero preserves legacy socket behavior.
	ExpectedCoreUID uint32
	ExpectedCorePID int32
	PeerValidator   func(pid int32, uid uint32) error
}

func verifyRoleSocketParent(path string, gid uint32) error {
	if gid == 0 {
		return nil
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0750 || info.Mode()&os.ModeSetgid == 0 || artifactio.CheckFileOwner(info, os.Geteuid(), int(gid)) != nil {
		return errors.New("prepublished role socket parent is missing or unsafe")
	}
	if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
		return errors.New("role socket path must be absent in unified IPC mode")
	}
	return nil
}
func verifyRoleSocket(path string, gid uint32) error {
	if gid == 0 {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 || artifactio.CheckFileOwner(info, os.Geteuid(), int(gid)) != nil {
		return errors.New("role socket did not inherit the prepublished IPC group")
	}
	return nil
}

// ContainerServer serves deployment and observation RPC requests over a Unix domain socket.
type ContainerServer struct {
	runtime    *ContainerRuntime
	socketPath string
	listener   net.Listener
	server     *http.Server
	mu         sync.Mutex
	closed     bool
}

// NewContainerServer creates and starts a container role Unix HTTP server.
func NewContainerServer(cfg ContainerServerConfig) (*ContainerServer, error) {
	if cfg.Runtime == nil {
		return nil, errors.New("runtime is required")
	}
	if cfg.SocketPath == "" {
		return nil, errors.New("socket path is required")
	}
	if err := verifyRoleSocketParent(cfg.SocketPath, cfg.SocketGID); err != nil {
		return nil, err
	}
	if cfg.SocketGID == 0 {
		_ = os.Remove(cfg.SocketPath)
	}

	rawListener, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on unix socket %s: %w", cfg.SocketPath, err)
	}
	if err := os.Chmod(cfg.SocketPath, 0o660); err != nil {
		_ = rawListener.Close()
		_ = os.Remove(cfg.SocketPath)
		return nil, err
	}
	if err := verifyRoleSocket(cfg.SocketPath, cfg.SocketGID); err != nil {
		_ = rawListener.Close()
		_ = os.Remove(cfg.SocketPath)
		return nil, err
	}

	verifiedListener := &peerVerifiedListener{
		Listener:    rawListener,
		expectedUID: cfg.ExpectedCoreUID,
		expectedPID: cfg.ExpectedCorePID,
		validator:   cfg.PeerValidator,
	}

	cs := &ContainerServer{
		runtime:    cfg.Runtime,
		socketPath: cfg.SocketPath,
		listener:   verifiedListener,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/image/deploy", cs.handleDeploy)
	mux.HandleFunc("/v1/image/observe", cs.handleObserve)
	mux.HandleFunc("/v1/image/managed-observation", cs.handleManagedObservation)
	mux.HandleFunc("/v1/image/managed-metrics", cs.handleManagedMetrics)
	mux.HandleFunc("/v1/image/built-oci/probe", cs.handleBuiltOCIProbe)
	mux.HandleFunc("/v1/image/built-oci/import", cs.handleBuiltOCIImport)
	if cfg.EnableLifecycle {
		mux.HandleFunc("/v1/image/lifecycle", cs.handleLifecycle)
	}
	mux.HandleFunc("/v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	cs.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Minute,
	}

	go func() {
		_ = cs.server.Serve(verifiedListener)
	}()

	return cs, nil
}

func (cs *ContainerServer) handleDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req DeployRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	resp := cs.runtime.Deploy(r.Context(), req)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (cs *ContainerServer) handleObserve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ObserveRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	resp := cs.runtime.Observe(r.Context(), req)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (cs *ContainerServer) handleBuiltOCIProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req BuiltOCIImportRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	receipt, present, err := cs.runtime.ProbeBuiltOCI(r.Context(), req)
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(BuiltOCIImportResponse{Present: present, Image: receipt.Image, StorageRef: receipt.StorageRef, ContentDigest: receipt.ArchiveSHA256, SizeBytes: receipt.SizeBytes, ManifestDigest: receipt.ManifestDigest, ConfigDigest: receipt.ConfigDigest})
}

func (cs *ContainerServer) handleBuiltOCIImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	encoded := r.Header.Get("X-AcornFox-Built-OCI-Authority")
	if len(encoded) == 0 || len(encoded) > packprotocol.MaxProtocolMessageBytes*2 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(data) > packprotocol.MaxProtocolMessageBytes {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var req BuiltOCIImportRequest
	if err := decodeStrictJSON(bytes.NewReader(data), &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	receipt, err := cs.runtime.ImportBuiltOCI(r.Context(), req, r.Body)
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(BuiltOCIImportResponse{Present: true, Image: receipt.Image, StorageRef: receipt.StorageRef, ContentDigest: receipt.ArchiveSHA256, SizeBytes: receipt.SizeBytes, ManifestDigest: receipt.ManifestDigest, ConfigDigest: receipt.ConfigDigest})
}

// Close stops the server and removes the Unix domain socket.
func (cs *ContainerServer) Close() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.closed {
		return nil
	}
	cs.closed = true

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := cs.server.Shutdown(ctx)
	_ = os.Remove(cs.socketPath)
	return err
}

// CoreAuthorityServerConfig configures Core's authority Unix socket listener.
type CoreAuthorityServerConfig struct {
	LifecycleStore         appcontracts.ImageLifecycleStore
	Store                  appcontracts.ImageExecutionStore
	SocketPath             string
	SocketGID              uint32 // Optional unified IPC group; zero preserves legacy socket behavior.
	ExpectedContainerUID   uint32
	ExpectedContainerPID   int32
	ContainerPeerValidator func(pid int32, uid uint32) error
}

// CoreAuthorityServer exposes Core's live lease authority validation to Container role processes over Unix socket.
type CoreAuthorityServer struct {
	lifecycleStore appcontracts.ImageLifecycleStore
	store          appcontracts.ImageExecutionStore
	socketPath     string
	listener       net.Listener
	server         *http.Server
	mu             sync.Mutex
	closed         bool
}

// NewCoreAuthorityServer creates and starts a Core authority Unix socket listener.
func NewCoreAuthorityServer(cfg CoreAuthorityServerConfig) (*CoreAuthorityServer, error) {
	if cfg.Store == nil {
		return nil, errors.New("store is required for core authority server")
	}
	if cfg.SocketPath == "" {
		return nil, errors.New("authority socket path is required")
	}
	if err := verifyRoleSocketParent(cfg.SocketPath, cfg.SocketGID); err != nil {
		return nil, err
	}
	if cfg.SocketGID == 0 {
		_ = os.Remove(cfg.SocketPath)
	}

	rawListener, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on authority socket %s: %w", cfg.SocketPath, err)
	}
	if err := os.Chmod(cfg.SocketPath, 0o660); err != nil {
		_ = rawListener.Close()
		_ = os.Remove(cfg.SocketPath)
		return nil, err
	}
	if err := verifyRoleSocket(cfg.SocketPath, cfg.SocketGID); err != nil {
		_ = rawListener.Close()
		_ = os.Remove(cfg.SocketPath)
		return nil, err
	}

	verifiedListener := &peerVerifiedListener{
		Listener:    rawListener,
		expectedUID: cfg.ExpectedContainerUID,
		expectedPID: cfg.ExpectedContainerPID,
		validator:   cfg.ContainerPeerValidator,
	}

	as := &CoreAuthorityServer{
		lifecycleStore: cfg.LifecycleStore,
		store:          cfg.Store,
		socketPath:     cfg.SocketPath,
		listener:       verifiedListener,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/authority/check", as.handleCheck)
	if cfg.LifecycleStore != nil {
		mux.HandleFunc("/v1/authority/lifecycle", as.handleLifecycleAuthority)
	}
	mux.HandleFunc("/v1/authority/observe-binding", as.handleObserveBinding)
	mux.HandleFunc("/v1/authority/managed-observation", as.handleManagedObservationBinding)

	as.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
	}

	go func() {
		_ = as.server.Serve(verifiedListener)
	}()

	return as, nil
}

func (as *CoreAuthorityServer) handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AuthorityCheckRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	facts, authErr := as.store.AuthorizeImageExecution(r.Context(), appcontracts.AuthorizeImageExecutionInput{
		TaskID:          req.TaskID,
		OperationID:     req.OperationID,
		DeploymentID:    req.DeploymentID,
		PlanDigest:      req.PlanDigest,
		Owner:           req.Owner,
		CoreGeneration:  req.CoreGeneration,
		LeaseGeneration: req.LeaseGeneration,
		Now:             time.Now().UTC(),
	})

	resp := AuthorityCheckResponse{
		Authorized: authErr == nil,
	}
	if authErr != nil {
		resp.Error = authErr.Error()
	} else {
		resp.PlanDigest = facts.PlanDigest
		resp.ApplicationID = facts.ApplicationID
		resp.EnvironmentID = facts.EnvironmentID
		resp.ReleaseID = facts.ReleaseID
		resp.ApprovedPort = facts.ApprovedPort
		resp.ImageOrigin = facts.ImageOrigin
		resp.SourceArtifact = facts.SourceArtifact
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (as *CoreAuthorityServer) handleObserveBinding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ObserveBindingRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	binding, err := as.store.ReadImageObservationBinding(r.Context(), req.OperationID, req.DeploymentID)
	resp := ObserveBindingResponse{
		Valid: err == nil,
	}
	if err != nil {
		resp.Error = err.Error()
	} else {
		resp.ApplicationID = binding.ApplicationID
		resp.EnvironmentID = binding.EnvironmentID
		resp.ReleaseID = binding.ReleaseID
		resp.Repository = binding.Repository
		resp.Digest = binding.Digest
		resp.ApprovedPort = binding.ApprovedPort
		resp.PlanDigest = binding.PlanDigest
		resp.OperationState = binding.OperationState
		resp.ImageOrigin = binding.ImageOrigin
		resp.SourceArtifact = binding.SourceArtifact
		resp.CanonicalInput = binding.CanonicalInput
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Close shuts down the authority server and removes the socket.
func (as *CoreAuthorityServer) Close() error {
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.closed {
		return nil
	}
	as.closed = true

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := as.server.Shutdown(ctx)
	_ = os.Remove(as.socketPath)
	return err
}
