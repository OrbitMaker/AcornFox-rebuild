//go:build linux

package hosthelper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	contracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/artifactio"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/localpeer"
	"github.com/open-card/open-card/internal/packprotocol"
	"github.com/open-card/open-card/internal/versionpolicy"
)

type StagedInventoryVerifier func(stagePath string, opID string, snap packprotocol.Selection, planSHA string, rawManifest []byte, expectedStageIdentity string, ownerUID int, ownerGID int) (*contracts.PackArtifactReceipt, error)

type ServerConfig struct {
	SocketPath               string
	StateDir                 string
	StageDir                 string
	PacksDir                 string
	PacksStateDir            string
	PacksRunDir              string
	ServiceTemplatePath      string
	TrustedCoreUID           uint32
	CoreGID                  uint32
	SocketGID                uint32 // Optional IPC group; zero keeps the legacy CoreGID socket group.
	TrustedCoreExecutableSHA string
	InstallationBinding      string
	Policies                 map[string]packprotocol.VerificationPolicy
	VerifyStagedInventory    StagedInventoryVerifier
	RuntimeBindingPath       string
	ReadOnlyPeerOnly         bool
}

type peerCtxKey struct{}

type Server struct {
	config         ServerConfig
	listener       net.Listener
	httpServer     *http.Server
	packLocks      sync.Map // packID -> *sync.Mutex
	regLock        sync.Mutex
	currentCore    *CoreRegistration
	coreEpochFloor int64
	tmpl           *template.Template
}

func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.ReadOnlyPeerOnly {
		if cfg.RuntimeBindingPath == "" {
			return nil, errors.New("runtime binding path is required for readonly peer helper")
		}
		if cfg.SocketPath == "" {
			cfg.SocketPath = DefaultHelperSocketPath
		}
		return &Server{config: cfg}, nil
	}

	if cfg.TrustedCoreUID == 0 {
		return nil, errors.New("trusted core UID must be configured (> 0); helper fail-closed")
	}
	if cfg.TrustedCoreExecutableSHA == "" {
		return nil, errors.New("trusted core executable SHA must be configured; helper fail-closed")
	}
	if cfg.InstallationBinding == "" {
		return nil, errors.New("installation binding must be configured; helper fail-closed")
	}
	if cfg.VerifyStagedInventory == nil {
		return nil, errors.New("VerifyStagedInventory callback must be wired; helper fail-closed")
	}
	if len(cfg.Policies) == 0 {
		return nil, errors.New("trusted publisher policies must be configured; helper fail-closed")
	}

	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultHelperSocketPath
	}
	if cfg.StateDir == "" {
		cfg.StateDir = DefaultHelperStateDir
	}
	if cfg.StageDir == "" {
		cfg.StageDir = "/var/lib/acornfox/core/pack-staging"
	}
	if cfg.PacksDir == "" {
		cfg.PacksDir = "/opt/acornfox/packs"
	}
	if cfg.PacksStateDir == "" {
		cfg.PacksStateDir = "/var/lib/acornfox/packs"
	}
	if cfg.PacksRunDir == "" {
		cfg.PacksRunDir = "/run/acornfox/packs"
	}

	var tmpl *template.Template
	var err error
	if cfg.ServiceTemplatePath != "" {
		tmpl, err = template.ParseFiles(cfg.ServiceTemplatePath)
		if err != nil {
			return nil, fmt.Errorf("parse service template: %w", err)
		}
	} else {
		const defaultTmpl = `[Unit]
Description=AcornFox Pack Adapter - {{.PackID}}
After=network.target

[Service]
Type=simple
User={{.PackUser}}
Group={{.PackGroup}}
WorkingDirectory=/opt/acornfox/packs/{{.PackID}}/{{.Version}}
ExecStart={{.ExecutablePath}}
Restart=no
TimeoutStopSec=10

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true

ReadOnlyPaths=/opt/acornfox/packs/{{.PackID}}/{{.Version}}
ReadWritePaths=/var/lib/acornfox/packs/{{.PackID}} /run/acornfox/packs/{{.PackID}}

Environment=ACORNFOX_PACK_ID={{.PackID}}
Environment=ACORNFOX_PACK_VERSION={{.Version}}
Environment=ACORNFOX_SOCKET_PATH={{.SocketPath}}
Environment=ACORNFOX_STATE_DIR=/var/lib/acornfox/packs/{{.PackID}}
{{range .ExtraEnv}}Environment={{.}}
{{end}}
`
		tmpl, err = template.New("adapter").Parse(defaultTmpl)
		if err != nil {
			return nil, err
		}
	}

	if err := os.MkdirAll(cfg.StateDir, 0700); err != nil {
		return nil, fmt.Errorf("create helper state dir: %w", err)
	}

	s := &Server{
		config: cfg,
		tmpl:   tmpl,
	}
	if err := s.loadFloor(); err != nil {
		return nil, fmt.Errorf("load core generation floor: %w", err)
	}
	return s, nil
}

func (s *Server) loadFloor() error {
	floorFile := filepath.Join(s.config.StateDir, "core_generation_floor")
	data, err := os.ReadFile(floorFile)
	if err != nil {
		if os.IsNotExist(err) {
			s.coreEpochFloor = 0
			return nil
		}
		return err
	}
	var f int64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &f); err != nil {
		return fmt.Errorf("corrupt core generation floor file: %w", err)
	}
	s.coreEpochFloor = f
	return nil
}

func (s *Server) saveFloor(f int64) error {
	floorFile := filepath.Join(s.config.StateDir, "core_generation_floor")
	tmpFile := floorFile + ".tmp"
	file, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(strconv.FormatInt(f, 10)); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpFile)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpFile)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}
	if err := os.Rename(tmpFile, floorFile); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}
	d, err := os.Open(s.config.StateDir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *Server) getPackLock(packID string) *sync.Mutex {
	val, _ := s.packLocks.LoadOrStore(packID, &sync.Mutex{})
	return val.(*sync.Mutex)
}

func derivePackAccount(packID string) (user string, group string) {
	h := sha256.Sum256([]byte(packID))
	hexShort := hex.EncodeToString(h[:4])
	name := "acornfox-p-" + hexShort
	return name, name
}

type ownedAccountRecord struct {
	PackID   string `json:"pack_id"`
	UserName string `json:"user_name"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
}

func (s *Server) ensurePackUserAndGroup(packID string) (uint32, uint32, string, string, error) {
	userName, groupName := derivePackAccount(packID)
	acctRecordPath := filepath.Join(s.config.StateDir, packID, "owned_account.json")

	var saved ownedAccountRecord
	hasSaved := false
	if data, err := os.ReadFile(acctRecordPath); err == nil {
		if json.Unmarshal(data, &saved) == nil && saved.PackID == packID {
			hasSaved = true
		}
	}

	if hasSaved {
		u, err := user.Lookup(userName)
		if err != nil {
			return 0, 0, "", "", fmt.Errorf("lookup owned user %s: %w", userName, err)
		}
		g, err := user.LookupGroup(groupName)
		if err != nil {
			return 0, 0, "", "", fmt.Errorf("lookup owned group %s: %w", groupName, err)
		}
		uidParsed, _ := strconv.ParseUint(u.Uid, 10, 32)
		gidParsed, _ := strconv.ParseUint(g.Gid, 10, 32)
		if uint32(uidParsed) != saved.UID || uint32(gidParsed) != saved.GID {
			return 0, 0, "", "", fmt.Errorf("account %s UID/GID changed unexpectedly (saved %d:%d, system %d:%d)", userName, saved.UID, saved.GID, uidParsed, gidParsed)
		}
		return saved.UID, saved.GID, userName, groupName, nil
	}

	// First time creation: refuse to adopt pre-existing foreign user or group without an owned record
	if _, err := user.Lookup(userName); err == nil {
		return 0, 0, "", "", fmt.Errorf("user %s exists on system without matching owned record; refusing foreign takeover", userName)
	}
	if _, err := user.LookupGroup(groupName); err == nil {
		return 0, 0, "", "", fmt.Errorf("group %s exists on system without matching owned record; refusing foreign takeover", groupName)
	}

	cmd := exec.Command("groupadd", "-r", groupName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return 0, 0, "", "", fmt.Errorf("groupadd %s: %v (%s)", groupName, err, string(out))
	}
	g, err := user.LookupGroup(groupName)
	if err != nil {
		return 0, 0, "", "", fmt.Errorf("lookup group %s after create: %w", groupName, err)
	}

	cmd = exec.Command("useradd", "-r", "-g", groupName, "-s", "/usr/sbin/nologin", "-d", "/nonexistent", userName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return 0, 0, "", "", fmt.Errorf("useradd %s: %v (%s)", userName, err, string(out))
	}
	u, err := user.Lookup(userName)
	if err != nil {
		return 0, 0, "", "", fmt.Errorf("lookup user %s after create: %w", userName, err)
	}

	uidParsed, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, 0, "", "", err
	}
	gidParsed, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0, 0, "", "", err
	}
	uid := uint32(uidParsed)
	gid := uint32(gidParsed)

	// Persist owned account record atomically
	rec := ownedAccountRecord{
		PackID:   packID,
		UserName: userName,
		UID:      uid,
		GID:      gid,
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return 0, 0, "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(acctRecordPath), 0700); err != nil {
		return 0, 0, "", "", err
	}
	tmpAcct := acctRecordPath + ".tmp"
	f, err := os.OpenFile(tmpAcct, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return 0, 0, "", "", fmt.Errorf("create owned_account tmp: %w", err)
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpAcct)
		return 0, 0, "", "", fmt.Errorf("write owned_account tmp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpAcct)
		return 0, 0, "", "", fmt.Errorf("sync owned_account tmp: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpAcct)
		return 0, 0, "", "", fmt.Errorf("close owned_account tmp: %w", err)
	}
	if err := os.Rename(tmpAcct, acctRecordPath); err != nil {
		_ = os.Remove(tmpAcct)
		return 0, 0, "", "", fmt.Errorf("rename owned_account: %w", err)
	}
	d, err := os.Open(filepath.Dir(acctRecordPath))
	if err != nil {
		return 0, 0, "", "", fmt.Errorf("open state dir for sync: %w", err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return 0, 0, "", "", fmt.Errorf("sync state dir for owned_account: %w", err)
	}
	if err := d.Close(); err != nil {
		return 0, 0, "", "", fmt.Errorf("close state dir for owned_account: %w", err)
	}

	return uid, gid, userName, groupName, nil
}

type peerListener struct {
	net.Listener
}

type peerConn struct {
	net.Conn
	ident localpeer.Identity
}

func (pl *peerListener) Accept() (net.Conn, error) {
	c, err := pl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	ident, err := localpeer.PeerIdentity(c)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("read peer identity failed: %w", err)
	}
	return &peerConn{Conn: c, ident: ident}, nil
}

func (s *Server) socketGroup() uint32 {
	if s.config.SocketGID > 0 {
		return s.config.SocketGID
	}
	return s.config.CoreGID
}

func (s *Server) Start() error {
	socketDir := filepath.Dir(s.config.SocketPath)
	socketGID := s.socketGroup()
	if s.config.SocketGID > 0 {
		info, err := os.Lstat(socketDir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0750 || artifactio.CheckFileOwner(info, 0, int(socketGID)) != nil {
			return errors.New("prepublished helper socket directory is missing or unsafe")
		}
		if _, err := os.Lstat(s.config.SocketPath); err == nil || !os.IsNotExist(err) {
			return errors.New("helper socket path must be absent in unified IPC mode")
		}
	} else {
		_ = os.Remove(s.config.SocketPath)
		if err := os.MkdirAll(socketDir, 0750); err != nil {
			return err
		}
		if socketGID > 0 {
			if err := os.Chown(socketDir, 0, int(socketGID)); err != nil {
				return fmt.Errorf("chown socket dir %s to CoreGID %d failed: %w", socketDir, socketGID, err)
			}
		}
		if err := os.Chmod(socketDir, 0750); err != nil {
			return fmt.Errorf("chmod socket dir %s failed: %w", socketDir, err)
		}
	}

	rawListener, err := net.Listen("unix", s.config.SocketPath)
	if err != nil {
		return fmt.Errorf("listen unix socket %s: %w", s.config.SocketPath, err)
	}
	if socketGID > 0 {
		if err := os.Chown(s.config.SocketPath, 0, int(socketGID)); err != nil {
			_ = rawListener.Close()
			_ = os.Remove(s.config.SocketPath)
			return fmt.Errorf("chown socket %s to socket GID %d failed: %w", s.config.SocketPath, socketGID, err)
		}
	}
	if err := os.Chmod(s.config.SocketPath, 0660); err != nil {
		_ = rawListener.Close()
		_ = os.Remove(s.config.SocketPath)
		return err
	}

	s.listener = &peerListener{Listener: rawListener}

	mux := http.NewServeMux()
	if s.config.RuntimeBindingPath != "" {
		mux.HandleFunc("/v1/runtime/peer/attest", s.handleRuntimePeerAttest)
	}
	if !s.config.ReadOnlyPeerOnly {
		mux.HandleFunc("/v1/core/register", s.handleRegisterCore)
		mux.HandleFunc("/v1/pack/prepare", s.handlePrepareDirs)
		mux.HandleFunc("/v1/pack/publish", s.handlePublishPack)
		mux.HandleFunc("/v1/pack/start", s.handleStartPack)
		mux.HandleFunc("/v1/pack/observe", s.handleObservePack)
		mux.HandleFunc("/v1/pack/stop", s.handleStopPending)
		mux.HandleFunc("/v1/pack/abort", s.handleAbortPending)
		mux.HandleFunc("/v1/pack/current", s.handleSwitchCurrent)
	}

	s.httpServer = &http.Server{
		Handler: mux,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if pc, ok := c.(*peerConn); ok {
				return context.WithValue(ctx, peerCtxKey{}, pc.ident)
			}
			return ctx
		},
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		_ = s.httpServer.Serve(s.listener)
	}()

	return nil
}

func (s *Server) Close() error {
	if s.httpServer != nil {
		_ = s.httpServer.Close()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	_ = os.Remove(s.config.SocketPath)
	return nil
}

func getPeer(r *http.Request) (localpeer.Identity, bool) {
	val := r.Context().Value(peerCtxKey{})
	if ident, ok := val.(localpeer.Identity); ok {
		return ident, true
	}
	return localpeer.Identity{}, false
}

// authenticateCaller enforces strict fail-closed kernel peer attestation.
func (s *Server) authenticateCaller(r *http.Request, allowUnregistered bool) (localpeer.Identity, error) {
	peer, ok := getPeer(r)
	if !ok {
		return localpeer.Identity{}, errors.New("missing peer identity")
	}

	if s.config.TrustedCoreUID == 0 {
		return peer, errors.New("trusted core UID is not configured; helper fail-closed")
	}

	if peer.UID != 0 && peer.UID != s.config.TrustedCoreUID {
		return peer, fmt.Errorf("untrusted peer UID %d rejected (allowed: root 0 or core %d)", peer.UID, s.config.TrustedCoreUID)
	}

	s.regLock.Lock()
	defer s.regLock.Unlock()

	if !allowUnregistered {
		if s.currentCore == nil {
			return peer, errors.New("no core currently registered with helper")
		}
		if peer.UID != s.currentCore.CoreUID || peer.PID != s.currentCore.CorePID {
			return peer, fmt.Errorf("peer PID %d UID %d does not match registered core PID %d UID %d",
				peer.PID, peer.UID, s.currentCore.CorePID, s.currentCore.CoreUID)
		}
		att, err := localpeer.AttestLinuxProcess(peer.PID)
		if err != nil {
			return peer, fmt.Errorf("attest live caller: %w", err)
		}
		if att.StartTime != s.currentCore.CoreStartTime || att.ExecutableSHA256 != s.currentCore.CoreExecutableSHA {
			return peer, errors.New("live caller process identity mismatch with registered core")
		}
	}
	return peer, nil
}

func (s *Server) handleRegisterCore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	peer, err := s.authenticateCaller(r, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var req RegisterCoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	att, err := localpeer.AttestLinuxProcess(peer.PID)
	if err != nil {
		http.Error(w, fmt.Sprintf("attest caller process: %v", err), http.StatusInternalServerError)
		return
	}
	if att.ExecutableSHA256 != s.config.TrustedCoreExecutableSHA {
		http.Error(w, "caller executable sha256 mismatch with trusted configuration", http.StatusForbidden)
		return
	}
	if req.Registration.InstallationBinding != s.config.InstallationBinding {
		http.Error(w, "installation binding mismatch", http.StatusForbidden)
		return
	}

	s.regLock.Lock()
	defer s.regLock.Unlock()

	// Exact replay of the same registered core instance: idempotent success
	if s.currentCore != nil && s.currentCore.CorePID == peer.PID && s.currentCore.CoreUID == peer.UID &&
		s.currentCore.CoreStartTime == att.StartTime && s.currentCore.CoreExecutableSHA == att.ExecutableSHA256 &&
		s.currentCore.CoreGeneration == req.Registration.CoreGeneration && s.currentCore.CoreGeneration == s.coreEpochFloor {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RegisterCoreResponse{Registered: true})
		return
	}

	if req.Registration.CoreGeneration <= s.coreEpochFloor {
		http.Error(w, fmt.Sprintf("core generation %d must be strictly greater than persisted floor %d", req.Registration.CoreGeneration, s.coreEpochFloor), http.StatusConflict)
		return
	}

	if err := s.saveFloor(req.Registration.CoreGeneration); err != nil {
		http.Error(w, fmt.Sprintf("save core generation floor: %v", err), http.StatusInternalServerError)
		return
	}

	s.coreEpochFloor = req.Registration.CoreGeneration
	s.currentCore = &CoreRegistration{
		CorePID:             peer.PID,
		CoreUID:             peer.UID,
		CoreStartTime:       att.StartTime,
		CoreExecutableSHA:   att.ExecutableSHA256,
		InstallationBinding: req.Registration.InstallationBinding,
		CoreGeneration:      req.Registration.CoreGeneration,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(RegisterCoreResponse{Registered: true})
}

func (s *Server) persistReceipt(r HelperEffectReceipt) error {
	dir := filepath.Join(s.config.StateDir, r.PackID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	filename := fmt.Sprintf("%s_%s_%d.json", r.Action, r.OperationID, r.Sequence)
	filePath := filepath.Join(dir, filename)
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp := filePath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filePath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *Server) computeRequestDigest(actionName string, permit ActionPermit, extra []byte) string {
	h := sha256.New()
	h.Write([]byte(actionName))
	h.Write([]byte(permit.OperationID))
	h.Write([]byte(permit.PackID))
	h.Write([]byte(permit.Version))
	h.Write([]byte(strconv.FormatInt(permit.CoreGeneration, 10)))
	h.Write([]byte(strconv.FormatInt(permit.LeaseGeneration, 10)))
	h.Write([]byte(permit.OwnerID))
	h.Write([]byte(strconv.FormatInt(permit.Sequence, 10)))
	if len(extra) > 0 {
		h.Write(extra)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Server) validatePermitAndCheckReplayLocked(permit ActionPermit, actionName string, requestDigest string) (bool, *HelperEffectReceipt, error) {
	if !packprotocol.ValidPackID(permit.PackID) {
		return false, nil, errors.New("invalid pack ID format")
	}
	if _, err := versionpolicy.ParseSemver(permit.Version); err != nil {
		return false, nil, fmt.Errorf("invalid semver version %q: %w", permit.Version, err)
	}
	if permit.OperationID == "" || permit.ActionID == "" || permit.OwnerID == "" {
		return false, nil, errors.New("operation ID, action ID, and owner ID are required")
	}
	if permit.CoreGeneration <= 0 || permit.LeaseGeneration <= 0 || permit.Sequence <= 0 {
		return false, nil, errors.New("positive core generation, lease generation, and sequence are required")
	}
	if time.Now().UTC().After(permit.Deadline) {
		return false, nil, errors.New("action permit deadline expired")
	}

	s.regLock.Lock()
	defer s.regLock.Unlock()
	if s.currentCore == nil || permit.CoreGeneration != s.currentCore.CoreGeneration {
		return false, nil, errors.New("permit core generation does not match current registered core")
	}

	dir := filepath.Join(s.config.StateDir, permit.PackID)
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return false, nil, fmt.Errorf("read state dir: %w", err)
	}

	var maxSeq int64 = 0
	var maxLeaseGen int64 = 0
	var matchedCandidate *HelperEffectReceipt
	var isAborted bool

	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return false, nil, fmt.Errorf("read existing receipt %s: %w", e.Name(), err)
			}
			var rcpt HelperEffectReceipt
			if err := json.Unmarshal(data, &rcpt); err != nil {
				return false, nil, fmt.Errorf("corrupt receipt %s: %w", e.Name(), err)
			}
			if rcpt.OperationID == permit.OperationID {
				if rcpt.Status == StatusAborted {
					isAborted = true
				}
				if rcpt.LeaseGeneration > maxLeaseGen {
					maxLeaseGen = rcpt.LeaseGeneration
				}
				if rcpt.Sequence > maxSeq {
					maxSeq = rcpt.Sequence
				}
				if rcpt.Sequence == permit.Sequence {
					cand := rcpt
					matchedCandidate = &cand
				}
			}
		}
	}

	// 1. Permanent block on late mutations if already aborted
	if isAborted && actionName != ActionAbort {
		return false, nil, errors.New("operation has already been aborted; subsequent mutations rejected")
	}

	// 2. Reject older lease generation across the whole operation history
	if permit.LeaseGeneration < maxLeaseGen {
		return false, nil, fmt.Errorf("permit lease generation %d older than recorded floor %d", permit.LeaseGeneration, maxLeaseGen)
	}

	// 3. Exact completed replay check after complete scan
	if matchedCandidate != nil {
		if matchedCandidate.ActionID == permit.ActionID && matchedCandidate.Action == actionName &&
			matchedCandidate.RequestDigest == requestDigest && matchedCandidate.CoreGeneration == permit.CoreGeneration &&
			matchedCandidate.LeaseGeneration == permit.LeaseGeneration {
			return true, matchedCandidate, nil
		}
		return false, nil, fmt.Errorf("sequence %d conflict: reused action ID or changed inputs under sequence", permit.Sequence)
	}

	if permit.Sequence != maxSeq+1 {
		return false, nil, fmt.Errorf("action sequence non-monotonic: expected %d, got %d", maxSeq+1, permit.Sequence)
	}
	return false, nil, nil
}

func (s *Server) handlePrepareDirs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, err := s.authenticateCaller(r, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var req PrepareDirsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	lock := s.getPackLock(req.Permit.PackID)
	lock.Lock()
	defer lock.Unlock()

	reqDigest := s.computeRequestDigest(ActionPrepare, req.Permit, nil)
	isReplay, savedRcpt, err := s.validatePermitAndCheckReplayLocked(req.Permit, ActionPrepare, reqDigest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	pubDir := filepath.Join(s.config.PacksDir, req.Permit.PackID, req.Permit.Version)
	stateDir := filepath.Join(s.config.PacksStateDir, req.Permit.PackID)
	runDir := filepath.Join(s.config.PacksRunDir, req.Permit.PackID)

	packUID, packGID, packUser, packGroup, err := s.ensurePackUserAndGroup(req.Permit.PackID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if isReplay && savedRcpt != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PrepareDirsResponse{
			PackUID:       packUID,
			PackGID:       packGID,
			PackUser:      packUser,
			PackGroup:     packGroup,
			PublishedRoot: pubDir,
			StateRoot:     stateDir,
			RunRoot:       runDir,
		})
		return
	}

	// 1. Payload root: 0755 root:root
	if err := os.MkdirAll(pubDir, 0755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.Chown(pubDir, 0, 0); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.Chmod(pubDir, 0755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 2. State root: 0700 packUID:packGID
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.Chown(stateDir, int(packUID), int(packGID)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.Chmod(stateDir, 0700); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 3. Run root: DAC layout strictly pack可写、Core仅连接 (setgid os.ModeSetgid | 0770, owner=packUID, group=CoreGID)
	if err := os.MkdirAll(runDir, 0770); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.Chown(runDir, int(packUID), int(s.config.CoreGID)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Go os.FileMode setgid bit is os.ModeSetgid
	if err := os.Chmod(runDir, os.ModeSetgid|0770); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Verify DAC attributes strictly using Go Mode().Perm() and Mode()&os.ModeSetgid
	rInfo, err := os.Stat(runDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rStat, rOk := rInfo.Sys().(*syscall.Stat_t)
	if !rOk || rStat.Uid != packUID || rStat.Gid != s.config.CoreGID || rInfo.Mode().Perm() != 0770 || rInfo.Mode()&os.ModeSetgid == 0 {
		http.Error(w, "run directory DAC verification failed", http.StatusInternalServerError)
		return
	}

	rcpt := HelperEffectReceipt{
		ActionID:        req.Permit.ActionID,
		OperationID:     req.Permit.OperationID,
		PackID:          req.Permit.PackID,
		Version:         req.Permit.Version,
		Action:          ActionPrepare,
		Status:          StatusSucceeded,
		CoreGeneration:  req.Permit.CoreGeneration,
		LeaseGeneration: req.Permit.LeaseGeneration,
		Sequence:        req.Permit.Sequence,
		RequestDigest:   reqDigest,
		RecordedAt:      time.Now().UTC(),
	}
	if err := s.persistReceipt(rcpt); err != nil {
		http.Error(w, fmt.Sprintf("persist receipt: %v", err), http.StatusInternalServerError)
		return
	}

	resp := PrepareDirsResponse{
		PackUID:       packUID,
		PackGID:       packGID,
		PackUser:      packUser,
		PackGroup:     packGroup,
		PublishedRoot: pubDir,
		StateRoot:     stateDir,
		RunRoot:       runDir,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handlePublishPack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, err := s.authenticateCaller(r, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var req PublishPackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	lock := s.getPackLock(req.Permit.PackID)
	lock.Lock()
	defer lock.Unlock()

	extra := []byte(fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%d:%d",
		req.ArtifactReceiptID, req.PlanSHA256, req.StageIdentity,
		req.ExpectedArchiveSHA, req.ExpectedManifestSHA,
		req.ExpectedExecutablePath, req.ExpectedExecutableSHA,
		req.ExpectedMemberCount, req.ExpectedUnpackedTotalBytes))
	reqDigest := s.computeRequestDigest(ActionPublish, req.Permit, extra)
	isReplay, savedRcpt, err := s.validatePermitAndCheckReplayLocked(req.Permit, ActionPublish, reqDigest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	pubDir := filepath.Join(s.config.PacksDir, req.Permit.PackID, req.Permit.Version)
	if isReplay && savedRcpt != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PublishPackResponse{
			PublishedRoot:  pubDir,
			ExecutablePath: savedRcpt.ExecutablePath,
			ExecutableSHA:  savedRcpt.ExecutableSHA,
		})
		return
	}

	// 1. Independently verify supplied signed trust material against protected root-owned policy
	if len(req.CatalogEnvelopeRaw) == 0 {
		http.Error(w, "missing signed catalog envelope", http.StatusBadRequest)
		return
	}
	var env packprotocol.CatalogEnvelope
	if err := json.Unmarshal(req.CatalogEnvelopeRaw, &env); err != nil {
		http.Error(w, "invalid catalog envelope JSON", http.StatusBadRequest)
		return
	}
	var catPay packprotocol.CatalogPayload
	rawPay, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if err != nil {
		http.Error(w, "decode catalog payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(rawPay, &catPay); err != nil {
		http.Error(w, "unmarshal catalog payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	policy, ok := s.config.Policies[catPay.Publisher]
	if !ok {
		http.Error(w, fmt.Sprintf("untrusted publisher %q rejected by protected policy", catPay.Publisher), http.StatusForbidden)
		return
	}

	policy.Now = time.Now().UTC()
	policy.InstallationBinding = s.config.InstallationBinding
	verifiedSelection, err := packprotocol.VerifySelection(req.CatalogEnvelopeRaw, req.ManifestRaw, policy)
	if err != nil {
		http.Error(w, fmt.Sprintf("verify selection failed: %v", err), http.StatusForbidden)
		return
	}

	snap, _, ok := verifiedSelection.Snapshot()
	if !ok || snap.PackID != req.Permit.PackID || snap.Version != req.Permit.Version {
		http.Error(w, "verified selection snapshot mismatch with permit", http.StatusBadRequest)
		return
	}

	// 2. Invoke the required A staged-inventory verifier callback
	stagePath := filepath.Join(s.config.StageDir, "staging", req.Permit.OperationID)
	artRcpt, err := s.config.VerifyStagedInventory(stagePath, req.Permit.OperationID, snap, req.PlanSHA256, req.ManifestRaw, req.StageIdentity, int(s.config.TrustedCoreUID), int(s.config.CoreGID))
	if err != nil {
		http.Error(w, fmt.Sprintf("verify staged inventory failed: %v", err), http.StatusBadRequest)
		return
	}
	if artRcpt == nil {
		http.Error(w, "nil artifact receipt from inventory verification", http.StatusBadRequest)
		return
	}

	// Verify immutable content rather than the freshly generated random receipt ID
	manifestObj, err := packprotocol.ParseManifest(req.ManifestRaw)
	if err != nil {
		http.Error(w, fmt.Sprintf("parse manifest: %v", err), http.StatusBadRequest)
		return
	}
	var adapterPath, adapterSHA string
	for _, e := range manifestObj.Entries {
		if e.Role == "adapter" {
			adapterPath = e.Path
			break
		}
	}
	for _, f := range manifestObj.Files {
		if f.Path == adapterPath {
			adapterSHA = f.SHA256
		}
	}
	if adapterPath == "" || adapterSHA == "" {
		http.Error(w, "manifest missing declared adapter entry", http.StatusBadRequest)
		return
	}

	if artRcpt.PackID != req.Permit.PackID || artRcpt.Version != req.Permit.Version ||
		artRcpt.PlanSHA256 != req.PlanSHA256 || artRcpt.StageIdentity != req.StageIdentity ||
		artRcpt.ArchiveSHA256 != req.ExpectedArchiveSHA ||
		artRcpt.ManifestSHA256 != req.ExpectedManifestSHA ||
		artRcpt.ExecutablePath != req.ExpectedExecutablePath ||
		artRcpt.ExecutableSHA256 != req.ExpectedExecutableSHA ||
		artRcpt.MemberCount != req.ExpectedMemberCount ||
		artRcpt.UnpackedTotalBytes != req.ExpectedUnpackedTotalBytes {
		http.Error(w, "verified artifact facts mismatch with expected original A receipt facts", http.StatusBadRequest)
		return
	}
	if snap.ArtifactSHA256 != req.ExpectedArchiveSHA || snap.ManifestSHA256 != req.ExpectedManifestSHA {
		http.Error(w, "signed catalog envelope hashes mismatch with expected original A receipt facts", http.StatusBadRequest)
		return
	}

	// 3. Publish to immutable root-owned directory using descriptor & fsync primitives
	if err := os.MkdirAll(pubDir, 0755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.Chown(pubDir, 0, 0); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.Chmod(pubDir, 0755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pubWriter, err := artifactio.NewDurableWriter(pubDir, 0, 0)
	if err != nil {
		http.Error(w, fmt.Sprintf("open pubDir descriptor: %v", err), http.StatusInternalServerError)
		return
	}
	defer pubWriter.Close()

	stagePackDir := filepath.Join(stagePath, "pack")
	srcWriter, err := artifactio.NewDurableWriter(stagePackDir, int(s.config.TrustedCoreUID), int(s.config.CoreGID))
	if err != nil {
		http.Error(w, fmt.Sprintf("open srcWriter descriptor: %v", err), http.StatusInternalServerError)
		return
	}
	defer srcWriter.Close()

	for _, f := range manifestObj.Files {
		// Open destination parent session via artifactio
		sess, err := artifactio.OpenParentWriterForPath(pubWriter, f.Path, true)
		if err != nil {
			http.Error(w, fmt.Sprintf("open destination parent for %s: %v", f.Path, err), http.StatusInternalServerError)
			return
		}

		// Immutable target conflict rejection
		out, err := sess.TargetWriter.Ops().OpenFile(sess.FileName, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			if os.IsExist(err) {
				// Destination already exists: verify exact mode, owner, and sha256 bytes
				existingFile, openErr := sess.TargetWriter.Ops().OpenFile(sess.FileName, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
				if openErr != nil {
					_ = sess.SyncAndClose()
					http.Error(w, fmt.Sprintf("inspect existing file %s: %v", f.Path, openErr), http.StatusConflict)
					return
				}
				eInfo, statErr := sess.TargetWriter.Ops().Stat(existingFile)
				if statErr != nil || eInfo.Mode().Perm() != os.FileMode(f.Mode) || artifactio.CheckFileOwner(eInfo, 0, 0) != nil {
					_ = sess.TargetWriter.Ops().CloseFile(existingFile)
					_ = sess.SyncAndClose()
					http.Error(w, fmt.Sprintf("existing file %s attributes or owner mismatch", f.Path), http.StatusConflict)
					return
				}
				h := sha256.New()
				_, cpErr := io.Copy(h, existingFile)
				_ = sess.TargetWriter.Ops().CloseFile(existingFile)
				if cpErr != nil || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
					_ = sess.SyncAndClose()
					http.Error(w, fmt.Sprintf("destination file %s already exists with different bytes", f.Path), http.StatusConflict)
					return
				}
				_ = sess.SyncAndClose()
				continue
			}
			_ = sess.SyncAndClose()
			http.Error(w, fmt.Sprintf("create destination file %s: %v", f.Path, err), http.StatusInternalServerError)
			return
		}

		// Open source file via srcWriter
		srcSess, srcErr := artifactio.OpenParentWriterForPath(srcWriter, f.Path, false)
		if srcErr != nil {
			_ = sess.TargetWriter.Ops().CloseFile(out)
			_ = sess.SyncAndClose()
			http.Error(w, fmt.Sprintf("open source parent for %s: %v", f.Path, srcErr), http.StatusInternalServerError)
			return
		}
		srcFile, srcErr := srcSess.TargetWriter.Ops().OpenFile(srcSess.FileName, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if srcErr != nil {
			_ = srcSess.SyncAndClose()
			_ = sess.TargetWriter.Ops().CloseFile(out)
			_ = sess.SyncAndClose()
			http.Error(w, fmt.Sprintf("open source file %s: %v", f.Path, srcErr), http.StatusInternalServerError)
			return
		}

		hasher := sha256.New()
		mw := io.MultiWriter(out, hasher)
		_, cpErr := io.Copy(mw, srcFile)
		_ = srcSess.TargetWriter.Ops().CloseFile(srcFile)
		_ = srcSess.SyncAndClose()

		syncErr := sess.TargetWriter.Ops().Sync(out)
		chmodErr := sess.TargetWriter.Ops().Chmod(out, os.FileMode(f.Mode))
		chownErr := sess.TargetWriter.Ops().Chown(out, 0, 0)
		postSyncErr := sess.TargetWriter.Ops().Sync(out)
		closeErr := sess.TargetWriter.Ops().CloseFile(out)
		sessSyncErr := sess.SyncAndClose()

		if cpErr != nil || syncErr != nil || chmodErr != nil || chownErr != nil || postSyncErr != nil || closeErr != nil || sessSyncErr != nil {
			http.Error(w, "copy or fsync member failed", http.StatusInternalServerError)
			return
		}

		if hex.EncodeToString(hasher.Sum(nil)) != f.SHA256 {
			http.Error(w, fmt.Sprintf("sha256 mismatch copying %s", f.Path), http.StatusInternalServerError)
			return
		}
	}

	// Copy and fsync manifest.json into pubWriter, verifying exact bytes
	manSess, err := artifactio.OpenParentWriterForPath(pubWriter, "manifest.json", false)
	if err != nil {
		http.Error(w, "open manifest parent: "+err.Error(), http.StatusInternalServerError)
		return
	}
	manOut, err := manSess.TargetWriter.Ops().OpenFile("manifest.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		if os.IsExist(err) {
			// Destination already exists: verify exact mode 0644, owner root 0:0, and exact bytes match req.ManifestRaw
			existingMan, openErr := manSess.TargetWriter.Ops().OpenFile("manifest.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if openErr != nil {
				_ = manSess.SyncAndClose()
				http.Error(w, fmt.Sprintf("inspect existing manifest.json: %v", openErr), http.StatusConflict)
				return
			}
			mInfo, statErr := manSess.TargetWriter.Ops().Stat(existingMan)
			if statErr != nil || mInfo.Mode().Perm() != 0644 || artifactio.CheckFileOwner(mInfo, 0, 0) != nil {
				_ = manSess.TargetWriter.Ops().CloseFile(existingMan)
				_ = manSess.SyncAndClose()
				http.Error(w, "existing manifest.json attributes or owner mismatch", http.StatusConflict)
				return
			}
			existingRaw, readErr := io.ReadAll(existingMan)
			_ = manSess.TargetWriter.Ops().CloseFile(existingMan)
			if readErr != nil || !bytes.Equal(existingRaw, req.ManifestRaw) {
				_ = manSess.SyncAndClose()
				http.Error(w, "destination manifest.json already exists with different bytes; refusing overwrite", http.StatusConflict)
				return
			}
			_ = manSess.SyncAndClose()
		} else {
			_ = manSess.SyncAndClose()
			http.Error(w, "create manifest.json: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		_, cpErr := io.Copy(manOut, bytes.NewReader(req.ManifestRaw))
		syncErr := manSess.TargetWriter.Ops().Sync(manOut)
		chmodErr := manSess.TargetWriter.Ops().Chmod(manOut, 0644)
		chownErr := manSess.TargetWriter.Ops().Chown(manOut, 0, 0)
		postSyncErr := manSess.TargetWriter.Ops().Sync(manOut)
		closeErr := manSess.TargetWriter.Ops().CloseFile(manOut)
		sessErr := manSess.SyncAndClose()
		if cpErr != nil || syncErr != nil || chmodErr != nil || chownErr != nil || postSyncErr != nil || closeErr != nil || sessErr != nil {
			http.Error(w, "write manifest.json failed", http.StatusInternalServerError)
			return
		}
	}

	// Final destination root sync
	if err := pubWriter.SyncRoot(); err != nil {
		http.Error(w, fmt.Sprintf("sync pubDir root: %v", err), http.StatusInternalServerError)
		return
	}

	publishedExe := filepath.Join(pubDir, adapterPath)
	rcpt := HelperEffectReceipt{
		ActionID:        req.Permit.ActionID,
		OperationID:     req.Permit.OperationID,
		PackID:          req.Permit.PackID,
		Version:         req.Permit.Version,
		Action:          ActionPublish,
		Status:          StatusSucceeded,
		CoreGeneration:  req.Permit.CoreGeneration,
		LeaseGeneration: req.Permit.LeaseGeneration,
		Sequence:        req.Permit.Sequence,
		RequestDigest:   reqDigest,
		ExecutablePath:  publishedExe,
		ExecutableSHA:   adapterSHA,
		Detail:          adapterPath,
		RecordedAt:      time.Now().UTC(),
	}
	if err := s.persistReceipt(rcpt); err != nil {
		http.Error(w, fmt.Sprintf("persist publish receipt: %v", err), http.StatusInternalServerError)
		return
	}

	resp := PublishPackResponse{
		PublishedRoot:  pubDir,
		ExecutablePath: publishedExe,
		ExecutableSHA:  adapterSHA,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleStartPack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, err := s.authenticateCaller(r, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var req StartPackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	lock := s.getPackLock(req.Permit.PackID)
	lock.Lock()
	defer lock.Unlock()

	extra := []byte(strconv.Itoa(req.GateDelaySecs))
	reqDigest := s.computeRequestDigest(ActionStart, req.Permit, extra)
	isReplay, savedRcpt, err := s.validatePermitAndCheckReplayLocked(req.Permit, ActionStart, reqDigest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	unitName := fmt.Sprintf("acornfox-pack-%s.service", req.Permit.PackID)
	pubDir := filepath.Join(s.config.PacksDir, req.Permit.PackID, req.Permit.Version)
	socketPath := filepath.Join(s.config.PacksRunDir, req.Permit.PackID, "adapter.sock")

	packUID, _, packUser, packGroup, err := s.ensurePackUserAndGroup(req.Permit.PackID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if isReplay && savedRcpt != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(StartPackResponse{
			UnitName:             unitName,
			MainPID:              savedRcpt.MainPID,
			ProcessStartIdentity: savedRcpt.ProcessStartTime,
			SocketPath:           savedRcpt.SocketPath,
			ExecutableSHA256:     savedRcpt.ExecutableSHA,
			UID:                  packUID,
			InstanceID:           savedRcpt.InstanceID,
		})
		return
	}

	// 1. Verify that a valid publish receipt exists for this exact operation and version
	dir := filepath.Join(s.config.StateDir, req.Permit.PackID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		http.Error(w, "missing state directory", http.StatusBadRequest)
		return
	}
	var pubRcpt *HelperEffectReceipt
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ActionPublish+"_"+req.Permit.OperationID+"_") && strings.HasSuffix(e.Name(), ".json") {
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err == nil {
				var r HelperEffectReceipt
				if json.Unmarshal(data, &r) == nil && r.Action == ActionPublish && r.Status == StatusSucceeded && r.Version == req.Permit.Version {
					pubRcpt = &r
					break
				}
			}
		}
	}
	if pubRcpt == nil {
		http.Error(w, "missing matching publish effect receipt for start", http.StatusBadRequest)
		return
	}

	manData, err := os.ReadFile(filepath.Join(pubDir, "manifest.json"))
	if err != nil {
		http.Error(w, fmt.Sprintf("read published manifest: %v", err), http.StatusInternalServerError)
		return
	}
	manifestObj, err := packprotocol.ParseManifest(manData)
	if err != nil {
		http.Error(w, fmt.Sprintf("parse published manifest: %v", err), http.StatusInternalServerError)
		return
	}
	var adapterPath, adapterSHA string
	for _, e := range manifestObj.Entries {
		if e.Role == "adapter" {
			adapterPath = e.Path
			break
		}
	}
	for _, f := range manifestObj.Files {
		if f.Path == adapterPath {
			adapterSHA = f.SHA256
		}
	}
	if adapterPath == "" || adapterSHA != pubRcpt.ExecutableSHA {
		http.Error(w, "adapter entry not found or digest mismatch with published receipt", http.StatusInternalServerError)
		return
	}
	executablePath := filepath.Join(pubDir, adapterPath)

	var extraEnv []string
	if req.GateDelaySecs > 0 {
		extraEnv = append(extraEnv, fmt.Sprintf("GATE_DELAY_SECS=%d", req.GateDelaySecs))
	}

	tmplData := struct {
		PackID         string
		Version        string
		PackUser       string
		PackGroup      string
		ExecutablePath string
		SocketPath     string
		ExtraEnv       []string
	}{
		PackID:         req.Permit.PackID,
		Version:        req.Permit.Version,
		PackUser:       packUser,
		PackGroup:      packGroup,
		ExecutablePath: executablePath,
		SocketPath:     socketPath,
		ExtraEnv:       extraEnv,
	}

	// Render unit in memory first
	var unitBuf bytes.Buffer
	if err := s.tmpl.Execute(&unitBuf, tmplData); err != nil {
		http.Error(w, fmt.Sprintf("render unit: %v", err), http.StatusInternalServerError)
		return
	}

	unitDir := "/run/systemd/system"
	_ = os.MkdirAll(unitDir, 0755)
	unitPath := filepath.Join(unitDir, unitName)

	// Conditional atomic write: reject overwriting existing unproven unit
	if existing, err := os.ReadFile(unitPath); err == nil {
		if !bytes.Equal(existing, unitBuf.Bytes()) {
			http.Error(w, fmt.Sprintf("systemd unit %s already exists with different contents; refusing overwrite", unitName), http.StatusConflict)
			return
		}
	} else {
		tmpUnit := unitPath + ".tmp." + req.Permit.ActionID
		f, err := os.OpenFile(tmpUnit, os.O_CREATE|os.O_WRONLY|os.O_EXCL|syscall.O_NOFOLLOW, 0644)
		if err != nil {
			http.Error(w, fmt.Sprintf("create unit tmp: %v", err), http.StatusInternalServerError)
			return
		}
		if _, err := f.Write(unitBuf.Bytes()); err != nil {
			_ = f.Close()
			_ = os.Remove(tmpUnit)
			http.Error(w, "write unit: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			_ = os.Remove(tmpUnit)
			http.Error(w, "sync unit: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_ = f.Close()
		if err := os.Rename(tmpUnit, unitPath); err != nil {
			_ = os.Remove(tmpUnit)
			http.Error(w, "rename unit: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if d, err := os.Open(unitDir); err == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}

	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		http.Error(w, fmt.Sprintf("daemon-reload failed: %v: %s", err, string(out)), http.StatusInternalServerError)
		return
	}

	startCmd := exec.Command("systemctl", "start", unitName)
	if out, err := startCmd.CombinedOutput(); err != nil {
		http.Error(w, fmt.Sprintf("systemctl start failed: %v: %s", err, string(out)), http.StatusInternalServerError)
		return
	}

	var mainPID int32
	var startIdent string
	for i := 0; i < 30; i++ {
		time.Sleep(50 * time.Millisecond)
		out, err := exec.Command("systemctl", "show", "-p", "MainPID", "--value", unitName).Output()
		if err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil && pid > 0 {
				mainPID = int32(pid)
				startIdent, _ = localpeer.ReadProcessStartTime(mainPID)
				if startIdent != "" {
					break
				}
			}
		}
	}

	if mainPID <= 0 || startIdent == "" {
		http.Error(w, "failed to obtain live MainPID for started unit", http.StatusInternalServerError)
		return
	}

	att, err := localpeer.AttestLinuxProcess(mainPID)
	if err != nil {
		http.Error(w, fmt.Sprintf("attest started main process: %v", err), http.StatusInternalServerError)
		return
	}
	if att.UID != packUID {
		http.Error(w, fmt.Sprintf("started main process UID mismatch: got %d want %d", att.UID, packUID), http.StatusInternalServerError)
		return
	}
	if att.ExecutableSHA256 != adapterSHA {
		http.Error(w, "started process executable sha mismatch with verified adapter", http.StatusInternalServerError)
		return
	}
	if !strings.HasPrefix(att.ExecutablePath, pubDir) {
		http.Error(w, fmt.Sprintf("started executable path %s not in published dir %s", att.ExecutablePath, pubDir), http.StatusInternalServerError)
		return
	}

	instID := fmt.Sprintf("inst_%s_%d", req.Permit.Version, mainPID)
	rcpt := HelperEffectReceipt{
		ActionID:         req.Permit.ActionID,
		OperationID:      req.Permit.OperationID,
		PackID:           req.Permit.PackID,
		Version:          req.Permit.Version,
		Action:           ActionStart,
		Status:           StatusSucceeded,
		CoreGeneration:   req.Permit.CoreGeneration,
		LeaseGeneration:  req.Permit.LeaseGeneration,
		Sequence:         req.Permit.Sequence,
		RequestDigest:    reqDigest,
		InstanceID:       instID,
		MainPID:          mainPID,
		ExecutablePath:   executablePath,
		ExecutableSHA:    adapterSHA,
		ProcessStartTime: startIdent,
		SocketPath:       socketPath,
		Detail:           startIdent,
		RecordedAt:       time.Now().UTC(),
	}
	if err := s.persistReceipt(rcpt); err != nil {
		http.Error(w, fmt.Sprintf("persist start receipt: %v", err), http.StatusInternalServerError)
		return
	}

	resp := StartPackResponse{
		UnitName:             unitName,
		MainPID:              mainPID,
		ProcessStartIdentity: startIdent,
		SocketPath:           socketPath,
		ExecutableSHA256:     att.ExecutableSHA256,
		UID:                  packUID,
		InstanceID:           instID,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleObservePack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, err := s.authenticateCaller(r, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var req ObservePackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !packprotocol.ValidPackID(req.PackID) {
		http.Error(w, "invalid pack ID format", http.StatusBadRequest)
		return
	}

	lock := s.getPackLock(req.PackID)
	lock.Lock()
	defer lock.Unlock()

	// Strictly read-only: query existing account without mutating filesystem
	userName, _ := derivePackAccount(req.PackID)
	u, err := user.Lookup(userName)
	if err != nil {
		http.Error(w, fmt.Sprintf("owned user for pack %s not found: %v", req.PackID, err), http.StatusNotFound)
		return
	}
	packUIDVal, _ := strconv.ParseUint(u.Uid, 10, 32)
	packUID := uint32(packUIDVal)

	// Load owned publish / start receipts to resolve real expected identity
	dir := filepath.Join(s.config.StateDir, req.PackID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		http.Error(w, "no owned records for pack", http.StatusNotFound)
		return
	}
	var latestStartRcpt *HelperEffectReceipt
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ActionStart+"_") && strings.HasSuffix(e.Name(), ".json") {
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err == nil {
				var rcpt HelperEffectReceipt
				if json.Unmarshal(data, &rcpt) == nil && rcpt.Action == ActionStart && rcpt.Status == StatusSucceeded {
					if latestStartRcpt == nil || rcpt.Sequence > latestStartRcpt.Sequence {
						latestStartRcpt = &rcpt
					}
				}
			}
		}
	}

	unitName := fmt.Sprintf("acornfox-pack-%s.service", req.PackID)
	resp := ObservePackResponse{
		UnitStatus: "unknown",
	}

	out, _ := exec.Command("systemctl", "is-active", unitName).Output()
	unitStatus := strings.TrimSpace(string(out))
	resp.UnitStatus = unitStatus
	resp.Active = (unitStatus == "active")

	var liveMainPID int32
	var liveStartIdent string
	if pidOut, err := exec.Command("systemctl", "show", "-p", "MainPID", "--value", unitName).Output(); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(pidOut))); err == nil && pid > 0 {
			liveMainPID = int32(pid)
			liveStartIdent, _ = localpeer.ReadProcessStartTime(liveMainPID)
			resp.MainPID = liveMainPID
			resp.ProcessStartIdentity = liveStartIdent
		}
	}

	if req.PeerAttest != nil {
		pa := req.PeerAttest
		attResp := &PeerAttestResponse{
			UID: pa.UID,
		}

		if latestStartRcpt == nil {
			attResp.Attested = false
			attResp.Error = "no owned start receipt found for pack"
		} else if pa.ExpectedPackID == "" || pa.ExpectedVersion == "" || pa.ExpectedInstanceID == "" ||
			pa.ExpectedExecutableSHA == "" || pa.ExpectedStartTime == "" {
			attResp.Attested = false
			attResp.Error = "peer attest requires non-empty expected pack, version, instance, sha and start time"
		} else if pa.ExpectedPackID != req.PackID || pa.ExpectedVersion != latestStartRcpt.Version ||
			pa.ExpectedInstanceID != latestStartRcpt.InstanceID || pa.ExpectedExecutableSHA != latestStartRcpt.ExecutableSHA ||
			pa.ExpectedStartTime != latestStartRcpt.ProcessStartTime {
			attResp.Attested = false
			attResp.Error = "peer attest expected identity does not match owned start receipt"
		} else if liveMainPID <= 0 || pa.PID != liveMainPID || pa.UID != packUID {
			attResp.Attested = false
			attResp.Error = fmt.Sprintf("peer PID %d UID %d does not match live owned unit MainPID %d UID %d",
				pa.PID, pa.UID, liveMainPID, packUID)
		} else {
			att, err := localpeer.AttestLinuxProcess(pa.PID)
			if err != nil {
				attResp.Error = err.Error()
			} else {
				attResp.ExecutablePath = att.ExecutablePath
				attResp.ExecutableSHA256 = att.ExecutableSHA256
				attResp.ProcessStartIdentity = att.StartTime
				attResp.UID = att.UID

				match := true
				if att.UID != packUID {
					match = false
					attResp.Error = fmt.Sprintf("uid mismatch: got %d want %d", att.UID, packUID)
				} else if att.ExecutableSHA256 != latestStartRcpt.ExecutableSHA {
					match = false
					attResp.Error = fmt.Sprintf("exe sha mismatch: got %s want %s", att.ExecutableSHA256, latestStartRcpt.ExecutableSHA)
				} else if att.StartTime != latestStartRcpt.ProcessStartTime {
					match = false
					attResp.Error = fmt.Sprintf("start time mismatch: got %s want %s", att.StartTime, latestStartRcpt.ProcessStartTime)
				} else {
					pubDir := filepath.Join(s.config.PacksDir, req.PackID, latestStartRcpt.Version)
					if !strings.HasPrefix(att.ExecutablePath, pubDir) {
						match = false
						attResp.Error = fmt.Sprintf("exe path %s outside published version payload %s", att.ExecutablePath, pubDir)
					}
				}
				attResp.Attested = match
			}
		}
		resp.PeerAttestResult = attResp
	}

	if req.OperationID != "" {
		if err := domain.RequireID(domain.ID(req.OperationID), "operation_id"); err != nil || strings.Contains(req.OperationID, "/") || strings.Contains(req.OperationID, "\\") || strings.Contains(req.OperationID, "..") {
			http.Error(w, "invalid operation ID format for cancellation snapshot", http.StatusBadRequest)
			return
		}
		if _, err := versionpolicy.ParseSemver(req.Version); err != nil {
			http.Error(w, fmt.Sprintf("invalid semver version %q for cancellation snapshot: %v", req.Version, err), http.StatusBadRequest)
			return
		}

		var maxOpSeq int64 = 0
		var publishRcpt *HelperEffectReceipt
		var startRcpt *HelperEffectReceipt
		var stopRcpt *HelperEffectReceipt
		var abortRcpt *HelperEffectReceipt
		var switchRcpt *HelperEffectReceipt
		var opInstanceID string
		var foundRecords int
		var corruptRecord bool

		for _, e := range entries {
			if strings.Contains(e.Name(), "_"+req.OperationID+"_") && strings.HasSuffix(e.Name(), ".json") {
				data, err := os.ReadFile(filepath.Join(dir, e.Name()))
				if err != nil {
					corruptRecord = true
					break
				}
				var rcpt HelperEffectReceipt
				if err := json.Unmarshal(data, &rcpt); err != nil {
					corruptRecord = true
					break
				}
				// Strictly match exact owned scope: PackID, Version, and OperationID
				if rcpt.OperationID == req.OperationID {
					if rcpt.PackID != req.PackID || rcpt.Version != req.Version {
						corruptRecord = true
						break
					}
					foundRecords++
					if rcpt.Sequence > maxOpSeq {
						maxOpSeq = rcpt.Sequence
					}
					if rcpt.Action == ActionPublish && rcpt.Status == StatusSucceeded {
						if publishRcpt == nil || rcpt.Sequence > publishRcpt.Sequence {
							rcptCopy := rcpt
							publishRcpt = &rcptCopy
						}
					}
					if rcpt.Action == ActionStart && rcpt.Status == StatusSucceeded {
						if startRcpt == nil || rcpt.Sequence > startRcpt.Sequence {
							rcptCopy := rcpt
							startRcpt = &rcptCopy
						}
					}
					if rcpt.Action == ActionStopForRecovery && rcpt.Status == StatusStoppedForRecovery {
						if stopRcpt == nil || rcpt.Sequence > stopRcpt.Sequence {
							rcptCopy := rcpt
							stopRcpt = &rcptCopy
						}
					}
					if rcpt.Action == ActionAbort && rcpt.Status == StatusAborted {
						if abortRcpt == nil || rcpt.Sequence > abortRcpt.Sequence {
							rcptCopy := rcpt
							abortRcpt = &rcptCopy
						}
					}
					if rcpt.Action == ActionSwitch && rcpt.Status == StatusSucceeded {
						if switchRcpt == nil || rcpt.Sequence > switchRcpt.Sequence {
							rcptCopy := rcpt
							switchRcpt = &rcptCopy
						}
					}
				}
			}
		}

		if corruptRecord {
			http.Error(w, "corrupt or conflicting receipt encountered in operation scope", http.StatusInternalServerError)
			return
		}

		if foundRecords == 0 {
			http.Error(w, fmt.Sprintf("no owned records found for operation %s version %s", req.OperationID, req.Version), http.StatusNotFound)
			return
		}

		// Derive top-level instance ID strictly from the selected latest StartEffect
		if startRcpt != nil && startRcpt.InstanceID != "" {
			opInstanceID = startRcpt.InstanceID
		} else if switchRcpt != nil && switchRcpt.InstanceID != "" {
			opInstanceID = switchRcpt.InstanceID
		} else if stopRcpt != nil && stopRcpt.InstanceID != "" {
			opInstanceID = stopRcpt.InstanceID
		} else if abortRcpt != nil && abortRcpt.InstanceID != "" {
			opInstanceID = abortRcpt.InstanceID
		} else if publishRcpt != nil && publishRcpt.InstanceID != "" {
			opInstanceID = publishRcpt.InstanceID
		}

		// Verify systemctl status strictly under request context
		cmdActive := exec.CommandContext(r.Context(), "systemctl", "is-active", unitName)
		outActive, errActive := cmdActive.Output()
		activeText := strings.TrimSpace(string(outActive))

		var knownActiveState string
		if errActive == nil && activeText == "active" {
			knownActiveState = "active"
		} else if activeText == "inactive" || activeText == "failed" {
			var exitErr *exec.ExitError
			if errActive == nil || errors.As(errActive, &exitErr) {
				knownActiveState = activeText
			}
		}

		if knownActiveState == "" {
			http.Error(w, fmt.Sprintf("cannot determine unit status: err=%v output=%q", errActive, activeText), http.StatusInternalServerError)
			return
		}

		cmdPID := exec.CommandContext(r.Context(), "systemctl", "show", "-p", "MainPID", "--value", unitName)
		outPID, errPID := cmdPID.Output()
		if errPID != nil {
			http.Error(w, fmt.Sprintf("failed to query MainPID: %v", errPID), http.StatusInternalServerError)
			return
		}
		pidText := strings.TrimSpace(string(outPID))
		parsedPID, pErr := strconv.Atoi(pidText)
		if pErr != nil || parsedPID < 0 {
			http.Error(w, fmt.Sprintf("invalid MainPID output %q: %v", pidText, pErr), http.StatusInternalServerError)
			return
		}

		var isStopped bool
		if (knownActiveState == "inactive" || knownActiveState == "failed") && parsedPID == 0 {
			isStopped = true
		} else if knownActiveState == "active" && parsedPID > 0 {
			isStopped = false
		} else {
			http.Error(w, fmt.Sprintf("contradictory unit state: status=%s MainPID=%d", knownActiveState, parsedPID), http.StatusInternalServerError)
			return
		}

		resp.CancellationSnapshot = &OperationCancellationSnapshot{
			OperationID:          req.OperationID,
			PackID:               req.PackID,
			Version:              req.Version,
			MaxOperationSequence: maxOpSeq,
			UID:                  packUID,
			PublishEffect:        publishRcpt,
			StartEffect:          startRcpt,
			StopEffect:           stopRcpt,
			AbortEffect:          abortRcpt,
			SwitchEffect:         switchRcpt,
			UnitName:             unitName,
			InstanceID:           opInstanceID,
			ObservedStopped:      isStopped,
			ObservedAt:           time.Now().UTC(),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleStopPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, err := s.authenticateCaller(r, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var req StopPendingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	lock := s.getPackLock(req.Permit.PackID)
	lock.Lock()
	defer lock.Unlock()

	reqDigest := s.computeRequestDigest(ActionStopForRecovery, req.Permit, []byte(req.Reason))
	isReplay, savedRcpt, err := s.validatePermitAndCheckReplayLocked(req.Permit, ActionStopForRecovery, reqDigest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if isReplay && savedRcpt != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(StopPendingResponse{Stopped: true})
		return
	}

	unitName := fmt.Sprintf("acornfox-pack-%s.service", req.Permit.PackID)

	stopCmd := exec.Command("systemctl", "stop", unitName)
	if out, err := stopCmd.CombinedOutput(); err != nil {
		http.Error(w, fmt.Sprintf("systemctl stop failed: %v: %s", err, string(out)), http.StatusInternalServerError)
		return
	}

	// Strictly poll until unit is completely stopped and MainPID is 0
	stopped := false
	for i := 0; i < 40; i++ {
		out, _ := exec.Command("systemctl", "is-active", unitName).Output()
		status := strings.TrimSpace(string(out))
		if status == "inactive" || status == "failed" {
			pidOut, _ := exec.Command("systemctl", "show", "-p", "MainPID", "--value", unitName).Output()
			if pid, err := strconv.Atoi(strings.TrimSpace(string(pidOut))); err == nil && pid == 0 {
				stopped = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !stopped {
		http.Error(w, "unit failed to confirm exit within bound", http.StatusInternalServerError)
		return
	}

	rcpt := HelperEffectReceipt{
		ActionID:        req.Permit.ActionID,
		OperationID:     req.Permit.OperationID,
		PackID:          req.Permit.PackID,
		Version:         req.Permit.Version,
		Action:          ActionStopForRecovery,
		Status:          StatusStoppedForRecovery,
		CoreGeneration:  req.Permit.CoreGeneration,
		LeaseGeneration: req.Permit.LeaseGeneration,
		Sequence:        req.Permit.Sequence,
		RequestDigest:   reqDigest,
		Detail:          "stopped pending unit for recovery: " + unitName,
		RecordedAt:      time.Now().UTC(),
	}
	if err := s.persistReceipt(rcpt); err != nil {
		http.Error(w, fmt.Sprintf("persist stop receipt: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(StopPendingResponse{Stopped: true})
}

func (s *Server) handleAbortPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, err := s.authenticateCaller(r, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var req AbortPendingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	lock := s.getPackLock(req.Permit.PackID)
	lock.Lock()
	defer lock.Unlock()

	reqDigest := s.computeRequestDigest(ActionAbort, req.Permit, []byte(req.Reason))
	isReplay, savedRcpt, err := s.validatePermitAndCheckReplayLocked(req.Permit, ActionAbort, reqDigest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if isReplay && savedRcpt != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AbortPendingResponse{
			Aborted:        true,
			AbortReceiptID: savedRcpt.ActionID,
		})
		return
	}

	unitName := fmt.Sprintf("acornfox-pack-%s.service", req.Permit.PackID)

	stopCmd := exec.Command("systemctl", "stop", unitName)
	if out, err := stopCmd.CombinedOutput(); err != nil {
		http.Error(w, fmt.Sprintf("systemctl stop failed: %v: %s", err, string(out)), http.StatusInternalServerError)
		return
	}

	stopped := false
	for i := 0; i < 40; i++ {
		out, _ := exec.Command("systemctl", "is-active", unitName).Output()
		status := strings.TrimSpace(string(out))
		if status == "inactive" || status == "failed" {
			pidOut, _ := exec.Command("systemctl", "show", "-p", "MainPID", "--value", unitName).Output()
			if pid, err := strconv.Atoi(strings.TrimSpace(string(pidOut))); err == nil && pid == 0 {
				stopped = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !stopped {
		http.Error(w, "unit failed to confirm exit within bound for abort", http.StatusInternalServerError)
		return
	}

	rcpt := HelperEffectReceipt{
		ActionID:        req.Permit.ActionID,
		OperationID:     req.Permit.OperationID,
		PackID:          req.Permit.PackID,
		Version:         req.Permit.Version,
		Action:          ActionAbort,
		Status:          StatusAborted,
		CoreGeneration:  req.Permit.CoreGeneration,
		LeaseGeneration: req.Permit.LeaseGeneration,
		Sequence:        req.Permit.Sequence,
		RequestDigest:   reqDigest,
		Detail:          "permanently aborted operation: " + req.Reason,
		RecordedAt:      time.Now().UTC(),
	}
	if err := s.persistReceipt(rcpt); err != nil {
		http.Error(w, fmt.Sprintf("persist abort receipt: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(AbortPendingResponse{
		Aborted:        true,
		AbortReceiptID: req.Permit.ActionID,
	})
}

func (s *Server) handleSwitchCurrent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, err := s.authenticateCaller(r, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var req SwitchCurrentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	lock := s.getPackLock(req.Permit.PackID)
	lock.Lock()
	defer lock.Unlock()

	reqDigest := s.computeRequestDigest(ActionSwitch, req.Permit, []byte(req.RelativeTarget))
	isReplay, savedRcpt, err := s.validatePermitAndCheckReplayLocked(req.Permit, ActionSwitch, reqDigest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	packDir := filepath.Join(s.config.PacksDir, req.Permit.PackID)
	currentPath := filepath.Join(packDir, "current")

	if isReplay && savedRcpt != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SwitchCurrentResponse{
			Effect:  "existing_matched",
			Message: "current pointer set to " + req.RelativeTarget,
		})
		return
	}

	if req.RelativeTarget != req.Permit.Version {
		http.Error(w, "switch current relative target must equal permit version", http.StatusBadRequest)
		return
	}

	effect := "created"
	existingTarget, err := os.Readlink(currentPath)
	if err == nil {
		if existingTarget == req.RelativeTarget {
			effect = "existing_matched"
		} else {
			http.Error(w, fmt.Sprintf("current symlink points to %s, cannot switch to %s without upgrade protocol; requires TP02C", existingTarget, req.RelativeTarget), http.StatusConflict)
			return
		}
	} else if os.IsNotExist(err) {
		tmpSym := filepath.Join(packDir, "current.tmp."+req.Permit.ActionID)
		if err := os.Symlink(req.RelativeTarget, tmpSym); err != nil {
			http.Error(w, fmt.Sprintf("create symlink: %v", err), http.StatusInternalServerError)
			return
		}
		if err := os.Rename(tmpSym, currentPath); err != nil {
			_ = os.Remove(tmpSym)
			http.Error(w, fmt.Sprintf("rename symlink: %v", err), http.StatusInternalServerError)
			return
		}

		d, err := os.Open(packDir)
		if err != nil {
			http.Error(w, fmt.Sprintf("open pack dir: %v", err), http.StatusInternalServerError)
			return
		}
		if err := d.Sync(); err != nil {
			_ = d.Close()
			http.Error(w, fmt.Sprintf("sync pack dir: %v", err), http.StatusInternalServerError)
			return
		}
		_ = d.Close()
	} else {
		http.Error(w, fmt.Sprintf("read current symlink: %v", err), http.StatusInternalServerError)
		return
	}

	rcpt := HelperEffectReceipt{
		ActionID:        req.Permit.ActionID,
		OperationID:     req.Permit.OperationID,
		PackID:          req.Permit.PackID,
		Version:         req.Permit.Version,
		Action:          ActionSwitch,
		Status:          StatusSucceeded,
		CoreGeneration:  req.Permit.CoreGeneration,
		LeaseGeneration: req.Permit.LeaseGeneration,
		Sequence:        req.Permit.Sequence,
		RequestDigest:   reqDigest,
		CurrentTarget:   req.RelativeTarget,
		Detail:          "current -> " + req.RelativeTarget,
		RecordedAt:      time.Now().UTC(),
	}
	if err := s.persistReceipt(rcpt); err != nil {
		http.Error(w, fmt.Sprintf("persist switch receipt: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(SwitchCurrentResponse{
		Effect:  effect,
		Message: "current pointer set to " + req.RelativeTarget,
	})
}

func writeHelperJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleRuntimePeerAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	peer, ok := getPeer(r)
	if !ok {
		writeHelperJSON(w, http.StatusForbidden, RuntimePeerAttestResponse{Valid: false, Error: "missing peer credentials"})
		return
	}

	if s.config.RuntimeBindingPath == "" {
		writeHelperJSON(w, http.StatusForbidden, RuntimePeerAttestResponse{Valid: false, Error: "runtime binding unconfigured"})
		return
	}

	binding, err := localpeer.LoadProtectedRuntimePeerBinding(s.config.RuntimeBindingPath)
	if err != nil || binding == nil {
		writeHelperJSON(w, http.StatusForbidden, RuntimePeerAttestResponse{Valid: false, Error: "runtime binding unavailable or invalid"})
		return
	}

	callerAtt, err := localpeer.AttestLinuxProcess(peer.PID)
	if err != nil {
		writeHelperJSON(w, http.StatusForbidden, RuntimePeerAttestResponse{Valid: false, Error: "attest caller failed: " + err.Error()})
		return
	}

	var callerRole string
	if peer.UID == binding.CoreUID && peer.PID == binding.CorePID &&
		callerAtt.ExecutableSHA256 == binding.CoreExeSHA && callerAtt.StartTime == binding.CoreStartTime {
		callerRole = "core"
	} else if peer.UID == binding.ContainerUID && peer.PID == binding.ContainerPID &&
		callerAtt.ExecutableSHA256 == binding.ContainerExeSHA && callerAtt.StartTime == binding.ContainerStartTime {
		callerRole = "container"
	} else if binding.HasSourceBuild() && peer.UID == binding.SourceBuildUID && peer.PID == binding.SourceBuildPID && callerAtt.ExecutableSHA256 == binding.SourceBuildExeSHA && callerAtt.StartTime == binding.SourceBuildStartTime {
		callerRole = "source-build"
	} else if binding.HasGateway() && peer.UID == binding.GatewayUID && peer.PID == binding.GatewayPID && callerAtt.ExecutableSHA256 == binding.GatewayExeSHA && callerAtt.StartTime == binding.GatewayStartTime {
		callerRole = "gateway"
	} else {
		writeHelperJSON(w, http.StatusForbidden, RuntimePeerAttestResponse{Valid: false, Error: "untrusted caller process identity"})
		return
	}

	var req RuntimePeerAttestRequest
	bodyData, err := io.ReadAll(io.LimitReader(r.Body, 16<<10+1))
	if err != nil {
		writeHelperJSON(w, http.StatusBadRequest, RuntimePeerAttestResponse{Valid: false, Error: "read request body: " + err.Error()})
		return
	}
	if len(bodyData) > 16<<10 {
		writeHelperJSON(w, http.StatusBadRequest, RuntimePeerAttestResponse{Valid: false, Error: "request body exceeds bound (16KB)"})
		return
	}
	dec := json.NewDecoder(bytes.NewReader(bodyData))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeHelperJSON(w, http.StatusBadRequest, RuntimePeerAttestResponse{Valid: false, Error: "decode request: " + err.Error()})
		return
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeHelperJSON(w, http.StatusBadRequest, RuntimePeerAttestResponse{Valid: false, Error: "extraneous content after request JSON"})
		return
	}

	expectedPID, expectedUID, expectedExeSHA, expectedStartTime, allowed := runtimePeerTarget(binding, callerRole, req.TargetRole)
	if !allowed {
		writeHelperJSON(w, http.StatusForbidden, RuntimePeerAttestResponse{Valid: false, Error: "runtime role pair is not permitted"})
		return
	}
	if req.PeerPID != expectedPID || req.PeerUID != expectedUID {
		writeHelperJSON(w, http.StatusForbidden, RuntimePeerAttestResponse{Valid: false, Error: "target PID or UID mismatch with binding"})
		return
	}
	if req.BindingDigest == "" || req.BindingDigest != binding.Digest() {
		writeHelperJSON(w, http.StatusForbidden, RuntimePeerAttestResponse{Valid: false, Error: "binding digest must be non-empty and match authoritative binding"})
		return
	}

	targetAtt, err := localpeer.AttestLinuxProcess(req.PeerPID)
	if err != nil {
		writeHelperJSON(w, http.StatusForbidden, RuntimePeerAttestResponse{Valid: false, Error: "attest target failed: " + err.Error()})
		return
	}

	if targetAtt.UID != expectedUID || targetAtt.StartTime != expectedStartTime || targetAtt.ExecutableSHA256 != expectedExeSHA {
		writeHelperJSON(w, http.StatusForbidden, RuntimePeerAttestResponse{Valid: false, Error: "target process identity mismatch"})
		return
	}

	writeHelperJSON(w, http.StatusOK, RuntimePeerAttestResponse{
		Valid:         true,
		PID:           req.PeerPID,
		UID:           req.PeerUID,
		ExeSHA:        targetAtt.ExecutableSHA256,
		StartTime:     targetAtt.StartTime,
		ObservedAt:    time.Now().UTC(),
		BindingDigest: binding.Digest(),
	})
}

// Only these fixed role pairs can ask the root helper to inspect their peer.
func runtimePeerTarget(b *localpeer.RuntimePeerBinding, caller, target string) (int32, uint32, string, string, bool) {
	if caller == "core" && target == "container" {
		return b.ContainerPID, b.ContainerUID, b.ContainerExeSHA, b.ContainerStartTime, true
	}
	if (caller == "container" || (caller == "source-build" && b.HasSourceBuild())) && target == "core" {
		return b.CorePID, b.CoreUID, b.CoreExeSHA, b.CoreStartTime, true
	}
	if caller == "core" && target == "source-build" && b.HasSourceBuild() {
		return b.SourceBuildPID, b.SourceBuildUID, b.SourceBuildExeSHA, b.SourceBuildStartTime, true
	}
	if caller == "core" && target == "gateway" && b.HasGateway() {
		return b.GatewayPID, b.GatewayUID, b.GatewayExeSHA, b.GatewayStartTime, true
	}
	if caller == "gateway" && target == "core" && b.HasGateway() {
		return b.CorePID, b.CoreUID, b.CoreExeSHA, b.CoreStartTime, true
	}
	return 0, 0, "", "", false
}
