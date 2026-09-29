//go:build linux

package application_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/application"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/hosthelper"
	"github.com/acornfox/acornfox/internal/imageexecution"
	"github.com/acornfox/acornfox/internal/localpeer"
	"github.com/acornfox/acornfox/internal/persistence/sqlite"
)

type runtimeLossInputs struct {
	FixtureRoot    string    `json:"fixture_root"`
	CoreUID        uint32    `json:"core_uid"`
	CoreGID        uint32    `json:"core_gid"`
	DataDirectory  string    `json:"data_directory"`
	BindingPath    string    `json:"binding_path"`
	TaskID         domain.ID `json:"task_id"`
	OperationID    domain.ID `json:"operation_id"`
	NativeCorePID  int32     `json:"stopped_native_core_pid"`
	EventFD        int       `json:"event_fd"`
	TimeoutSeconds int       `json:"timeout_seconds"`
	HoldSeconds    int       `json:"hold_seconds"`
	WorkerOwner    string    `json:"worker_owner"`
}

type runtimeLossEvent struct {
	Phase          string    `json:"phase"`
	PID            int       `json:"pid"`
	TaskID         domain.ID `json:"task_id,omitempty"`
	OperationID    domain.ID `json:"operation_id,omitempty"`
	CoreGeneration int64     `json:"core_generation,omitempty"`
	// Result contains only the original non-credential worker receipt/fence fields.
	Result *appcontracts.CommitImageExecutionResultInput `json:"result,omitempty"`
}

// The only decorated method is commit. All authority, task and storage behavior
// remains the actual Store. It never forwards a result to the underlying commit.
type beforeCommitStore struct {
	*sqlite.Store
	inputs  runtimeLossInputs
	pipe    *json.Encoder
	reached bool
}

func (s *beforeCommitStore) CommitImageExecutionResult(ctx context.Context, original appcontracts.CommitImageExecutionResultInput) error {
	if s.reached || original.TaskID != s.inputs.TaskID || original.OperationID != s.inputs.OperationID {
		return errors.New("unexpected commit boundary")
	}
	if original.ContainerID == "" || original.ContainerName == "" || original.ImageID == "" || original.ManifestDigest == "" || original.HostPort <= 0 || original.ObservedAt.IsZero() {
		return errors.New("incomplete original receipt at commit boundary")
	}
	s.reached = true
	if err := s.pipe.Encode(runtimeLossEvent{Phase: "before_commit", PID: os.Getpid(), TaskID: original.TaskID, OperationID: original.OperationID, CoreGeneration: original.CoreGeneration, Result: &original}); err != nil {
		return fmt.Errorf("write parent barrier: %w", err)
	}
	timer := time.NewTimer(time.Duration(s.inputs.HoldSeconds) * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("bounded before-commit hold expired without committing")
	}
}

func readRuntimeLossInputs(path string) (runtimeLossInputs, error) {
	var cfg runtimeLossInputs
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "recovery-harness-input.json" || filepath.Base(filepath.Dir(path)) != "trust" {
		return cfg, errors.New("input path is outside the exact fixture trust boundary")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return cfg, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0027 != 0 || info.Size() > 8192 {
		return cfg, errors.New("input file is not bounded root-protected fixture data")
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		d, err := os.Lstat(dir)
		if err != nil {
			return cfg, err
		}
		ds, ok := d.Sys().(*syscall.Stat_t)
		if !ok || ds.Uid != 0 || !d.IsDir() || d.Mode().Perm()&0022 != 0 {
			return cfg, errors.New("input ancestry is not root-protected")
		}
		if dir == "/" {
			break
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return cfg, errors.New("input file changed during open")
	}
	dec := json.NewDecoder(io.LimitReader(file, 8193))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return cfg, errors.New("trailing input data")
	}
	if !filepath.IsAbs(cfg.FixtureRoot) || filepath.Clean(cfg.FixtureRoot) != cfg.FixtureRoot || cfg.FixtureRoot == "/" || path != cfg.FixtureRoot+"/trust/recovery-harness-input.json" || cfg.CoreUID == 0 || cfg.CoreGID == 0 || cfg.DataDirectory != cfg.FixtureRoot+"/core-data" || cfg.BindingPath != cfg.FixtureRoot+"/trust/runtime-binding.json" || cfg.TaskID.Empty() || cfg.OperationID.Empty() || cfg.NativeCorePID <= 0 || cfg.EventFD < 3 || cfg.EventFD > 64 || cfg.TimeoutSeconds < 60 || cfg.TimeoutSeconds > 300 || cfg.HoldSeconds < 15 || cfg.HoldSeconds > 120 || !strings.HasPrefix(cfg.WorkerOwner, "tp06a-loss-") {
		return cfg, errors.New("explicit owned fixture inputs are incomplete")
	}
	return cfg, nil
}

// This child is never ordinary CI or a production failure flag. It requires a
// dedicated parent pipe, sole physical Store lock, root-published test-binary
// identity and the real container/helper peer chain.
func TestImageExecutionRuntimeLossBeforeCommit(t *testing.T) {
	if os.Getenv("ACORNFOX_TP06A_RUNTIME_LOSS") != "1" {
		t.Skip("explicit task-private runtime-loss opt-in required; skip is not runtime acceptance")
	}
	cfg, err := readRuntimeLossInputs(os.Getenv("ACORNFOX_TP06A_RUNTIME_LOSS_CONFIG"))
	if err != nil {
		t.Fatal("invalid protected runtime-loss inputs")
	}
	if uint32(os.Getuid()) != cfg.CoreUID || uint32(os.Getgid()) != cfg.CoreGID {
		t.Fatal("runtime-loss child must use the exact fixture Core identity")
	}
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal("cannot verify child groups")
	}
	for _, g := range groups {
		if uint32(g) != cfg.CoreGID {
			t.Fatal("Core child has unexpected supplementary privilege")
		}
	}
	for _, name := range []string{"root", "docker", "sudo", "wheel"} {
		if group, err := user.LookupGroup(name); err == nil && group.Gid == strconv.FormatUint(uint64(cfg.CoreGID), 10) {
			t.Fatal("Core child must not use a privileged group")
		}
	}
	marker := filepath.Join(cfg.FixtureRoot, "owner-marker.json")
	mi, err := os.Lstat(marker)
	if err != nil || !mi.Mode().IsRegular() {
		t.Fatal("owned fixture marker is missing")
	}
	ms, ok := mi.Sys().(*syscall.Stat_t)
	if !ok || ms.Uid != 0 || mi.Mode().Perm()&0022 != 0 {
		t.Fatal("fixture marker is not root-protected")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("cannot verify test executable")
	}
	ei, err := os.Lstat(executable)
	if err != nil || !ei.Mode().IsRegular() {
		t.Fatal("test executable is not a regular installed binary")
	}
	es, ok := ei.Sys().(*syscall.Stat_t)
	if !ok || es.Uid != 0 || ei.Mode().Perm()&0022 != 0 {
		t.Fatal("test binary is not root-protected")
	}

	if _, err := os.Stat("/proc/" + strconv.Itoa(int(cfg.NativeCorePID))); !os.IsNotExist(err) {
		t.Fatal("native Core process has not completely exited")
	}
	pipe := os.NewFile(uintptr(cfg.EventFD), "owned-parent-barrier")
	if pipe == nil {
		t.Fatal("parent pipe missing")
	}
	defer pipe.Close()
	pipeInfo, err := pipe.Stat()
	if err != nil || pipeInfo.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("barrier descriptor is not a pipe")
	}
	pipeOwner, ok := pipeInfo.Sys().(*syscall.Stat_t)
	if !ok || pipeOwner.Uid != 0 {
		t.Fatal("barrier pipe must be parent root-owned")
	}
	events := json.NewEncoder(pipe)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.TimeoutSeconds)*time.Second)
	defer cancel()
	if err := events.Encode(runtimeLossEvent{Phase: "awaiting_root_binding", PID: os.Getpid()}); err != nil {
		t.Fatal("parent pipe unavailable")
	}
	var binding *localpeer.RuntimePeerBinding
	waitDeadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(waitDeadline) {
		b, loadErr := localpeer.LoadProtectedRuntimePeerBinding(cfg.BindingPath)
		if loadErr == nil && b != nil && b.CorePID == int32(os.Getpid()) && b.CoreUID == uint32(os.Getuid()) && localpeer.VerifyProcessIdentity(b.CorePID, b.CoreUID, b.CoreExeSHA, b.CoreStartTime) == nil {
			binding = b
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("binding wait context expired")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if binding == nil {
		t.Fatal("actual test-binary binding was not published")
	}
	helper := hosthelper.NewClient(hosthelper.DefaultHelperSocketPath, 5*time.Second)
	peerCheck := func(pid int32, uid uint32) error {
		return imageexecution.VerifyCounterpartPeerViaHelper(ctx, helper, "container", pid, uid, binding)
	}
	if err := peerCheck(binding.ContainerPID, binding.ContainerUID); err != nil {
		t.Fatal("real container/helper peer verification failed")
	}
	store, err := sqlite.Open(sqlite.Config{DataDirectory: cfg.DataDirectory})
	if err != nil {
		t.Fatal("sole physical Store open failed")
	}
	defer store.Close()
	task, err := store.GetTask(ctx, cfg.TaskID)
	if err != nil || task.OperationID != cfg.OperationID || task.State != appcontracts.TaskReady || task.Attempt >= task.MaxAttempts {
		t.Fatal("the exact expected task is not claimable")
	}
	// Read-only connection only; a second product Store would advance generation.
	ro, err := sql.Open("sqlite", "file:"+filepath.Join(cfg.DataDirectory, "acornfox.db")+"?mode=ro")
	if err != nil {
		t.Fatal("readonly eligibility check failed")
	}
	var count int
	err = ro.QueryRowContext(ctx, `SELECT count(*) FROM task_leases WHERE json_extract(payload,'$.kind')='image.deploy' AND attempt<min(max_attempts,3) AND (state='ready' OR (state='leased' AND (lease_until<=? OR core_generation<?)))`, sqlite.FormatTime(time.Now().UTC()), store.CoreGeneration()).Scan(&count)
	closeErr := ro.Close()
	if err != nil || closeErr != nil || count != 1 {
		t.Fatal("expected exactly one eligible owned image task")
	}
	decorated := &beforeCommitStore{Store: store, inputs: cfg, pipe: events}
	authority, err := imageexecution.NewCoreAuthorityServer(imageexecution.CoreAuthorityServerConfig{Store: decorated, SocketPath: binding.AuthoritySocket, ExpectedContainerUID: binding.ContainerUID, ExpectedContainerPID: binding.ContainerPID, ContainerPeerValidator: peerCheck})
	if err != nil {
		t.Fatal("real authority server failed")
	}
	defer authority.Close()
	client, err := imageexecution.NewClient(imageexecution.ClientConfig{SocketPath: binding.ContainerSocket, ExpectedUID: binding.ContainerUID, ExpectedPID: binding.ContainerPID, PeerValidator: peerCheck, Timeout: 120 * time.Second})
	if err != nil {
		t.Fatal("real Unix client failed")
	}
	readyDeadline := time.Now().Add(45 * time.Second)
	ready := false
	for time.Now().Before(readyDeadline) {
		if err := client.CheckReady(ctx); err == nil {
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("business readiness context expired")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatal("real container business endpoint is not ready")
	}
	worker, err := application.NewImageExecutionWorker(application.ImageExecutionWorkerConfig{WorkerID: cfg.WorkerOwner, LeaseDuration: 120 * time.Second, MaxAttempts: 3, Store: decorated, TaskRepo: store, Client: client})
	if err != nil {
		t.Fatal("production worker construction failed")
	}
	if err := events.Encode(runtimeLossEvent{Phase: "authority_ready", PID: os.Getpid(), TaskID: cfg.TaskID, OperationID: cfg.OperationID, CoreGeneration: store.CoreGeneration()}); err != nil {
		t.Fatal("parent pipe unavailable")
	}
	handled, pollErr := worker.PollOnce(ctx)
	if !handled || !decorated.reached {
		t.Fatal("real worker did not reach the original commit boundary")
	}
	if pollErr != nil {
		t.Fatal("bounded commit barrier released without underlying commit; parent did not interrupt")
	}
	t.Fatal("runtime-loss child unexpectedly completed")
}
