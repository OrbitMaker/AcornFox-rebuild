package source

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/foundation"
)

func TestWorkspaceCapacityConfigIsFiniteAndOverflowSafe(t *testing.T) {
	limits := foundation.ArchiveLimits{MaxFiles: 1, MaxUnpackedBytes: 1024}
	provider, err := New(Config{UploadRoot: t.TempDir(), WorkspaceRoot: filepath.Join(t.TempDir(), "workspaces"), Limits: limits})
	if err != nil || provider.workspaceCapacityBytes <= 0 || provider.workspaceCapacityEntries <= 0 {
		t.Fatalf("finite defaults provider=%+v err=%v", provider, err)
	}
	reserve, err := workspaceAdmissionReserve(domain.SourceGitHTTPS, limits)
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []Config{
		{UploadRoot: t.TempDir(), WorkspaceRoot: filepath.Join(t.TempDir(), "workspaces"), Limits: limits, WorkspaceCapacityBytes: -1},
		{UploadRoot: t.TempDir(), WorkspaceRoot: filepath.Join(t.TempDir(), "workspaces"), Limits: limits, WorkspaceCapacityEntries: -1},
		{UploadRoot: t.TempDir(), WorkspaceRoot: filepath.Join(t.TempDir(), "workspaces"), Limits: limits, WorkspaceCapacityBytes: reserve.bytes - 1, WorkspaceCapacityEntries: reserve.entries},
		{UploadRoot: t.TempDir(), WorkspaceRoot: filepath.Join(t.TempDir(), "workspaces"), Limits: limits, WorkspaceCapacityBytes: reserve.bytes, WorkspaceCapacityEntries: reserve.entries - 1},
		{UploadRoot: t.TempDir(), WorkspaceRoot: filepath.Join(t.TempDir(), "workspaces"), Limits: limits, WorkspaceCapacityBytes: reserve.bytes, WorkspaceCapacityEntries: reserve.entries},
		{UploadRoot: t.TempDir(), WorkspaceRoot: filepath.Join(t.TempDir(), "workspaces"), Limits: limits, WorkspaceOperationalReserveBytes: -1},
		{UploadRoot: t.TempDir(), WorkspaceRoot: filepath.Join(t.TempDir(), "workspaces"), Limits: limits, WorkspaceOperationalReserveEntries: -1},
		{UploadRoot: t.TempDir(), WorkspaceRoot: filepath.Join(t.TempDir(), "workspaces"), Limits: limits, WorkspaceOperationalReserveBytes: defaultWorkspaceOperationalReserveBytes - 1},
		{UploadRoot: t.TempDir(), WorkspaceRoot: filepath.Join(t.TempDir(), "workspaces"), Limits: foundation.ArchiveLimits{MaxFiles: math.MaxInt64, MaxUnpackedBytes: 1}},
	} {
		if _, err := New(config); err == nil {
			t.Fatal("invalid or undersized workspace capacity was accepted")
		}
	}
}

func TestWorkspaceFilesystemAvailabilityRejectsBeforeGitAndNormalAvailabilityPasses(t *testing.T) {
	fixture := newHTTPSGitFixture(t, false)
	provider := fixture.provider(t)
	request := contracts.PrepareSourceRequest{ApplicationID: "app_filesystem_capacity", Kind: domain.SourceGitHTTPS, Locator: fixture.URL("repo.git"), Ref: "main", Operation: contracts.OperationContext{IdempotencyKey: "filesystem-capacity"}}
	reserve, err := workspaceAdmissionReserve(domain.SourceGitHTTPS, provider.limits)
	if err != nil {
		t.Fatal(err)
	}
	provider.filesystemAvailability = func(string) (workspaceFilesystemAvailability, error) {
		return workspaceFilesystemAvailability{bytes: reserve.bytes + provider.workspaceOperationalReserveBytes - 1, entries: reserve.entries + provider.workspaceOperationalReserveEntries}, nil
	}
	if _, err := provider.Prepare(context.Background(), request); err == nil {
		t.Fatal("low filesystem bytes admitted Git request")
	} else {
		assertProviderCode(t, err, contracts.ErrUnavailable)
	}
	if fixture.requests.Load() != 0 {
		t.Fatal("low filesystem admission contacted Git")
	}
	assertNoPublishedGitWorkspace(t, fixture.workspace)

	provider.filesystemAvailability = func(string) (workspaceFilesystemAvailability, error) {
		return workspaceFilesystemAvailability{bytes: math.MaxInt64, entries: math.MaxInt64}, nil
	}
	if _, err := provider.Prepare(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if fixture.requests.Load() == 0 {
		t.Fatal("normal filesystem availability did not materialize Git")
	}
}

func TestWorkspaceCapacityReleaseInvalidatesCachedReplay(t *testing.T) {
	fixture := newHTTPSGitFixture(t, false)
	provider := fixture.provider(t)
	request := contracts.PrepareSourceRequest{ApplicationID: "app_release_replay", Kind: domain.SourceGitHTTPS, Locator: fixture.URL("repo.git"), Ref: "main", Operation: contracts.OperationContext{IdempotencyKey: "release-replay"}}
	first, err := provider.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Release(context.Background(), contracts.ReleaseSourceRequest{Revision: first.Revision, Operation: contracts.OperationContext{IdempotencyKey: "release-replay-release", Actor: "test"}}); err != nil {
		t.Fatal(err)
	}
	requests := fixture.requests.Load()
	recreated, err := provider.Prepare(context.Background(), request)
	if err != nil || recreated.Revision.ID == first.Revision.ID || fixture.requests.Load() <= requests {
		t.Fatalf("post-Release same-key replay reused stale workspace: result=%+v err=%v requests=%d before=%d", recreated.Revision, err, fixture.requests.Load(), requests)
	}
}

func TestWorkspaceRootLockSerializesConcurrentReleaseAndReplay(t *testing.T) {
	fixture := newHTTPSGitFixture(t, false)
	provider := fixture.provider(t)
	request := contracts.PrepareSourceRequest{ApplicationID: "app_release_race", Kind: domain.SourceGitHTTPS, Locator: fixture.URL("repo.git"), Ref: "main", Operation: contracts.OperationContext{IdempotencyKey: "release-race"}}
	first, err := provider.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 2)
	go func() {
		completed <- provider.Release(context.Background(), contracts.ReleaseSourceRequest{Revision: first.Revision, Operation: contracts.OperationContext{IdempotencyKey: "release-race-release", Actor: "test"}})
	}()
	go func() { _, err := provider.Prepare(context.Background(), request); completed <- err }()
	for range 2 {
		select {
		case err := <-completed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent Release/replay deadlocked")
		}
	}
}

func TestWorkspaceCapacityRejectsNewGitBeforeNetworkButReplaysAtCap(t *testing.T) {
	fixture := newHTTPSGitFixture(t, false)
	provider := fixture.provider(t)
	request := contracts.PrepareSourceRequest{ApplicationID: "app_capacity", Kind: domain.SourceGitHTTPS, Locator: fixture.URL("repo.git"), Ref: "main", Operation: contracts.OperationContext{IdempotencyKey: "capacity-first"}}
	first, err := provider.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	usage, err := measureWorkspacePool(fixture.workspace)
	if err != nil {
		t.Fatal(err)
	}
	provider.workspaceCapacityBytes, provider.workspaceCapacityEntries = usage.bytes, usage.entries
	requests := fixture.requests.Load()
	if replay, err := provider.Prepare(context.Background(), request); err != nil || replay.Revision.ID != first.Revision.ID || fixture.requests.Load() != requests {
		t.Fatalf("same-key replay at cap=%+v err=%v requests=%d before=%d", replay, err, fixture.requests.Load(), requests)
	}
	next := request
	next.Operation.IdempotencyKey = "capacity-next"
	if _, err := provider.Prepare(context.Background(), next); err == nil {
		t.Fatal("new Git request was admitted at cap")
	} else {
		assertProviderCode(t, err, contracts.ErrUnavailable)
	}
	if fixture.requests.Load() != requests {
		t.Fatal("capacity rejection contacted Git")
	}
	assertRetainedGitWorkspaceWithoutTransientEntries(t, fixture.workspace, "fixture\n")

	fresh := fixture.provider(t)
	fresh.workspaceCapacityBytes, fresh.workspaceCapacityEntries = usage.bytes, usage.entries
	if _, err := fresh.Prepare(context.Background(), next); err == nil {
		t.Fatal("fresh provider did not re-measure full workspace pool")
	}
}

func TestWorkspaceCapacityReleaseFreesAdmissionBudget(t *testing.T) {
	fixture := newHTTPSGitFixture(t, false)
	provider := fixture.provider(t)
	request := contracts.PrepareSourceRequest{ApplicationID: "app_capacity_release", Kind: domain.SourceGitHTTPS, Locator: fixture.URL("repo.git"), Ref: "main", Operation: contracts.OperationContext{IdempotencyKey: "capacity-release-first"}}
	first, err := provider.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	usage, err := measureWorkspacePool(fixture.workspace)
	if err != nil {
		t.Fatal(err)
	}
	reserve, err := workspaceAdmissionReserve(domain.SourceGitHTTPS, provider.limits)
	if err != nil {
		t.Fatal(err)
	}
	provider.workspaceCapacityBytes, err = safeWorkspaceAdd(usage.bytes, reserve.bytes-1)
	if err != nil {
		t.Fatal(err)
	}
	provider.workspaceCapacityEntries, err = safeWorkspaceAdd(usage.entries, reserve.entries-1)
	if err != nil {
		t.Fatal(err)
	}
	next := request
	next.Operation.IdempotencyKey = "capacity-release-next"
	if _, err := provider.Prepare(context.Background(), next); err == nil {
		t.Fatal("new request was admitted before explicit Release freed capacity")
	}
	if err := provider.Release(context.Background(), contracts.ReleaseSourceRequest{Revision: first.Revision, Operation: contracts.OperationContext{IdempotencyKey: "capacity-release", Actor: "test"}}); err != nil {
		t.Fatal(err)
	}
	fixture.advanceMain(t, "fixture v2\n")
	if nextResult, err := provider.Prepare(context.Background(), next); err != nil || nextResult.Revision.WorkspaceRef == first.Revision.WorkspaceRef {
		t.Fatalf("explicit Release did not free admission capacity: next=%+v err=%v", nextResult, err)
	}
}

func TestWorkspacePoolFailsClosedForUnknownSymlinkAndMetadataHeavyTrees(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspaces")
	if err := os.MkdirAll(filepath.Join(root, strings.Repeat("a", 64)), 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 32; index++ {
		if err := os.WriteFile(filepath.Join(root, strings.Repeat("a", 64), "zero-"+strings.Repeat("x", index)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	usage, err := measureWorkspacePool(root)
	if err != nil || usage.entries < 33 || usage.bytes < usage.entries*workspaceMetadataBytes {
		t.Fatalf("metadata-heavy zero-byte tree usage=%+v err=%v", usage, err)
	}
	if err := os.WriteFile(filepath.Join(root, "unexpected-ACORNFOX_CAPACITY_CANARY"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := measureWorkspacePool(root); err == nil {
		t.Fatal("unknown pool entry was accepted")
	}
	if err := os.Remove(filepath.Join(root, "unexpected-ACORNFOX_CAPACITY_CANARY")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, strings.Repeat("a", 64)), filepath.Join(root, strings.Repeat("b", 64))); err != nil {
		t.Fatal(err)
	}
	if _, err := measureWorkspacePool(root); err == nil {
		t.Fatal("symlink workspace entry was accepted")
	}
	if err := os.Remove(filepath.Join(root, strings.Repeat("b", 64))); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, strings.Repeat("c", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := measureWorkspacePool(root); err == nil {
		t.Fatal("special workspace entry was accepted")
	}
}

func TestWorkspaceRootLockSerializesAdmission(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspaces")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	firstRelease, err := acquireWorkspaceRootLock(root)
	if err != nil {
		t.Fatal(err)
	}
	defer firstRelease()
	acquired := make(chan func(), 1)
	go func() {
		release, lockErr := acquireWorkspaceRootLock(root)
		if lockErr == nil {
			acquired <- release
		}
	}()
	select {
	case release := <-acquired:
		release()
		t.Fatal("second root lock acquired before first release")
	case <-time.After(50 * time.Millisecond):
	}
	firstRelease()
	select {
	case release := <-acquired:
		release()
	case <-time.After(time.Second):
		t.Fatal("second root lock did not acquire after release")
	}
}
