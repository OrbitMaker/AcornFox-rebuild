package imagegc

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

var fixedGCNow = time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)

func gcConfig() Config {
	return Config{
		KeepSuccessfulReleases: 3,
		SoftWatermarkPercent:   80,
		HardWatermarkPercent:   90,
		Clock:                  func() time.Time { return fixedGCNow },
	}
}

func gcImage(name string, value int) domain.ImageDigest {
	image, err := domain.ParseImageDigest("opencard/"+name, fmt.Sprintf("sha256:%064x", value))
	if err != nil {
		panic(err)
	}
	return image
}

func gcResource(image domain.ImageDigest, created time.Time, buildID string) Resource {
	return Resource{Kind: ResourceImage, Name: image.Repository, Image: image, SizeBytes: 10, CreatedAt: created, BuildID: buildID}
}

type fakeGCInventory struct {
	mu           sync.Mutex
	resources    []Resource
	releases     []ReleaseRecord
	builds       []BuildRecord
	runtime      []RuntimeUse
	disk         DiskUsage
	runtimeFn    func(int) []RuntimeUse
	runtimeCalls int
}

func (f *fakeGCInventory) ListResources(context.Context) ([]Resource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Resource(nil), f.resources...), nil
}

func (f *fakeGCInventory) ListReleases(context.Context) ([]ReleaseRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ReleaseRecord(nil), f.releases...), nil
}

func (f *fakeGCInventory) ListBuilds(context.Context) ([]BuildRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]BuildRecord(nil), f.builds...), nil
}

func (f *fakeGCInventory) ListRuntimeUse(context.Context) ([]RuntimeUse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runtimeCalls++
	if f.runtimeFn != nil {
		return append([]RuntimeUse(nil), f.runtimeFn(f.runtimeCalls)...), nil
	}
	return append([]RuntimeUse(nil), f.runtime...), nil
}

func (f *fakeGCInventory) DiskUsage(context.Context) (DiskUsage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.disk, nil
}

type fakeGCDeleter struct {
	mu      sync.Mutex
	deleted []domain.ImageDigest
	fail    map[string]error
}

func (f *fakeGCDeleter) DeleteImage(_ context.Context, image domain.ImageDigest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail[imageKey(image)]; err != nil {
		f.deleted = append(f.deleted, cleanImage(image))
		return err
	}
	f.deleted = append(f.deleted, cleanImage(image))
	return nil
}

func (f *fakeGCDeleter) calls() []domain.ImageDigest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]domain.ImageDigest(nil), f.deleted...)
}

func TestEvaluateWatermarkDeterministicSoftHardAndFreeThresholds(t *testing.T) {
	c := gcConfig()
	tests := []struct {
		name  string
		usage DiskUsage
		level WatermarkLevel
		fire  bool
	}{
		{name: "below", usage: DiskUsage{TotalBytes: 100, UsedBytes: 79, AvailableBytes: 21}, level: WatermarkBelowSoft},
		{name: "soft percentage", usage: DiskUsage{TotalBytes: 100, UsedBytes: 80, AvailableBytes: 20}, level: WatermarkSoft, fire: true},
		{name: "hard percentage", usage: DiskUsage{TotalBytes: 100, UsedBytes: 91, AvailableBytes: 9}, level: WatermarkHard, fire: true},
		{name: "soft free bytes", usage: DiskUsage{TotalBytes: 100, UsedBytes: 60, AvailableBytes: 20}, level: WatermarkSoft, fire: true},
	}
	c.MinFreeBytes = 20
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EvaluateWatermark(tt.usage, c)
			if err != nil {
				t.Fatal(err)
			}
			if got.Level != tt.level || got.Triggered != tt.fire {
				t.Fatalf("decision = %#v, want level=%s triggered=%v", got, tt.level, tt.fire)
			}
		})
	}
	c.HardMinFreeBytes = 10
	decision, err := EvaluateWatermark(DiskUsage{TotalBytes: 100, UsedBytes: 70, AvailableBytes: 10}, c)
	if err != nil || decision.Level != WatermarkHard {
		t.Fatalf("hard free-space watermark=%#v err=%v", decision, err)
	}
	c.HardMinFreeBytes = 21
	if _, err := EvaluateWatermark(DiskUsage{TotalBytes: 100, UsedBytes: 70, AvailableBytes: 30}, c); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("inverted free-space watermarks were accepted: %v", err)
	}
	c.HardMinFreeBytes = 10
	if _, err := EvaluateWatermark(DiskUsage{TotalBytes: 0}, c); !errors.Is(err, ErrInvalidInventory) {
		t.Fatalf("invalid disk usage error = %v, want ErrInvalidInventory", err)
	}
}

func TestIMG_GC_001_ProtectsCurrentLatestTwoSuccessfulAndSpecialReferences(t *testing.T) {
	base := fixedGCNow.Add(-time.Hour)
	latest := gcImage("latest", 1)
	previous := gcImage("previous", 2)
	older := gcImage("older", 3)
	oldest := gcImage("oldest", 4)
	pending := gcImage("pending", 5)
	rollback := gcImage("rollback", 6)
	running := gcImage("running", 7)
	building := gcImage("building", 8)
	failed := gcImage("failed", 9)
	inventory := &fakeGCInventory{
		resources: []Resource{
			gcResource(latest, base.Add(5*time.Hour), ""),
			gcResource(previous, base.Add(4*time.Hour), ""),
			gcResource(older, base.Add(3*time.Hour), ""),
			gcResource(oldest, base.Add(2*time.Hour), ""),
			gcResource(pending, base.Add(6*time.Hour), ""),
			gcResource(rollback, base.Add(7*time.Hour), ""),
			gcResource(running, base.Add(8*time.Hour), ""),
			gcResource(building, base.Add(9*time.Hour), "build-running"),
			gcResource(failed, base.Add(10*time.Hour), "build-failed"),
			{Kind: ResourceVolume, Name: "opencard-m2-data", SizeBytes: 100},
		},
		releases: []ReleaseRecord{
			{ID: "rel-latest", Status: ReleaseCurrent, Current: true, CreatedAt: base.Add(5 * time.Hour), Images: []domain.ImageDigest{latest}},
			{ID: "rel-previous", Status: ReleaseSucceeded, CreatedAt: base.Add(4 * time.Hour), Images: []domain.ImageDigest{previous}},
			{ID: "rel-older", Status: ReleaseSucceeded, CreatedAt: base.Add(3 * time.Hour), Images: []domain.ImageDigest{older}},
			{ID: "rel-oldest", Status: ReleaseSucceeded, CreatedAt: base.Add(2 * time.Hour), Images: []domain.ImageDigest{oldest}},
			{ID: "rel-pending", Status: ReleaseInProgress, InProgress: true, Images: []domain.ImageDigest{pending}},
			{ID: "rel-rollback", Status: ReleaseRollback, Rollback: true, Images: []domain.ImageDigest{rollback}},
		},
		builds: []BuildRecord{
			{ID: "build-running", Status: BuildInProgress, Images: []domain.ImageDigest{building}},
			{ID: "build-failed", Status: BuildFailed, Images: []domain.ImageDigest{failed}},
		},
		runtime: []RuntimeUse{{Image: running, InUse: true, DeploymentID: "dep-1"}},
		disk:    DiskUsage{TotalBytes: 100, UsedBytes: 95, AvailableBytes: 5},
	}
	provider, err := New(gcConfig(), inventory, &fakeGCDeleter{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := provider.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	protected := make(map[string][]ProtectionReason)
	for _, item := range plan.Protected {
		protected[imageKey(item.Image)] = item.Reasons
	}
	for _, image := range []domain.ImageDigest{latest, previous, older, pending, rollback, running, building} {
		if _, ok := protected[imageKey(image)]; !ok {
			t.Fatalf("image %s was not protected; protected=%#v", imageKey(image), protected)
		}
	}
	if _, ok := protected[imageKey(oldest)]; ok {
		t.Fatalf("fourth successful release was incorrectly retained: %#v", protected[imageKey(oldest)])
	}
	if len(plan.Candidates) != 2 {
		t.Fatalf("candidates = %#v, want oldest and failed build", plan.Candidates)
	}
	if plan.Candidates[0].Image != oldest || plan.Candidates[0].Reason != CandidateWatermark {
		t.Fatalf("first candidate = %#v, want oldest watermark candidate", plan.Candidates[0])
	}
	if plan.Candidates[1].Image != failed || plan.Candidates[1].Reason != CandidateFailedBuild {
		t.Fatalf("second candidate = %#v, want failed build candidate", plan.Candidates[1])
	}
	if plan.VolumeCount != 1 || plan.ImageCount != 9 || plan.FailedBuildRefs != 1 {
		t.Fatalf("inventory counts = image=%d volume=%d failed=%d", plan.ImageCount, plan.VolumeCount, plan.FailedBuildRefs)
	}
}

func TestPlanBelowWatermarkStillCleansFailedBuildOnly(t *testing.T) {
	old := gcImage("old", 10)
	failed := gcImage("failed", 11)
	inventory := &fakeGCInventory{
		resources: []Resource{gcResource(old, fixedGCNow.Add(-time.Hour), ""), gcResource(failed, fixedGCNow, "build-failed")},
		builds:    []BuildRecord{{ID: "build-failed", Status: BuildFailed, Images: []domain.ImageDigest{failed}}},
		disk:      DiskUsage{TotalBytes: 100, UsedBytes: 20, AvailableBytes: 80},
	}
	provider, err := New(gcConfig(), inventory, &fakeGCDeleter{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := provider.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Watermark.Triggered || len(plan.Candidates) != 1 || plan.Candidates[0].Image != failed || plan.Candidates[0].Reason != CandidateFailedBuild {
		t.Fatalf("below-watermark plan = %#v", plan)
	}
}

func TestPlanUsesBuildIDToCleanFailedBuildWhenBuildRecordOmitsImageList(t *testing.T) {
	failed := gcImage("failed-by-id", 111)
	inventory := &fakeGCInventory{
		resources: []Resource{gcResource(failed, fixedGCNow, "build-failed")},
		builds:    []BuildRecord{{ID: "build-failed", Status: BuildFailed}},
		disk:      DiskUsage{TotalBytes: 100, UsedBytes: 20, AvailableBytes: 80},
	}
	provider, err := New(gcConfig(), inventory, &fakeGCDeleter{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := provider.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) != 1 || plan.Candidates[0].Image != failed || plan.Candidates[0].Reason != CandidateFailedBuild {
		t.Fatalf("failed-build-by-id plan = %#v", plan)
	}
}

func TestPlanRetainsCurrentPlusTwoWhenCurrentRolloutIsNotSuccessfulYet(t *testing.T) {
	current := gcImage("current", 112)
	one := gcImage("one", 113)
	two := gcImage("two", 114)
	three := gcImage("three", 115)
	inventory := &fakeGCInventory{
		resources: []Resource{
			gcResource(current, fixedGCNow, ""),
			gcResource(one, fixedGCNow.Add(-time.Hour), ""),
			gcResource(two, fixedGCNow.Add(-2*time.Hour), ""),
			gcResource(three, fixedGCNow.Add(-3*time.Hour), ""),
		},
		releases: []ReleaseRecord{
			{ID: "rel-current", Status: ReleaseInProgress, Current: true, Images: []domain.ImageDigest{current}},
			{ID: "rel-one", Status: ReleaseSucceeded, CreatedAt: fixedGCNow.Add(-time.Hour), Images: []domain.ImageDigest{one}},
			{ID: "rel-two", Status: ReleaseSucceeded, CreatedAt: fixedGCNow.Add(-2 * time.Hour), Images: []domain.ImageDigest{two}},
			{ID: "rel-three", Status: ReleaseSucceeded, CreatedAt: fixedGCNow.Add(-3 * time.Hour), Images: []domain.ImageDigest{three}},
		},
		disk: DiskUsage{TotalBytes: 100, UsedBytes: 95, AvailableBytes: 5},
	}
	provider, err := New(gcConfig(), inventory, &fakeGCDeleter{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := provider.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) != 1 || plan.Candidates[0].Image != three {
		t.Fatalf("current rollout plan = %#v, want only third successful image as candidate", plan)
	}
}

func TestIMG_GC_002_CollectRechecksRuntimeBeforeEachDeleteAndNeverTouchesVolume(t *testing.T) {
	first := gcImage("first", 12)
	second := gcImage("second", 13)
	deleted := &fakeGCDeleter{}
	inventory := &fakeGCInventory{
		resources: []Resource{
			gcResource(first, fixedGCNow.Add(-2*time.Hour), ""),
			gcResource(second, fixedGCNow.Add(-time.Hour), ""),
			{Kind: ResourceVolume, Name: "data", SizeBytes: 10},
		},
		disk: DiskUsage{TotalBytes: 100, UsedBytes: 95, AvailableBytes: 5},
		runtimeFn: func(call int) []RuntimeUse {
			// Call 1 is the plan snapshot.  The first deletion sees a new
			// runtime reference; the second deletion sees a clear runtime.
			if call == 2 {
				return []RuntimeUse{{Image: first, InUse: true, DeploymentID: "dep-new"}}
			}
			return nil
		},
	}
	provider, err := New(gcConfig(), inventory, deleted)
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := deleted.calls(); !reflect.DeepEqual(got, []domain.ImageDigest{second}) {
		t.Fatalf("deleted = %#v, want only second image", got)
	}
	if len(result.Skipped()) != 1 || result.Skipped()[0].Reason != "runtime-reference-reappeared" {
		t.Fatalf("skip outcomes = %#v", result.Skipped())
	}
	if result.Plan.VolumeCount != 1 {
		t.Fatalf("volume count = %d, want 1", result.Plan.VolumeCount)
	}
}

func TestCollectContinuesAfterDeleteFailureAndReturnsAggregateError(t *testing.T) {
	one := gcImage("one", 14)
	two := gcImage("two", 15)
	deleteErr := errors.New("daemon refused delete")
	deleter := &fakeGCDeleter{fail: map[string]error{imageKey(one): deleteErr}}
	inventory := &fakeGCInventory{
		resources: []Resource{gcResource(one, fixedGCNow.Add(-2*time.Hour), ""), gcResource(two, fixedGCNow.Add(-time.Hour), "")},
		disk:      DiskUsage{TotalBytes: 100, UsedBytes: 95, AvailableBytes: 5},
	}
	provider, err := New(gcConfig(), inventory, deleter)
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Collect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "daemon refused delete") {
		t.Fatalf("collect error = %v, want delete failure", err)
	}
	if len(result.Outcomes) != 2 || result.Outcomes[0].Action != "failed" || result.Outcomes[1].Action != "deleted" {
		t.Fatalf("outcomes = %#v", result.Outcomes)
	}
	if len(deleter.calls()) != 2 {
		t.Fatalf("delete attempts = %#v, want both candidates attempted", deleter.calls())
	}
}

func TestPlanFailsClosedOnUnknownResourceAndStatus(t *testing.T) {
	base := &fakeGCInventory{disk: DiskUsage{TotalBytes: 100, UsedBytes: 90, AvailableBytes: 10}}
	base.resources = []Resource{{Kind: ResourceKind("network"), Name: "unsafe"}}
	provider, err := New(gcConfig(), base, &fakeGCDeleter{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Plan(context.Background()); !errors.Is(err, ErrInvalidInventory) {
		t.Fatalf("unknown resource error = %v, want ErrInvalidInventory", err)
	}
	base.resources = nil
	base.releases = []ReleaseRecord{{ID: "rel-unknown", Status: ReleaseStatus("mystery"), Images: []domain.ImageDigest{gcImage("mystery", 16)}}}
	if _, err := provider.Plan(context.Background()); !errors.Is(err, ErrInvalidInventory) {
		t.Fatalf("unknown release error = %v, want ErrInvalidInventory", err)
	}
}

func TestConfigRejectsRetentionBelowCurrentPlusTwo(t *testing.T) {
	c := gcConfig()
	c.KeepSuccessfulReleases = 2
	if _, err := New(c, &fakeGCInventory{}, &fakeGCDeleter{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("config error = %v, want ErrInvalidConfig", err)
	}
}

func TestPlanCandidateOrderingIsStableForEqualTimes(t *testing.T) {
	a := gcImage("a", 17)
	b := gcImage("b", 18)
	created := fixedGCNow.Add(-time.Hour)
	inventory := &fakeGCInventory{
		resources: []Resource{gcResource(b, created, ""), gcResource(a, created, "")},
		disk:      DiskUsage{TotalBytes: 100, UsedBytes: 95, AvailableBytes: 5},
	}
	provider, err := New(gcConfig(), inventory, &fakeGCDeleter{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := provider.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !sort.SliceIsSorted(plan.Candidates, func(i, j int) bool { return imageKey(plan.Candidates[i].Image) < imageKey(plan.Candidates[j].Image) }) {
		t.Fatalf("candidate ordering is not deterministic: %#v", plan.Candidates)
	}
}

func TestConcurrentPlansHaveNoSharedMutableState(t *testing.T) {
	inventory := &fakeGCInventory{
		resources: []Resource{gcResource(gcImage("a", 19), fixedGCNow, "")},
		disk:      DiskUsage{TotalBytes: 100, UsedBytes: 95, AvailableBytes: 5},
	}
	provider, err := New(gcConfig(), inventory, &fakeGCDeleter{})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := provider.Plan(context.Background()); err != nil {
				t.Errorf("concurrent plan: %v", err)
			}
		}()
	}
	wg.Wait()
}
