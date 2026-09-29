package containermetrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

func historySample(cid string, started, at time.Time) appcontracts.ImageMetricsResult {
	cpu, memory := uint64(0), uint64(1024)
	return appcontracts.ImageMetricsResult{State: appcontracts.ImageLifecycleResult{Running: true, VerifiedIdentity: true, ContainerID: cid, ImageID: "sha256:image", ManifestDigest: "sha256:manifest", HostPort: 39001, ContainerPort: 80, ObservedAt: at}, Available: true, SampledAt: at, ProcessStartedAt: started, CPUUsageMillis: &cpu, MemoryUsageBytes: &memory}
}

type phaseStart struct {
	id domain.ID
	at time.Time
}
type phaseClient struct {
	started  chan phaseStart
	inflight atomic.Int32
	peak     atomic.Int32
}

func (c *phaseClient) ReadManagedImageMetrics(ctx context.Context, q appcontracts.ImageMetricsRequest) (appcontracts.ImageMetricsResult, error) {
	n := c.inflight.Add(1)
	for old := c.peak.Load(); n > old && !c.peak.CompareAndSwap(old, n); old = c.peak.Load() {
	}
	defer c.inflight.Add(-1)
	select {
	case c.started <- phaseStart{id: q.DeploymentID, at: time.Now()}:
	case <-ctx.Done():
		return appcontracts.ImageMetricsResult{}, ctx.Err()
	}
	<-ctx.Done()
	return appcontracts.ImageMetricsResult{}, ctx.Err()
}

func TestSamplerThirtyTwoSlowReadsTickPhaseAndCancellationJoin(t *testing.T) {
	targets := make([]appcontracts.ImageMetricsRequest, 32)
	for i := range targets {
		targets[i] = appcontracts.ImageMetricsRequest{AdminID: "admin", DeploymentID: domain.ID(fmt.Sprintf("dep-phase-%02d", i))}
	}
	client := &phaseClient{started: make(chan phaseStart, 32)}
	s := &Sampler{Store: fixedTargetStore{selection: appcontracts.ImageMetricsTargetSelection{Targets: targets}}, History: NewHistory(time.Now().UTC()), interval: 50 * time.Millisecond, readTimeout: 100 * time.Millisecond}
	s.SetClient(client)
	ctx, cancel := context.WithCancel(context.Background())
	done := s.Start(ctx)
	deadline := time.After(4 * time.Second)
	var first, last time.Time
	seen := make(map[domain.ID]bool, 32)
	for i := range targets {
		select {
		case started := <-client.started:
			pair := i / 2
			if (started.id != targets[2*pair].DeploymentID && started.id != targets[2*pair+1].DeploymentID) || seen[started.id] {
				cancel()
				<-done
				t.Fatalf("slow tick skipped/duplicated pair %d: %s", pair, started.id)
			}
			seen[started.id] = true
			if i == 0 {
				first = started.at
			}
			last = started.at
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("32 slow targets did not complete one launch rotation; reached %d", i)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not join all in-flight sample reads")
	}
	if c := client.peak.Load(); c > 2 || c < 1 {
		t.Fatalf("background read concurrency escaped two slots: %d", c)
	}
	if elapsed := last.Sub(first); elapsed > staleAfterFor(32, 100*time.Millisecond, 50*time.Millisecond)+100*time.Millisecond {
		t.Fatalf("ticker phase exceeded scaled 250-second freshness budget: %v", elapsed)
	} else {
		t.Logf("32_target_slow_rotation=%s scaled_stale_after=%s", elapsed, staleAfterFor(32, 100*time.Millisecond, 50*time.Millisecond))
	}
}

func TestHistoryFixedCapacityRotationExpiryAndIndependentCopies(t *testing.T) {
	if size := unsafe.Sizeof(History{}); size > 8<<20 {
		t.Fatalf("fixed retained history exceeds 8 MiB: %d", size)
	} else {
		t.Logf("fixed_history_bytes=%d", size)
	}
	base := time.Now().UTC().Add(-30 * time.Minute)
	h := NewHistory(base.Add(-time.Minute))
	id := domain.ID("dep-history")
	if err := h.SetActiveTargets(appcontracts.ImageMetricsTargetSelection{Targets: []appcontracts.ImageMetricsRequest{{AdminID: "admin", DeploymentID: id}}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= appcontracts.ImageMetricsHistorySamples; i++ {
		at := base.Add(time.Duration(i) * 5 * time.Second)
		if err := h.Record(id, historySample("same-cid", base.Add(-time.Minute), at), at); err != nil {
			t.Fatal(err)
		}
	}
	end := base.Add(30 * time.Minute)
	recent := h.Recent(id, "same-cid", 360, end)
	if len(recent.Samples) != 360 || recent.HistoryStart == nil || !recent.HistoryStart.Equal(base.Add(5*time.Second)) || recent.RecordingStatus != "recording" || recent.StaleAfterSeconds != 30 {
		t.Fatalf("count, expiry or start drifted: %d %+v", len(recent.Samples), recent)
	}
	firstSegment := recent.CurrentSegmentID
	newStart := end.Add(time.Second)
	if err := h.Record(id, historySample("same-cid", newStart, end.Add(5*time.Second)), end.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	recent = h.Recent(id, "same-cid", 360, end.Add(5*time.Second))
	if len(recent.Samples) != 360 || recent.CurrentSegmentID == firstSegment || recent.Samples[len(recent.Samples)-2].SegmentID != firstSegment || recent.SegmentStart == nil || !recent.SegmentStart.Equal(end.Add(5*time.Second)) {
		t.Fatal("same-CID process restart crossed a history segment")
	}
	recent.Samples[len(recent.Samples)-1].MemoryUsageBytes = nil
	if last := h.Recent(id, "same-cid", 1, end.Add(5*time.Second)).Samples[0]; last.MemoryUsageBytes == nil || *last.MemoryUsageBytes != 1024 {
		t.Fatal("caller mutated retained history")
	}
	payload, err := json.Marshal(recent)
	if err != nil || len(payload) > appcontracts.ImageMetricsHistoryJSONBytes {
		t.Fatal("bounded 360-point response exceeded its wire ceiling")
	}
	selection := make([]appcontracts.ImageMetricsRequest, 32)
	selection[0] = appcontracts.ImageMetricsRequest{AdminID: "admin", DeploymentID: id}
	for i := 1; i < len(selection); i++ {
		selection[i] = appcontracts.ImageMetricsRequest{AdminID: "admin", DeploymentID: domain.ID(fmt.Sprintf("dep-other-%02d", i))}
	}
	if err := h.SetActiveTargets(appcontracts.ImageMetricsTargetSelection{Targets: selection}); err != nil {
		t.Fatal(err)
	}
	if staleAfter(32) != 250*time.Second || h.Recent(id, "same-cid", 1, end.Add(85*time.Second)).Stale || !h.Recent(id, "same-cid", 1, end.Add(256*time.Second)).Stale {
		t.Fatal("multi-target scheduling budget falsely marked normal rotation stale")
	}
	notRunningAt := end.Add(10 * time.Second)
	notRunning := appcontracts.ImageMetricsResult{State: appcontracts.ImageLifecycleResult{Running: false, VerifiedIdentity: true, ContainerID: "same-cid", ImageID: "sha256:image", ManifestDigest: "sha256:manifest", HostPort: 39001, ContainerPort: 80, ObservedAt: notRunningAt}, UnavailableReason: "not_running"}
	if err := h.Record(id, notRunning, notRunningAt); err != nil {
		t.Fatal(err)
	}
	stopped := h.Recent(id, "same-cid", 2, notRunningAt)
	if stopped.Samples[1].Available || stopped.Samples[1].SegmentID == stopped.Samples[0].SegmentID || stopped.Samples[1].CPUUsageMillis != nil || stopped.RecordingStatus != "stale" || stopped.Reason != "not_running" || !stopped.Stale {
		t.Fatal("stop was merged into running segment or invented numeric zero")
	}
	stoppedJSON, err := json.Marshal(stopped.Samples[1])
	if err != nil || strings.Contains(string(stoppedJSON), "process_started_at") {
		t.Fatal("unobserved process start leaked as a zero timestamp")
	}
	if expired := h.Recent(id, "same-cid", 2, notRunningAt.Add(31*time.Minute)); expired.RecordingStatus != "stale" || expired.Reason != "sample_expired" || len(expired.Samples) != 0 {
		t.Fatal("expired history was mislabeled as first-sample warm-up")
	}
}

type fixedTargetStore struct {
	selection appcontracts.ImageMetricsTargetSelection
}

func (s fixedTargetStore) ListActiveManagedImageMetricTargets(context.Context, int) (appcontracts.ImageMetricsTargetSelection, error) {
	return s.selection, nil
}

type blockedMetricsClient struct {
	started chan appcontracts.ImageMetricsRequest
	release chan struct{}
}

func (c *blockedMetricsClient) ReadManagedImageMetrics(ctx context.Context, q appcontracts.ImageMetricsRequest) (appcontracts.ImageMetricsResult, error) {
	select {
	case c.started <- q:
	case <-ctx.Done():
		return appcontracts.ImageMetricsResult{}, ctx.Err()
	}
	select {
	case <-c.release:
		return appcontracts.ImageMetricsResult{}, errors.New("fixture read failed")
	case <-ctx.Done():
		return appcontracts.ImageMetricsResult{}, ctx.Err()
	}
}

func TestSamplerThirtyTwoTargetsTwoInflightWithoutCatchup(t *testing.T) {
	targets := make([]appcontracts.ImageMetricsRequest, 32)
	for i := range targets {
		targets[i] = appcontracts.ImageMetricsRequest{AdminID: "admin", DeploymentID: domain.ID(fmt.Sprintf("dep-%02d", i))}
	}
	h := NewHistory(time.Now().UTC())
	client := &blockedMetricsClient{started: make(chan appcontracts.ImageMetricsRequest, 4), release: make(chan struct{})}
	s := &Sampler{Store: fixedTargetStore{selection: appcontracts.ImageMetricsTargetSelection{Targets: targets, Limited: true}}, History: h}
	s.SetClient(client)
	s.tick(context.Background())
	first, second := <-client.started, <-client.started
	if (first.DeploymentID != targets[0].DeploymentID && first.DeploymentID != targets[1].DeploymentID) || (second.DeploymentID != targets[0].DeploymentID && second.DeploymentID != targets[1].DeploymentID) || first.DeploymentID == second.DeploymentID {
		t.Fatal("first bounded target pair changed")
	}
	s.tick(context.Background())
	select {
	case unexpected := <-client.started:
		t.Fatalf("queued a catch-up request while two reads were blocked: %s", unexpected.DeploymentID)
	default:
	}
	close(client.release)
	s.wg.Wait()
	s.tick(context.Background())
	third, fourth := <-client.started, <-client.started
	s.wg.Wait()
	if (third.DeploymentID != targets[2].DeploymentID && third.DeploymentID != targets[3].DeploymentID) || (fourth.DeploymentID != targets[2].DeploymentID && fourth.DeploymentID != targets[3].DeploymentID) || third.DeploymentID == fourth.DeploymentID {
		t.Fatal("slow-read tick skipped a target or broke round-robin order")
	}
	if got := h.Recent(targets[31].DeploymentID, "full-cid", 1, time.Now().UTC()); !got.Scheduled || !got.SelectionLimited || got.RecordingStatus != "warming_up" || got.StaleAfterSeconds != 250 {
		t.Fatalf("32-target warm-up contract drifted: %+v", got)
	}
	replacement := append([]appcontracts.ImageMetricsRequest(nil), targets[1:]...)
	replacement = append(replacement, appcontracts.ImageMetricsRequest{AdminID: "admin", DeploymentID: "dep-32"})
	if err := h.SetActiveTargets(appcontracts.ImageMetricsTargetSelection{Targets: replacement, Limited: true}); err != nil {
		t.Fatal(err)
	}
	if got := h.Recent(targets[0].DeploymentID, "full-cid", 1, time.Now().UTC()); got.Scheduled || got.RecordingStatus != "not_selected" || !got.SelectionLimited {
		t.Fatal("evicted target was still presented as monitored")
	}
}
