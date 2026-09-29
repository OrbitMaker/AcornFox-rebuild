package main

import (
	"bytes"
	"net/http"
	"testing"
	"time"
)

func TestValidateHostMetricsWarmingUpAndAvailable(t *testing.T) {
	// 1. Initial unpopulated warming_up before first sample
	emptyWarmingUp := &apiHostMetrics{
		SchemaVersion:     1,
		Availability:      "warming_up",
		StaleAfterSeconds: 15,
	}
	if !validateHostMetrics(emptyWarmingUp) {
		t.Fatal("expected empty warming_up before first sample to be valid")
	}

	// 2. First successful sample: observed_at and core metrics present, UsagePercent is nil
	now := time.Now().UTC()
	firstSample := &apiHostMetrics{
		SchemaVersion:     1,
		Availability:      "warming_up",
		ObservedAt:        &now,
		StaleAfterSeconds: 15,
		CPU:               &apiHostCPU{LogicalCores: 4, UsagePercent: nil},
		Memory:            &apiHostMemory{TotalBytes: 1000, AvailableBytes: 500, UsedBytes: 500},
		Disk:              &apiHostDisk{Mountpoint: "/", TotalBytes: 2000, FreeBytes: 1000, UsedBytes: 1000},
	}
	if !validateHostMetrics(firstSample) {
		t.Fatal("expected first sample warming_up with nil UsagePercent to be valid")
	}

	// 3. Available requires complete data including UsagePercent
	cpuUse := 25.5
	available := &apiHostMetrics{
		SchemaVersion:     1,
		Availability:      "available",
		ObservedAt:        &now,
		StaleAfterSeconds: 15,
		CPU:               &apiHostCPU{LogicalCores: 4, UsagePercent: &cpuUse},
		Memory:            &apiHostMemory{TotalBytes: 1000, AvailableBytes: 500, UsedBytes: 500},
		Disk:              &apiHostDisk{Mountpoint: "/", TotalBytes: 2000, FreeBytes: 1000, UsedBytes: 1000},
	}
	if !validateHostMetrics(available) {
		t.Fatal("expected fully populated available host metrics to be valid")
	}

	// 4. Available missing UsagePercent must be rejected
	availableMissingUse := &apiHostMetrics{
		SchemaVersion:     1,
		Availability:      "available",
		ObservedAt:        &now,
		StaleAfterSeconds: 15,
		CPU:               &apiHostCPU{LogicalCores: 4, UsagePercent: nil},
		Memory:            &apiHostMemory{TotalBytes: 1000, AvailableBytes: 500, UsedBytes: 500},
		Disk:              &apiHostDisk{Mountpoint: "/", TotalBytes: 2000, FreeBytes: 1000, UsedBytes: 1000},
	}
	if validateHostMetrics(availableMissingUse) {
		t.Fatal("expected available host metrics missing UsagePercent to be rejected")
	}

	// 5. Unavailable / Unsupported with no metrics is valid
	unavailable := &apiHostMetrics{
		SchemaVersion:     1,
		Availability:      "unavailable",
		StaleAfterSeconds: 15,
	}
	if !validateHostMetrics(unavailable) {
		t.Fatal("expected unavailable with no metrics to be valid")
	}
}

func TestValidateHostMetricsRecent(t *testing.T) {
	now := time.Now().UTC()
	t1 := now.Add(-10 * time.Second)
	t2 := now.Add(-5 * time.Second)
	cpuUse := 12.0

	validPoint1 := apiHostMetrics{
		SchemaVersion:     1,
		Availability:      "warming_up",
		ObservedAt:        &t1,
		StaleAfterSeconds: 15,
		CPU:               &apiHostCPU{LogicalCores: 4},
		Memory:            &apiHostMemory{TotalBytes: 1000, AvailableBytes: 500, UsedBytes: 500},
		Disk:              &apiHostDisk{Mountpoint: "/", TotalBytes: 2000, FreeBytes: 1000, UsedBytes: 1000},
	}

	validPoint2 := apiHostMetrics{
		SchemaVersion:     1,
		Availability:      "available",
		ObservedAt:        &t2,
		StaleAfterSeconds: 15,
		CPU:               &apiHostCPU{LogicalCores: 4, UsagePercent: &cpuUse},
		Memory:            &apiHostMemory{TotalBytes: 1000, AvailableBytes: 500, UsedBytes: 500},
		Disk:              &apiHostDisk{Mountpoint: "/", TotalBytes: 2000, FreeBytes: 1000, UsedBytes: 1000},
	}

	// 1. Valid recent response
	recent := &apiHostMetricsRecent{
		SchemaVersion:    1,
		Availability:     "available",
		GeneratedAt:      now,
		Capacity:         360,
		RetentionSeconds: 1800,
		Points:           []apiHostMetrics{validPoint1, validPoint2},
	}
	if !validateHostMetricsRecent(recent) {
		t.Fatal("expected valid recent response to pass validation")
	}

	// 2. Reject empty warming_up in history (historical point must have observed_at)
	emptyWarmingUpPoint := apiHostMetrics{
		SchemaVersion:     1,
		Availability:      "warming_up",
		StaleAfterSeconds: 15,
	}
	recentWithEmptyPoint := &apiHostMetricsRecent{
		SchemaVersion:    1,
		Availability:     "warming_up",
		GeneratedAt:      now,
		Capacity:         360,
		RetentionSeconds: 1800,
		Points:           []apiHostMetrics{emptyWarmingUpPoint},
	}
	if validateHostMetricsRecent(recentWithEmptyPoint) {
		t.Fatal("expected history point with no observed_at to be rejected")
	}

	// 3. Reject non-monotonic time ordering
	recentNonMonotonic := &apiHostMetricsRecent{
		SchemaVersion:    1,
		Availability:     "available",
		GeneratedAt:      now,
		Capacity:         360,
		RetentionSeconds: 1800,
		Points:           []apiHostMetrics{validPoint2, validPoint1}, // t2 > t1, so t1 after t2 is backwards
	}
	if validateHostMetricsRecent(recentNonMonotonic) {
		t.Fatal("expected backwards time order in history to be rejected")
	}

	// 4. Reject invalid capacity / retention
	badMeta := &apiHostMetricsRecent{
		SchemaVersion:    1,
		Availability:     "available",
		GeneratedAt:      now,
		Capacity:         100, // must be 360
		RetentionSeconds: 1800,
		Points:           []apiHostMetrics{},
	}
	if validateHostMetricsRecent(badMeta) {
		t.Fatal("expected capacity != 360 to be rejected")
	}
}

func TestCLIHostCommandValidationZeroNetwork(t *testing.T) {
	c := &cli{
		in:  &bytes.Buffer{},
		out: &bytes.Buffer{},
		err: &bytes.Buffer{},
	}

	// 1. Empty args
	if err := c.host([]string{}); err == nil {
		t.Fatal("expected error for empty args")
	}

	// 2. Invalid limit parameters must fail with zero network
	invalidLimits := []string{"0", "-1", "361", "abc", "01"}
	for _, l := range invalidLimits {
		if err := c.host([]string{"recent", "--limit", l}); err == nil {
			t.Fatalf("expected error for --limit %s", l)
		}
	}

	// 3. Extra positionals
	if err := c.host([]string{"metrics", "extra"}); err == nil {
		t.Fatal("expected error for extra positional on metrics")
	}
	if err := c.host([]string{"recent", "extra"}); err == nil {
		t.Fatal("expected error for extra positional on recent")
	}
}

func TestExpectedStatusForHostMetricsAndRecent(t *testing.T) {
	// Snapshot
	if status, ok := expectedSuccessStatus(http.MethodGet, "/host/metrics", shapeHostMetrics); !ok || status != http.StatusOK {
		t.Fatalf("expected /host/metrics to be allowed, got status=%d ok=%v", status, ok)
	}
	if _, ok := expectedSuccessStatus(http.MethodGet, "/host/metrics?limit=10", shapeHostMetrics); ok {
		t.Fatal("expected /host/metrics with query to be rejected")
	}

	// Recent
	if status, ok := expectedSuccessStatus(http.MethodGet, "/host/metrics/recent", shapeHostMetricsRecent); !ok || status != http.StatusOK {
		t.Fatalf("expected /host/metrics/recent to be allowed, got status=%d ok=%v", status, ok)
	}
	if status, ok := expectedSuccessStatus(http.MethodGet, "/host/metrics/recent?limit=60", shapeHostMetricsRecent); !ok || status != http.StatusOK {
		t.Fatalf("expected /host/metrics/recent?limit=60 to be allowed, got status=%d ok=%v", status, ok)
	}
	if _, ok := expectedSuccessStatus(http.MethodGet, "/host/metrics/recent?limit=0", shapeHostMetricsRecent); ok {
		t.Fatal("expected limit=0 to be rejected in expectedSuccessStatus")
	}
	if _, ok := expectedSuccessStatus(http.MethodGet, "/host/metrics/recent?limit=400", shapeHostMetricsRecent); ok {
		t.Fatal("expected limit=400 to be rejected in expectedSuccessStatus")
	}
	if _, ok := expectedSuccessStatus(http.MethodGet, "/host/metrics/recent?unknown=1", shapeHostMetricsRecent); ok {
		t.Fatal("expected unknown query to be rejected in expectedSuccessStatus")
	}
}

func TestHostMetricsRawFieldPresenceRejections(t *testing.T) {
	// 1. Available missing cpu usage_percent
	badAvailable := []byte(`{
		"schema_version": 1,
		"availability": "available",
		"observed_at": "2026-09-26T19:00:00Z",
		"stale_after_seconds": 15,
		"cpu": {"logical_cores": 4},
		"memory": {"total_bytes": 1000, "available_bytes": 500, "used_bytes": 500},
		"disk": {"mountpoint": "/", "total_bytes": 2000, "free_bytes": 1000, "used_bytes": 1000}
	}`)
	if _, err := decodeResponse(bytes.NewReader(badAvailable), shapeHostMetrics); err == nil {
		t.Fatal("expected available metrics missing usage_percent to be rejected by decodeResponse")
	}

	// 2. Empty memory object: memory: {}
	emptyMem := []byte(`{
		"schema_version": 1,
		"availability": "available",
		"observed_at": "2026-09-26T19:00:00Z",
		"stale_after_seconds": 15,
		"cpu": {"logical_cores": 4, "usage_percent": 10.0},
		"memory": {},
		"disk": {"mountpoint": "/", "total_bytes": 2000, "free_bytes": 1000, "used_bytes": 1000}
	}`)
	if _, err := decodeResponse(bytes.NewReader(emptyMem), shapeHostMetrics); err == nil {
		t.Fatal("expected empty memory object to be rejected")
	}

	// 3. Unavailable carrying cpu metrics must be rejected
	unavailableWithCPU := []byte(`{
		"schema_version": 1,
		"availability": "unavailable",
		"stale_after_seconds": 15,
		"cpu": {"logical_cores": 4}
	}`)
	if _, err := decodeResponse(bytes.NewReader(unavailableWithCPU), shapeHostMetrics); err == nil {
		t.Fatal("expected unavailable with cpu to be rejected")
	}

	// 4. Available carrying negative byte values (e.g. used_bytes: -1) must be rejected
	negativeBytes := []byte(`{
		"schema_version": 1,
		"availability": "available",
		"observed_at": "2026-09-26T19:00:00Z",
		"stale_after_seconds": 15,
		"cpu": {"logical_cores": 4, "usage_percent": 10.0},
		"memory": {"total_bytes": 1000, "available_bytes": 500, "used_bytes": -1},
		"disk": {"mountpoint": "/", "total_bytes": 2000, "free_bytes": 1000, "used_bytes": 1000}
	}`)
	if _, err := decodeResponse(bytes.NewReader(negativeBytes), shapeHostMetrics); err == nil {
		t.Fatal("expected negative used_bytes to be rejected")
	}
}
