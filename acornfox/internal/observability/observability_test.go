package observability

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMetricSampleValidationDedupAndIdentity(t *testing.T) {
	start := time.Unix(1_700_000_000, 0).UTC().Truncate(5 * time.Minute)
	first := testSample("sample-1", start, 0.1)
	duplicate := first
	changed := first
	changed.MemoryBytes++

	if err := first.Validate(); err != nil {
		t.Fatal(err)
	}
	if first.Identity() != duplicate.Identity() || first.ContentIdentity() != duplicate.ContentIdentity() {
		t.Fatal("equal samples must have stable identities")
	}
	if first.ContentIdentity() == changed.ContentIdentity() {
		t.Fatal("changed measurement reused content identity")
	}
	unique, err := DeduplicateSamples([]Sample{first, duplicate})
	if err != nil || len(unique) != 1 {
		t.Fatalf("duplicate sample handling = %d, %v", len(unique), err)
	}
	if _, err := DeduplicateSamples([]Sample{first, changed}); !errors.Is(err, ErrSampleConflict) {
		t.Fatalf("changed retry error = %v, want conflict", err)
	}
	for _, invalid := range []Sample{
		{},
		{ApplicationID: "app", ServiceName: "svc", At: start, CPU: -1},
		{ApplicationID: "app", ServiceName: "svc", At: start, MemoryBytes: math.NaN()},
		{ApplicationID: "app", ServiceName: "svc", At: start, DiskBytes: math.Inf(1)},
	} {
		if err := invalid.Validate(); !errors.Is(err, ErrInvalidSample) {
			t.Errorf("invalid sample accepted: %v", err)
		}
	}
}

func TestMetricAggregateAndLateBuckets(t *testing.T) {
	start := time.Unix(1_700_000_000, 0).UTC().Truncate(5 * time.Minute)
	samples := []Sample{
		testSample("s3", start.Add(2*time.Minute), 0.5),
		testSample("s1", start, 0.1),
		testSample("s2", start.Add(time.Minute), 0.3),
	}
	samples[0].MemoryBytes = 300
	samples[1].MemoryBytes = 100
	samples[2].MemoryBytes = 200
	samples[0].NetworkRxBytes = 3
	samples[1].NetworkRxBytes = 1
	samples[2].NetworkRxBytes = 2
	aggregate, err := AggregateSamples(samples)
	if err != nil {
		t.Fatal(err)
	}
	if aggregate.SampleCount != 3 || aggregate.AverageCPU != 0.3 || aggregate.PeakCPU != 0.5 {
		t.Fatalf("aggregate CPU = %+v", aggregate)
	}
	if aggregate.AverageMemory != 200 || aggregate.PeakMemory != 300 || aggregate.NetworkRx != 6 {
		t.Fatalf("aggregate memory/network = %+v", aggregate)
	}
	if aggregate.CPUSeconds != 36 || aggregate.MemoryByteSecs != 24_000 {
		t.Fatalf("aggregate integrals = %+v", aggregate)
	}

	late := testSample("late", start.Add(6*time.Minute), 0.7)
	buckets, err := AggregateBuckets(append(samples, late), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 2 || !buckets[0].BucketStart.Equal(start.Truncate(5*time.Minute)) {
		t.Fatalf("bucket result = %+v", buckets)
	}
	if buckets[1].SampleCount != 1 || buckets[1].PeakCPU != 0.7 {
		t.Fatalf("late sample landed in wrong bucket: %+v", buckets)
	}
}

func TestLogStoreRedactionRotationAndCaps(t *testing.T) {
	root := t.TempDir()
	secret := "tok+en/with=chars"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	urlEncoded := strings.NewReplacer("+", "%2B", "/", "%2F", "=", "%3D").Replace(secret)
	hexEncoded := hex.EncodeToString([]byte(secret))
	store, err := NewLogStore(LogStoreConfig{
		RootDir:         root,
		MaxFileBytes:    5,
		MaxTotalBytes:   1000,
		MaxBuildFiles:   20,
		MaxRuntimeFiles: 20,
		Secrets:         []string{secret},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("event=deploy password=\"" + secret + "\" b64=" + encoded + " url=" + urlEncoded + " hex=" + hexEncoded + "\n")
	if err := store.Append(LogCategoryRuntime, "svc-a", payload); err != nil {
		t.Fatal(err)
	}
	files, err := store.Files(LogCategoryRuntime, "svc-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 2 {
		t.Fatalf("rotation did not create multiple files: %+v", files)
	}
	for _, file := range files {
		if file.Bytes > 5 {
			t.Fatalf("rotated file exceeded cap: %+v", file)
		}
	}
	read, err := store.Read(LogCategoryRuntime, "svc-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{secret, encoded, urlEncoded, hexEncoded} {
		if strings.Contains(string(read), leaked) {
			t.Fatalf("secret variant leaked to disk: %q in %q", leaked, read)
		}
	}
	if !strings.Contains(string(read), "event=deploy") {
		t.Fatalf("non-secret log context was lost: %q", read)
	}
	ordinary, err := store.OrdinaryBytes()
	if err != nil {
		t.Fatal(err)
	}
	if ordinary > 1000 {
		t.Fatalf("ordinary log cap exceeded: %d", ordinary)
	}
}

func TestLogStoreRestartRecoveryAndPathTraversal(t *testing.T) {
	root := t.TempDir()
	config := LogStoreConfig{RootDir: root, MaxFileBytes: 4, MaxTotalBytes: 100, MaxRuntimeFiles: 20}
	store, err := NewLogStore(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AppendText(LogCategoryRuntime, "svc-a", "abcdef"); err != nil {
		t.Fatal(err)
	}
	before, err := store.Files(LogCategoryRuntime, "svc-a")
	if err != nil || len(before) != 2 {
		t.Fatalf("initial segments = %+v err=%v", before, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewLogStore(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.AppendText(LogCategoryRuntime, "svc-a", "gh"); err != nil {
		t.Fatal(err)
	}
	read, err := restarted.Read(LogCategoryRuntime, "svc-a")
	if err != nil || string(read) != "abcdefgh" {
		t.Fatalf("restart recovery read = %q err=%v", read, err)
	}
	after, err := restarted.Files(LogCategoryRuntime, "svc-a")
	if err != nil || len(after) != 2 || after[1].Sequence != before[1].Sequence {
		t.Fatalf("restart did not reuse current segment: before=%+v after=%+v err=%v", before, after, err)
	}
	if err := restarted.AppendText(LogCategoryRuntime, "../outside", "nope"); !errors.Is(err, ErrLogPathTraversal) {
		t.Fatalf("path traversal error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "outside")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path traversal created outside path: %v", err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, string(LogCategoryRuntime), "link")); err != nil {
		t.Fatal(err)
	}
	if err := restarted.AppendText(LogCategoryRuntime, "link", "nope"); !errors.Is(err, ErrLogPathTraversal) {
		t.Fatalf("symlink traversal error = %v", err)
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("symlink target changed: entries=%v err=%v", entries, err)
	}
}

func TestAuditLogsExcludedFromOrdinaryGC(t *testing.T) {
	root := t.TempDir()
	store, err := NewLogStore(LogStoreConfig{RootDir: root, MaxFileBytes: 4, MaxTotalBytes: 4, MaxRuntimeFiles: 20})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AppendText(LogCategoryAudit, "evidence-1", strings.Repeat("audit", 4)); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendText(LogCategoryRuntime, "svc-a", "runtime-data"); err != nil {
		t.Fatal(err)
	}
	if err := store.GC(); err != nil {
		t.Fatal(err)
	}
	ordinary, err := store.OrdinaryBytes()
	if err != nil {
		t.Fatal(err)
	}
	if ordinary > 4 {
		t.Fatalf("ordinary bytes exceeded cap: %d", ordinary)
	}
	audit, err := store.Read(LogCategoryAudit, "evidence-1")
	if err != nil {
		t.Fatal(err)
	}
	if string(audit) != strings.Repeat("audit", 4) {
		t.Fatalf("audit log was modified by ordinary GC: %q", audit)
	}
	auditBytes, err := store.AuditBytes()
	if err != nil || auditBytes == 0 {
		t.Fatalf("audit bytes = %d err=%v", auditBytes, err)
	}
}

func TestLogStoreGCIsOldestFirstAndDeterministic(t *testing.T) {
	root := t.TempDir()
	store, err := NewLogStore(LogStoreConfig{RootDir: root, MaxFileBytes: 10, MaxTotalBytes: 9, MaxRuntimeFiles: 20, RuntimeRetention: 100 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AppendText(LogCategoryRuntime, "old", "old"); err != nil {
		t.Fatal(err)
	}
	oldFiles, err := store.Files(LogCategoryRuntime, "old")
	if err != nil || len(oldFiles) != 1 {
		t.Fatalf("old stream files = %+v err=%v", oldFiles, err)
	}
	oldTime := time.Unix(100, 0)
	if err := os.Chtimes(oldFiles[0].Path, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendText(LogCategoryRuntime, "new", "newnew"); err != nil {
		t.Fatal(err)
	}
	newFiles, err := store.Files(LogCategoryRuntime, "new")
	if err != nil || len(newFiles) != 1 {
		t.Fatalf("new stream files = %+v err=%v", newFiles, err)
	}
	newTime := time.Unix(200, 0)
	if err := os.Chtimes(newFiles[0].Path, newTime, newTime); err != nil {
		t.Fatal(err)
	}
	store.config.MaxTotalBytes = 8
	if err := store.GC(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldFiles[0].Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oldest file survived GC: %v", err)
	}
	read, err := store.Read(LogCategoryRuntime, "new")
	if err != nil || string(read) != "newnew" {
		t.Fatalf("newest stream was not retained: %q err=%v", read, err)
	}
}

func TestLogStoreRetainsLatestTwentyBuildExecutions(t *testing.T) {
	root := t.TempDir()
	store, err := NewLogStore(LogStoreConfig{RootDir: root, MaxFileBytes: 1024, MaxTotalBytes: 1024 * 1024, MaxBuildFiles: 20, MaxRuntimeFiles: 5})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 21; index++ {
		stream := fmt.Sprintf("build-%02d", index)
		if err := store.AppendText(LogCategoryBuild, stream, stream); err != nil {
			t.Fatal(err)
		}
		files, err := store.Files(LogCategoryBuild, stream)
		if err != nil || len(files) != 1 {
			t.Fatalf("build %s files=%v err=%v", stream, files, err)
		}
		stamp := time.Unix(int64(100+index), 0)
		if err := os.Chtimes(files[0].Path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.GC(); err != nil {
		t.Fatal(err)
	}
	if files, err := store.Files(LogCategoryBuild, "build-00"); err != nil || len(files) != 0 {
		t.Fatalf("oldest build was retained: files=%v err=%v", files, err)
	}
	if files, err := store.Files(LogCategoryBuild, "build-20"); err != nil || len(files) != 1 {
		t.Fatalf("newest build was removed: files=%v err=%v", files, err)
	}
}

func TestRuntimeSevenDayRetentionNeverDeletesAudit(t *testing.T) {
	root := t.TempDir()
	store, err := NewLogStore(LogStoreConfig{RootDir: root, MaxFileBytes: 1024, MaxTotalBytes: 1024 * 1024, MaxRuntimeFiles: 20, RuntimeRetention: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AppendText(LogCategoryRuntime, "service-api", "old runtime token=runtime-canary"); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendText(LogCategoryAudit, "audit-immutable", "authorization=audit-canary"); err != nil {
		t.Fatal(err)
	}
	runtimeFiles, _ := store.List(LogCategoryRuntime, "service-api")
	auditFiles, _ := store.List(LogCategoryAudit, "audit-immutable")
	old := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(runtimeFiles[0].Path, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(auditFiles[0].Path, old, old); err != nil {
		t.Fatal(err)
	}
	if err := store.GC(); err != nil {
		t.Fatal(err)
	}
	if data, _ := store.Read(LogCategoryRuntime, "service-api"); len(data) != 0 {
		t.Fatalf("expired runtime log retained: %q", data)
	}
	if data, _ := store.Read(LogCategoryAudit, "audit-immutable"); len(data) == 0 || strings.Contains(string(data), "audit-canary") {
		t.Fatalf("audit retention/redaction failed: %q", data)
	}
}

func testSample(id string, at time.Time, cpu float64) Sample {
	return Sample{
		ID:            id,
		ApplicationID: "app-1",
		ServiceName:   "svc-a",
		ReleaseID:     "release-1",
		At:            at,
		CPU:           cpu,
		MemoryBytes:   cpu * 100,
		DiskBytes:     cpu * 10,
	}
}
