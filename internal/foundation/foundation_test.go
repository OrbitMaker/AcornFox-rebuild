package foundation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUnitSRC001NormalizeGitLocatorAndRef(t *testing.T) {
	tests := []struct {
		name    string
		locator string
		ref     string
		want    GitSource
		valid   bool
	}{
		{name: "https canonical", locator: " HTTPS://GitHub.COM/acme/app.git/ ", ref: " main ", want: GitSource{Locator: "https://github.com/acme/app.git", Ref: "main", Scheme: GitHTTPS}, valid: true},
		{name: "ssh scp canonical", locator: "git@GitHub.COM:acme/app.git", ref: "refs/heads/main", want: GitSource{Locator: "git@github.com:acme/app.git", Ref: "refs/heads/main", Scheme: GitSSH}, valid: true},
		{name: "ssh url", locator: "ssh://git@GitHub.COM/acme/app.git/", ref: "v1.0.0", want: GitSource{Locator: "ssh://git@github.com/acme/app.git", Ref: "v1.0.0", Scheme: GitSSH}, valid: true},
		{name: "http rejected", locator: "http://github.com/acme/app.git", ref: "main", valid: false},
		{name: "userinfo rejected", locator: "https://user:pass@github.com/acme/app.git", ref: "main", valid: false},
		{name: "invalid ref rejected", locator: "https://github.com/acme/app.git", ref: "main..tmp", valid: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeGitSource(tt.locator, tt.ref)
			if tt.valid {
				if err != nil {
					t.Fatalf("NormalizeGitSource() error = %v", err)
				}
				if got != tt.want {
					t.Fatalf("NormalizeGitSource() = %+v, want %+v", got, tt.want)
				}
				again, err := NormalizeGitSource(got.Locator, got.Ref)
				if err != nil || again != got {
					t.Fatalf("normalization is not idempotent: got=%+v err=%v", again, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("NormalizeGitSource() accepted invalid input: %+v", got)
			}
		})
	}
}

func TestUnitSRC002DigestUploadTree(t *testing.T) {
	base := []TreeEntry{
		{Path: "z.txt", Data: []byte("last"), Mode: 0o644},
		{Path: "a/index.html", Data: []byte("hello"), Mode: 0o644},
		{Path: ".DS_Store", Data: []byte("machine metadata"), Mode: 0o644},
	}
	got, err := DigestTree(base)
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := DigestTree([]TreeEntry{base[2], base[0], base[1]})
	if err != nil {
		t.Fatal(err)
	}
	if got != reordered {
		t.Fatalf("same tree changed digest after reorder: %s != %s", got, reordered)
	}
	permissionNormalized := append([]TreeEntry(nil), base...)
	permissionNormalized[0].Mode = 0o400
	permissionNormalized[1].Mode = 0o600
	permissionDigest, err := DigestTree(permissionNormalized)
	if err != nil || permissionDigest != got {
		t.Fatalf("read/write permission normalization changed digest: %s err=%v", permissionDigest, err)
	}
	executable := append([]TreeEntry(nil), base...)
	executable[0].Mode = 0o755
	executableDigest, err := DigestTree(executable)
	if err != nil || executableDigest == got {
		t.Fatalf("executable semantics were not included in digest: %s err=%v", executableDigest, err)
	}
	changed := append([]TreeEntry(nil), base...)
	changed[1].Data = []byte("hellO")
	changedDigest, err := DigestUploadTree(changed)
	if err != nil {
		t.Fatal(err)
	}
	if got == changedDigest {
		t.Fatal("one-byte content change did not change digest")
	}
	metadataChanged := append([]TreeEntry(nil), base...)
	metadataChanged[2].Data = []byte("different metadata")
	metadataDigest, err := DigestTree(metadataChanged)
	if err != nil {
		t.Fatal(err)
	}
	if got != metadataDigest {
		t.Fatal("ignored system metadata changed source digest")
	}

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a", "index.html"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "z.txt"), []byte("last"), 0o644); err != nil {
		t.Fatal(err)
	}
	directoryDigest, err := HashDirectory(root)
	if err != nil || directoryDigest != got {
		t.Fatalf("directory digest = %s err=%v, want %s", directoryDigest, err, got)
	}
}

func TestUnitARCHIVE001SafetyClassification(t *testing.T) {
	limits := ArchiveLimits{MaxFiles: 2, MaxUnpackedBytes: 10, IgnoreHidden: true}
	tests := []struct {
		name         string
		entries      []ArchiveEntry
		wantError    ArchiveViolation
		wantFiles    int64
		wantBytes    int64
		wantSkip     int64
		ignoreHidden bool
	}{
		{name: "safe and hidden", entries: []ArchiveEntry{{Name: "app/index.html", Kind: ArchiveRegular, Size: 5}, {Name: ".DS_Store", Kind: ArchiveRegular, Size: 99}, {Name: "app", Kind: ArchiveDirectory}}, wantFiles: 1, wantBytes: 5, wantSkip: 1, ignoreHidden: true},
		{name: "application dotfile retained by default", entries: []ArchiveEntry{{Name: ".well-known/assetlinks.json", Kind: ArchiveRegular, Size: 2}}, wantFiles: 1, wantBytes: 2},
		{name: "traversal", entries: []ArchiveEntry{{Name: "../outside", Kind: ArchiveRegular, Size: 1}}, wantError: ViolationPathTraversal},
		{name: "absolute", entries: []ArchiveEntry{{Name: "/etc/passwd", Kind: ArchiveRegular, Size: 1}}, wantError: ViolationAbsolutePath},
		{name: "windows absolute", entries: []ArchiveEntry{{Name: `C:\\Windows\\system.ini`, Kind: ArchiveRegular, Size: 1}}, wantError: ViolationAbsolutePath},
		{name: "symlink", entries: []ArchiveEntry{{Name: "escape", Kind: ArchiveSymlink, Size: 0, Linkname: "/etc"}}, wantError: ViolationSpecialFile},
		{name: "too many", entries: []ArchiveEntry{{Name: "a", Kind: ArchiveRegular, Size: 1}, {Name: "b", Kind: ArchiveRegular, Size: 1}, {Name: "c", Kind: ArchiveRegular, Size: 1}}, wantError: ViolationTooManyFiles},
		{name: "too large", entries: []ArchiveEntry{{Name: "a", Kind: ArchiveRegular, Size: 11}}, wantError: ViolationTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caseLimits := limits
			caseLimits.IgnoreHidden = tt.ignoreHidden
			report, err := InspectArchive(tt.entries, caseLimits)
			if tt.wantError != "" {
				if err == nil {
					t.Fatalf("InspectArchive accepted unsafe entries: %+v", report)
				}
				var archiveErr *ArchiveError
				if !errors.As(err, &archiveErr) || archiveErr.Violation != tt.wantError {
					t.Fatalf("error = %v, want violation %s", err, tt.wantError)
				}
				if report.Decisions != nil || report.FileCount != 0 || report.UnpackedBytes != 0 {
					t.Fatalf("unsafe archive returned partial report: %+v", report)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if report.FileCount != tt.wantFiles || report.UnpackedBytes != tt.wantBytes || report.IgnoredHidden != tt.wantSkip {
				t.Fatalf("report = %+v", report)
			}
		})
	}
}

func TestUnitREDACT001SecretsAndEncodedVariants(t *testing.T) {
	secret := "tok+en/with=chars"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	urlEncoded := strings.ReplaceAll(strings.ReplaceAll(fmt.Sprintf("%s", secret), "+", "%2B"), "/", "%2F")
	hexEncoded := hex.EncodeToString([]byte(secret))
	input := fmt.Sprintf("event=deploy user=alice password=\"%s\" token=%s\nCookie: sid=%s; theme=dark\nAuthorization: Bearer %s b64=%s url=%s hex=%s", secret, secret, secret, secret, encoded, urlEncoded, hexEncoded)
	got := NewRedactor(secret).RedactString(input)
	for _, leaked := range []string{secret, encoded, urlEncoded, hexEncoded} {
		if strings.Contains(got, leaked) {
			t.Fatalf("redacted value still contains %q: %s", leaked, got)
		}
	}
	if !strings.Contains(got, "event=deploy") || !strings.Contains(got, "user=alice") {
		t.Fatalf("non-sensitive fields were not preserved: %s", got)
	}
	structured := map[string]any{"name": "app", "password": secret, "nested": map[string]any{"token": secret, "ok": "yes"}}
	redacted := NewRedactor(secret).RedactMap(structured)
	if structured["password"] != secret || redacted["password"] == secret {
		t.Fatalf("RedactMap mutated input or failed to mask password: input=%v output=%v", structured, redacted)
	}
	nested := redacted["nested"].(map[string]any)
	if nested["token"] == secret || nested["ok"] != "yes" {
		t.Fatalf("nested map redaction incorrect: %v", nested)
	}
}

func TestUnitWEBHOOK001SignatureVectorAndReplay(t *testing.T) {
	secret := "whsec_test"
	timestamp := int64(1700000000)
	eventID := "evt_123"
	payload := []byte(`{"event":"deploy","ok":true}`)
	message := CanonicalWebhookMessage(timestamp, eventID, payload)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(message)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	got, err := SignWebhook(secret, timestamp, eventID, payload)
	if err != nil || got != want {
		t.Fatalf("signature = %q err=%v, want %q", got, err, want)
	}
	now := time.Unix(timestamp+60, 0).UTC()
	if err := VerifyWebhookSignature(secret, timestamp, eventID, payload, got, now); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := VerifyWebhookSignature(secret, timestamp, eventID, []byte(`{"event":"other"}`), got, now); err == nil {
		t.Fatal("signature accepted after payload mutation")
	}
	if err := VerifyWebhookSignature(secret, timestamp-DefaultWebhookReplayWindow.Milliseconds()/1000-1, eventID, payload, got, now); !errors.Is(err, ErrWebhookReplay) {
		t.Fatalf("stale signature error = %v, want replay error", err)
	}
	if WebhookEventID("deployment.failed", "dep_1", now) != WebhookEventID("deployment.failed", "dep_1", now) {
		t.Fatal("event ID is not stable")
	}
}

func TestUnitUSAGE001AggregateAveragePeakTrend(t *testing.T) {
	start := time.Unix(1700000000, 0).UTC()
	samples := []UsageSample{
		{At: start.Add(20 * time.Second), CPU: 0.5, MemoryBytes: 300, DiskBytes: 30, NetworkRxBytes: 3, RestartCount: 1},
		{At: start, CPU: 0.1, MemoryBytes: 100, DiskBytes: 10, NetworkRxBytes: 1},
		{At: start.Add(10 * time.Second), CPU: 0.3, MemoryBytes: 200, DiskBytes: 20, NetworkRxBytes: 2, ExceptionCount: 1},
	}
	got, err := AggregateSamples(samples)
	if err != nil {
		t.Fatal(err)
	}
	if got.SampleCount != 3 || got.AverageCPU != 0.3 || got.PeakCPU != 0.5 || got.TrendCPU != 0.02 {
		t.Fatalf("aggregate CPU = %+v", got)
	}
	if got.AverageMemoryBytes != 200 || got.PeakMemoryBytes != 300 || got.TrendMemoryBytes != 10 {
		t.Fatalf("aggregate memory = %+v", got)
	}
	if got.NetworkRxBytes != 6 || got.RestartCount != 1 || got.ExceptionCount != 1 || got.CPUSeconds != 6 || got.MemoryByteSeconds != 4_000 {
		t.Fatalf("aggregate counters/integrals = %+v", got)
	}
	if Trend(0.1, 0.5, start, start.Add(20*time.Second)) != got.TrendCPU {
		t.Fatalf("Trend helper disagrees: %v vs %v", Trend(0.1, 0.5, start, start.Add(20*time.Second)), got.TrendCPU)
	}
}

func TestUnitAI001FingerprintCacheAndVersionKeys(t *testing.T) {
	problem := ProblemInput{TaskType: "build_failure_diagnosis", ApplicationID: "app_1", ErrorCode: "BUILD_FAILED", ErrorMessage: "compiler\n  failed", EvidenceDigests: []string{"sha256:b", "sha256:a", "sha256:a"}}
	otherOrder := problem
	otherOrder.ErrorMessage = "compiler failed"
	otherOrder.EvidenceDigests = []string{"sha256:a", "sha256:b"}
	fingerprint := ProblemFingerprint(problem)
	if fingerprint == "" || fingerprint != ProblemFingerprint(otherOrder) {
		t.Fatalf("equivalent problem changed fingerprint: %q vs %q", fingerprint, ProblemFingerprint(otherOrder))
	}
	versionOne := VersionKey("src_1", "definition_1", "policy_1")
	versionOneAgain := VersionKey("src_1", "definition_1", "policy_1")
	versionTwo := VersionKey("src_2", "definition_1", "policy_1")
	if versionOne != versionOneAgain || versionOne == versionTwo {
		t.Fatalf("version key stability/separation failed: %q %q %q", versionOne, versionOneAgain, versionTwo)
	}
	cacheOne := CacheKey(fingerprint, versionOne, "policy_1")
	cacheTwo := CacheKey(fingerprint, versionTwo, "policy_1")
	if cacheOne == cacheTwo || cacheOne != CacheKey(fingerprint, versionOne, "policy_1") {
		t.Fatalf("cache key stability/separation failed: %q %q", cacheOne, cacheTwo)
	}
	if strings.Contains(fingerprint+versionOne+cacheOne, "build_failure") || strings.Contains(fingerprint+versionOne+cacheOne, "compiler") {
		t.Fatal("AI keys leaked problem text")
	}
}
