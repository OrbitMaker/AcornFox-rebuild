package domain

import (
	"strings"
	"testing"
	"time"
)

func TestSourceUploadPathRejectsAmbiguousOrHostPaths(t *testing.T) {
	for _, value := range []string{"/absolute", `C:\\drive`, `folder\\file`, "", "a//b", "a/./b", "a/../b", "a/", "a\x00b", "目录/file", "a:drive"} {
		if _, err := NormalizeSourceUploadPath(value); err == nil {
			t.Fatalf("unsafe path accepted: %q", value)
		}
	}
	if value, err := NormalizeSourceUploadPath("src/main.go"); err != nil || value != "src/main.go" {
		t.Fatalf("safe path=%q err=%v", value, err)
	}
}

func TestSourceUploadRequiresOneTimeClaimShape(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	upload := SourceUploadRecord{ID: "upload_1", Kind: SourceUploadDirectory, Status: SourceUploadReady, Digest: "sha256:" + strings.Repeat("a", 64), Bytes: 4, FileCount: 1, StorageRef: "upload://upload_1", ExpiresAt: now.Add(24 * time.Hour), IdempotencyKey: "upload-key", RequestDigest: "sha256:" + strings.Repeat("b", 64), CreatedAt: now, UpdatedAt: now, Files: []SourceUploadFile{{Path: "src/main.go", Bytes: 4, Digest: "sha256:" + strings.Repeat("c", 64)}}}
	if err := upload.Validate(); err != nil {
		t.Fatal(err)
	}
	upload.Status = SourceUploadClaimed
	if err := upload.Validate(); err == nil {
		t.Fatal("claim without immutable consumer ids was accepted")
	}
	upload.ClaimedApplicationID, upload.ClaimedSourceID = "app_1", "src_1"
	if err := upload.Validate(); err != nil {
		t.Fatal(err)
	}
}
