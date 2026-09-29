package sourcebuildexecution

import (
	"context"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"os"
	"strings"
	"testing"
)

func TestProductionSourceBuildFailsClosedAndPersistsBoundedLogs(t *testing.T) {
	if err := ValidateProductionConfig(ProductionConfig{}); err == nil {
		t.Fatal("missing Core authority and resolver accepted")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	sink, err := NewFileBuildLogSink(root, []string{"/owned/workspace"})
	if err != nil {
		t.Fatal(err)
	}
	request := contracts.BuildRequest{BuildID: domain.ID("build_log_fixture"), Source: domain.SourceRevision{Locator: "https://github.com/acme/app", WorkspaceRef: "/owned/workspace/source"}}
	original := "build source /owned/workspace/source token=private-token\n"
	ref, err := sink.StoreBuildLog(context.Background(), request, original)
	if err != nil || !strings.Contains(ref, "source-limited") || strings.Contains(ref, "private-token") {
		t.Fatalf("bounded log unavailable: %v", err)
	}
	replay, err := sink.StoreBuildLog(context.Background(), request, original)
	if err != nil || replay != ref {
		t.Fatal("original log replay changed immutable reference")
	}
	if _, err := sink.StoreBuildLog(context.Background(), request, "different output"); err == nil {
		t.Fatal("immutable log was appended or replaced")
	}
	if _, err := sink.StoreBuildLog(context.Background(), request, strings.Repeat("x", (1<<20)+1)); err == nil {
		t.Fatal("oversized capture persisted")
	}
	segments, err := sink.logs.List("build", "build-build_log_fixture")
	if err != nil || len(segments) != 1 {
		t.Fatal("single immutable log segment unavailable")
	}
	info, err := os.Stat(segments[0].Path)
	if err != nil || info.Mode().Perm() != 0400 {
		t.Fatal("persisted log capture is not read-only")
	}
	data, err := sink.logs.Read("build", "build-build_log_fixture")
	if err != nil || strings.Contains(string(data), "private-token") || strings.Contains(string(data), "/owned/workspace") {
		t.Fatal("private build log material not redacted")
	}
}
