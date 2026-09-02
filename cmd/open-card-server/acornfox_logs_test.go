package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/observability"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type acornFoxLogReaderFixture struct {
	page            postgres.AcornFoxDeliveryLogIndexes
	err             error
	redactionValues []string
	redactionErr    error
	seen            struct {
		application domain.ID
		deployment  domain.ID
		source      postgres.LogIndexCategory
		limit       int
		cursor      *postgres.AcornFoxLogIndexCursor
	}
}

func (f *acornFoxLogReaderFixture) GetAcornFoxDeliveryLogRedactionValues(_ context.Context, _, _ domain.ID) ([]string, error) {
	return append([]string(nil), f.redactionValues...), f.redactionErr
}

func (f *acornFoxLogReaderFixture) ListAcornFoxDeliveryLogIndexes(_ context.Context, application, deployment domain.ID, source postgres.LogIndexCategory, cursor *postgres.AcornFoxLogIndexCursor, limit int) (postgres.AcornFoxDeliveryLogIndexes, error) {
	f.seen.application, f.seen.deployment, f.seen.source, f.seen.limit, f.seen.cursor = application, deployment, source, limit, cursor
	return f.page, f.err
}

func TestAcornFoxLogsHTTPHandlerReadsLogicalRecordsWithBoundedRedaction(t *testing.T) {
	t.Parallel()
	logs, err := observability.NewLogStore(observability.LogStoreConfig{RootDir: t.TempDir(), MaxFileBytes: 128 << 10, MaxTotalBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	locator := "https://private.example/repo.git"
	encodedLocator := base64.RawURLEncoding.EncodeToString([]byte(locator))
	file, err := logs.AppendRecord(observability.LogCategoryBuild, "build_1", []byte("token=secret-value workspace=/private/workspace locator="+locator+" encoded="+encodedLocator+" body"))
	if err != nil {
		t.Fatal(err)
	}
	digest, _, err := acornFoxLogSegmentDigest(filepath.Join(logs.RootDir(), string(observability.LogCategoryBuild)), file.Path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	fixture := &acornFoxLogReaderFixture{redactionValues: []string{locator}, page: postgres.AcornFoxDeliveryLogIndexes{Records: []postgres.AcornFoxDeliveryLogRecord{{Category: postgres.LogIndexBuild, BuildID: "build_1", LogStream: postgres.LogStreamCombined, Truncation: postgres.LogTruncationComplete, RecordedAt: now, Segments: []postgres.LogIndex{{ID: "log_1", ApplicationID: "app_1", ServiceName: "web", Category: postgres.LogIndexBuild, BuildID: "build_1", LogStream: postgres.LogStreamCombined, Truncation: postgres.LogTruncationComplete, Path: file.Path, Segment: file.Sequence, ByteSize: file.Bytes, ContentDigest: digest, CreatedAt: now}}}}}}
	handler := newAcornFoxLogsHTTPHandler(fixture, logs, "/private/workspace")
	request := httptest.NewRequest(http.MethodGet, "/?source=build", nil)
	recorder := httptest.NewRecorder()
	handler.Handle(recorder, request, "app_1", "dep_1")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response acornFoxLogsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Source != "build" || response.Availability != "available" || len(response.Items) != 1 || response.Items[0].Stream != "combined" || response.Items[0].Truncation != "complete" {
		t.Fatalf("unexpected response: %#v", response)
	}
	if strings.Contains(response.Items[0].Content, "secret-value") || strings.Contains(response.Items[0].Content, "/private/workspace") || strings.Contains(response.Items[0].Content, "private.example") || strings.Contains(response.Items[0].Content, encodedLocator) || !strings.Contains(response.Items[0].Content, "[REDACTED]") {
		t.Fatalf("response did not redact derived and generic sensitive values: %q", response.Items[0].Content)
	}
	if fixture.seen.application != "app_1" || fixture.seen.deployment != "dep_1" || fixture.seen.source != postgres.LogIndexBuild || fixture.seen.limit != acornFoxLogsMaximumRecordsPerPage || fixture.seen.cursor != nil {
		t.Fatalf("unexpected store call: %#v", fixture.seen)
	}
}

func TestAcornFoxLogsHTTPHandlerReconstructsNewlineDelimitedLogicalLines(t *testing.T) {
	t.Parallel()
	logs, err := observability.NewLogStore(observability.LogStoreConfig{RootDir: t.TempDir(), MaxFileBytes: 9, MaxTotalBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if err := logs.Append(observability.LogCategoryRuntime, "runtime_lines", []byte("line-one\nline-two\n")); err != nil {
		t.Fatal(err)
	}
	files, err := logs.List(observability.LogCategoryRuntime, "runtime_lines")
	if err != nil || len(files) != 2 {
		t.Fatalf("runtime segments=%#v err=%v", files, err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	segments := make([]postgres.LogIndex, 0, len(files))
	for _, file := range files {
		digest, _, err := acornFoxLogSegmentDigest(filepath.Join(logs.RootDir(), string(observability.LogCategoryRuntime)), file.Path)
		if err != nil {
			t.Fatal(err)
		}
		segments = append(segments, postgres.LogIndex{ID: domain.ID("log_lines_" + strconv.Itoa(file.Sequence)), ApplicationID: "app_1", ServiceName: "web", DeploymentID: "dep_1", OperationID: "operation_lines", Category: postgres.LogIndexRuntime, LogStream: postgres.LogStreamCombined, Truncation: postgres.LogTruncationComplete, Path: file.Path, Segment: file.Sequence, ByteSize: file.Bytes, ContentDigest: digest, CreatedAt: now})
	}
	fixture := &acornFoxLogReaderFixture{page: postgres.AcornFoxDeliveryLogIndexes{Records: []postgres.AcornFoxDeliveryLogRecord{{Category: postgres.LogIndexRuntime, OperationID: "operation_lines", LogStream: postgres.LogStreamCombined, Truncation: postgres.LogTruncationComplete, RecordedAt: now, Segments: segments}}}}
	handler := newAcornFoxLogsHTTPHandler(fixture, logs)
	recorder := httptest.NewRecorder()
	handler.Handle(recorder, httptest.NewRequest(http.MethodGet, "/?source=runtime", nil), "app_1", "dep_1")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response acornFoxLogsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Items) != 1 || response.Items[0].Content != "line-one\nline-two\n" {
		t.Fatalf("logical lines were not reconstructed: %#v", response.Items)
	}
}

func TestAcornFoxLogsHTTPHandlerRejectsBadAndCrossScopeCursors(t *testing.T) {
	t.Parallel()
	logs, err := observability.NewLogStore(filepath.Join(t.TempDir(), "logs"))
	if err != nil {
		t.Fatal(err)
	}
	fixture := &acornFoxLogReaderFixture{}
	handler := newAcornFoxLogsHTTPHandler(fixture, logs)
	cursor := handler.encodeCursor("app_1", "dep_1", postgres.LogIndexRuntime, postgres.AcornFoxLogIndexCursor{RecordedAt: time.Unix(1_700_000_000, 0).UTC(), RecordKey: "op_1\x1fcombined"})
	for _, raw := range []string{"/?source=runtime&cursor=broken", "/?source=runtime&cursor=" + cursor, "/?source=build&cursor=" + cursor, "/?source=runtime&limit=101", "/?source=runtime&source=build"} {
		recorder := httptest.NewRecorder()
		handler.Handle(recorder, httptest.NewRequest(http.MethodGet, raw, nil), "app_1", "dep_2")
		if recorder.Code != http.StatusUnprocessableEntity || !strings.Contains(recorder.Body.String(), "invalid_log_query") {
			t.Fatalf("%s status=%d body=%s", raw, recorder.Code, recorder.Body.String())
		}
	}
}

func TestAcornFoxLogsHTTPHandlerReturnsRetiredWithoutReadingStorage(t *testing.T) {
	t.Parallel()
	logs, err := observability.NewLogStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fixture := &acornFoxLogReaderFixture{page: postgres.AcornFoxDeliveryLogIndexes{HasRetiredIndexes: true}}
	handler := newAcornFoxLogsHTTPHandler(fixture, logs)
	recorder := httptest.NewRecorder()
	handler.Handle(recorder, httptest.NewRequest(http.MethodGet, "/?source=runtime", nil), "app_1", "dep_1")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"availability":"retired"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAcornFoxLogsHTTPHandlerDisclosesRetiredIndexesAlongsideActiveItems(t *testing.T) {
	t.Parallel()
	logs, err := observability.NewLogStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file, err := logs.AppendRecord(observability.LogCategoryRuntime, "active", []byte("active"))
	if err != nil {
		t.Fatal(err)
	}
	digest, _, err := acornFoxLogSegmentDigest(filepath.Join(logs.RootDir(), string(observability.LogCategoryRuntime)), file.Path)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &acornFoxLogReaderFixture{page: postgres.AcornFoxDeliveryLogIndexes{HasRetiredIndexes: true, Records: []postgres.AcornFoxDeliveryLogRecord{{Category: postgres.LogIndexRuntime, OperationID: "operation_active", LogStream: postgres.LogStreamStdout, Truncation: postgres.LogTruncationComplete, RecordedAt: time.Now().UTC(), Segments: []postgres.LogIndex{{ID: "log_active", ApplicationID: "app_1", ServiceName: "web", DeploymentID: "dep_1", OperationID: "operation_active", Category: postgres.LogIndexRuntime, LogStream: postgres.LogStreamStdout, Truncation: postgres.LogTruncationComplete, Path: file.Path, Segment: file.Sequence, ByteSize: file.Bytes, ContentDigest: digest, CreatedAt: time.Now().UTC()}}}}}}
	recorder := httptest.NewRecorder()
	newAcornFoxLogsHTTPHandler(fixture, logs).Handle(recorder, httptest.NewRequest(http.MethodGet, "/?source=runtime", nil), "app_1", "dep_1")
	var response acornFoxLogsResponse
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &response) != nil || !response.RetentionLimited || len(response.Items) != 1 || response.Availability != "available" {
		t.Fatalf("status=%d response=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAcornFoxLogsHTTPHandlerRejectsLegacyQueryKeysAndProtectsRouteMethod(t *testing.T) {
	t.Parallel()
	logs, err := observability.NewLogStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newAcornFoxLogsHTTPHandler(&acornFoxLogReaderFixture{}, logs)
	for _, raw := range []string{"/?source=runtime&path=/etc/passwd", "/?source=runtime&build_id=build_1", "/?source=runtime&tail=10"} {
		recorder := httptest.NewRecorder()
		handler.Handle(recorder, httptest.NewRequest(http.MethodGet, raw, nil), "app_1", "dep_1")
		if recorder.Code != http.StatusUnprocessableEntity {
			t.Fatalf("%s status=%d", raw, recorder.Code)
		}
	}
	server := NewAcornFoxServer()
	server.SetAcornFoxLogs(nil)
	recorder := httptest.NewRecorder()
	server.handleAcornFoxDeliveryLogs(recorder, httptest.NewRequest(http.MethodPost, "/", nil), "app_1", "dep_1")
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != "GET, OPTIONS" {
		t.Fatalf("method status=%d allow=%q", recorder.Code, recorder.Header().Get("Allow"))
	}
}

func TestAcornFoxLogsHTTPHandlerKeepsEncodedResponseUnderOneMiB(t *testing.T) {
	t.Parallel()
	logs, err := observability.NewLogStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	records := make([]postgres.AcornFoxDeliveryLogRecord, 0, acornFoxLogsMaximumRecordsPerPage)
	for index := 0; index < acornFoxLogsMaximumRecordsPerPage; index++ {
		file, err := logs.AppendRecord(observability.LogCategoryRuntime, "runtime_"+strconv.Itoa(index), []byte(strings.Repeat("x", acornFoxLogMaximumBytes)))
		if err != nil {
			t.Fatal(err)
		}
		digest, _, err := acornFoxLogSegmentDigest(filepath.Join(logs.RootDir(), string(observability.LogCategoryRuntime)), file.Path)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, postgres.AcornFoxDeliveryLogRecord{Category: postgres.LogIndexRuntime, OperationID: domain.ID("operation_" + strconv.Itoa(index)), LogStream: postgres.LogStreamCombined, Truncation: postgres.LogTruncationComplete, RecordedAt: now.Add(time.Duration(index) * time.Second), Segments: []postgres.LogIndex{{ID: domain.ID("log_" + strconv.Itoa(index)), ApplicationID: "app_1", ServiceName: "web", DeploymentID: "dep_1", OperationID: domain.ID("operation_" + strconv.Itoa(index)), Category: postgres.LogIndexRuntime, LogStream: postgres.LogStreamCombined, Truncation: postgres.LogTruncationComplete, Path: file.Path, Segment: file.Sequence, ByteSize: file.Bytes, ContentDigest: digest, CreatedAt: now}}})
	}
	fixture := &acornFoxLogReaderFixture{page: postgres.AcornFoxDeliveryLogIndexes{Records: records, NextCursor: &postgres.AcornFoxLogIndexCursor{RecordedAt: now, RecordKey: "cursor_15"}}}
	handler := newAcornFoxLogsHTTPHandler(fixture, logs)
	recorder := httptest.NewRecorder()
	handler.Handle(recorder, httptest.NewRequest(http.MethodGet, "/?source=runtime&limit=100", nil), "app_1", "dep_1")
	var response acornFoxLogsResponse
	if recorder.Code != http.StatusOK || recorder.Body.Len() > acornFoxLogsMaximumBytes || json.Unmarshal(recorder.Body.Bytes(), &response) != nil || len(response.Items) != len(records) || response.NextCursor == nil {
		t.Fatalf("status=%d responseBytes=%d", recorder.Code, recorder.Body.Len())
	}
}

func TestAcornFoxLogsHTTPHandlerFailsClosedForSameLengthTamperAndAncestorSymlink(t *testing.T) {
	t.Parallel()
	logs, err := observability.NewLogStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file, err := logs.AppendRecord(observability.LogCategoryRuntime, "runtime_tamper", []byte("valid"))
	if err != nil {
		t.Fatal(err)
	}
	digest, _, err := acornFoxLogSegmentDigest(filepath.Join(logs.RootDir(), string(observability.LogCategoryRuntime)), file.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file.Path, []byte("other"), 0o640); err != nil {
		t.Fatal(err)
	}
	newFixture := func(path string, bytes int64, contentDigest string) *acornFoxLogReaderFixture {
		return &acornFoxLogReaderFixture{page: postgres.AcornFoxDeliveryLogIndexes{Records: []postgres.AcornFoxDeliveryLogRecord{{Category: postgres.LogIndexRuntime, OperationID: "operation_1", LogStream: postgres.LogStreamCombined, Truncation: postgres.LogTruncationComplete, RecordedAt: time.Now().UTC(), Segments: []postgres.LogIndex{{ID: "log_1", ApplicationID: "app_1", ServiceName: "web", DeploymentID: "dep_1", OperationID: "operation_1", Category: postgres.LogIndexRuntime, LogStream: postgres.LogStreamCombined, Truncation: postgres.LogTruncationComplete, Path: path, Segment: 0, ByteSize: bytes, ContentDigest: contentDigest, CreatedAt: time.Now().UTC()}}}}}}
	}
	for _, fixture := range []*acornFoxLogReaderFixture{newFixture(file.Path, file.Bytes, digest)} {
		recorder := httptest.NewRecorder()
		newAcornFoxLogsHTTPHandler(fixture, logs).Handle(recorder, httptest.NewRequest(http.MethodGet, "/?source=runtime", nil), "app_1", "dep_1")
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("same-size tamper status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	}

	external := t.TempDir()
	if err := os.WriteFile(filepath.Join(external, "segment.log"), []byte("outside"), 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(logs.RootDir(), string(observability.LogCategoryRuntime), "ancestor-link")
	if err := os.Symlink(external, link); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	newAcornFoxLogsHTTPHandler(newFixture(filepath.Join(link, "segment.log"), int64(len("outside")), "sha256:"+strings.Repeat("a", 64)), logs).Handle(recorder, httptest.NewRequest(http.MethodGet, "/?source=runtime", nil), "app_1", "dep_1")
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("ancestor symlink status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAcornFoxLogsHTTPHandlerFailsClosedForCorruptActiveSegment(t *testing.T) {
	t.Parallel()
	logs, err := observability.NewLogStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file, err := logs.AppendRecord(observability.LogCategoryRuntime, "runtime_1", []byte("valid"))
	if err != nil {
		t.Fatal(err)
	}
	digest, _, err := acornFoxLogSegmentDigest(filepath.Join(logs.RootDir(), string(observability.LogCategoryRuntime)), file.Path)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &acornFoxLogReaderFixture{page: postgres.AcornFoxDeliveryLogIndexes{Records: []postgres.AcornFoxDeliveryLogRecord{{Category: postgres.LogIndexRuntime, OperationID: "operation_1", LogStream: postgres.LogStreamCombined, Truncation: postgres.LogTruncationComplete, RecordedAt: time.Now().UTC(), Segments: []postgres.LogIndex{{ID: "log_1", ApplicationID: "app_1", ServiceName: "web", DeploymentID: "dep_1", OperationID: "operation_1", Category: postgres.LogIndexRuntime, LogStream: postgres.LogStreamCombined, Truncation: postgres.LogTruncationComplete, Path: file.Path, Segment: file.Sequence, ByteSize: file.Bytes + 1, ContentDigest: digest, CreatedAt: time.Now().UTC()}}}}}}
	handler := newAcornFoxLogsHTTPHandler(fixture, logs)
	recorder := httptest.NewRecorder()
	handler.Handle(recorder, httptest.NewRequest(http.MethodGet, "/?source=runtime", nil), "app_1", "dep_1")
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "log_integrity_unavailable") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
