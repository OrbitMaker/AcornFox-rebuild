package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	"github.com/open-card/open-card/internal/observability"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

const (
	acornFoxLogsDefaultLimit  = 50
	acornFoxLogsMaximumLimit  = 100
	acornFoxLogMaximumBytes   = 64 << 10
	acornFoxLogsMaximumBytes  = 1 << 20
	acornFoxLogSegmentCeiling = 1 << 30
	// Public records are deliberately smaller than the storage read cap. JSON
	// escaping can expand arbitrary control bytes sixfold; fifteen 8KiB records
	// remain below the response bound even in that worst case.
	acornFoxLogResponseItemBytes      = 8 << 10
	acornFoxLogsMaximumRecordsPerPage = 15
)

// acornFoxDeliveryLogReader deliberately returns logical records rather than
// files. The HTTP surface consequently cannot expose paths, segment IDs, or
// internal source locators as pagination material.
type acornFoxDeliveryLogReader interface {
	ListAcornFoxDeliveryLogIndexes(context.Context, domain.ID, domain.ID, postgres.LogIndexCategory, *postgres.AcornFoxLogIndexCursor, int) (postgres.AcornFoxDeliveryLogIndexes, error)
	GetAcornFoxDeliveryLogRedactionValues(context.Context, domain.ID, domain.ID) ([]string, error)
}

// AcornFoxLogsHTTPHandler serves already-collected AcornFox build/runtime
// evidence. It has no task queue or runtime provider, so GET cannot trigger
// Docker, an Agent task, or a new deployment operation.
type AcornFoxLogsHTTPHandler struct {
	Store     acornFoxDeliveryLogReader
	Logs      *observability.LogStore
	redactor  foundation.Redactor
	cursorKey []byte
}

func newAcornFoxLogsHTTPHandler(store acornFoxDeliveryLogReader, logs *observability.LogStore, redactionValues ...string) *AcornFoxLogsHTTPHandler {
	values := append([]string(nil), redactionValues...)
	if logs != nil {
		values = append(values, logs.RootDir())
	}
	keySeed := strings.Join(values, "\x00")
	digest := sha256.Sum256([]byte("acornfox-log-cursor-v1\x00" + keySeed))
	return &AcornFoxLogsHTTPHandler{Store: store, Logs: logs, redactor: foundation.NewRedactor(values...), cursorKey: digest[:]}
}

func (h *AcornFoxLogsHTTPHandler) Handle(w http.ResponseWriter, r *http.Request, applicationID, deploymentID domain.ID) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if h == nil || h.Store == nil || h.Logs == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "logs_unavailable", "logs are unavailable")
		return
	}
	source, limit, cursor, err := h.parseQuery(r, applicationID, deploymentID)
	if err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, "invalid_log_query", "logs query is invalid")
		return
	}
	fetchLimit := limit
	if fetchLimit > acornFoxLogsMaximumRecordsPerPage {
		fetchLimit = acornFoxLogsMaximumRecordsPerPage
	}
	page, err := h.Store.ListAcornFoxDeliveryLogIndexes(r.Context(), applicationID, deploymentID, source, cursor, fetchLimit)
	if errors.Is(err, postgres.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "logs_unavailable", "logs are unavailable")
		return
	}
	redactionValues, err := h.Store.GetAcornFoxDeliveryLogRedactionValues(r.Context(), applicationID, deploymentID)
	if errors.Is(err, postgres.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "log_integrity_unavailable", "log integrity is unavailable")
		return
	}

	items := make([]acornFoxLogItem, 0, len(page.Records))
	remaining := acornFoxLogsMaximumRecordsPerPage * acornFoxLogResponseItemBytes
	for _, record := range page.Records {
		if remaining == 0 {
			break
		}
		content, responseLimited, readErr := h.readRecord(record, minAcornFoxLogBytes(remaining, acornFoxLogResponseItemBytes))
		if readErr != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "log_integrity_unavailable", "log integrity is unavailable")
			return
		}
		remaining -= len(content)
		truncation := string(record.Truncation)
		if responseLimited {
			truncation = "response_limited"
		}
		if truncation == "" {
			truncation = "unknown"
		}
		content = normalizeAcornFoxLogText(content)
		items = append(items, acornFoxLogItem{Stream: string(record.LogStream), RecordedAt: record.RecordedAt.UTC(), Content: h.redact(content, redactionValues...), Truncation: truncation})
	}
	availability := "available"
	if len(items) == 0 {
		availability = "not_collected"
		if page.HasRetiredIndexes {
			availability = "retired"
		}
	}
	var next any
	if page.NextCursor != nil {
		next = h.encodeCursor(applicationID, deploymentID, source, *page.NextCursor)
	}
	response := acornFoxLogsResponse{Source: string(source), Availability: availability, Items: items, NextCursor: next, RetentionLimited: page.HasRetiredIndexes}
	// The conservative per-record bound above is the cursor-safety mechanism:
	// it guarantees every fetched record is emitted, so the storage keyset
	// cursor never skips content that response shaping removed.
	if encoded, _ := json.Marshal(response); len(encoded) > acornFoxLogsMaximumBytes {
		writeJSONError(w, http.StatusServiceUnavailable, "log_integrity_unavailable", "log response is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

type acornFoxLogItem struct {
	Stream     string    `json:"stream"`
	RecordedAt time.Time `json:"recorded_at"`
	Content    string    `json:"content"`
	Truncation string    `json:"truncation"`
}

type acornFoxLogsResponse struct {
	Source           string            `json:"source"`
	Availability     string            `json:"availability"`
	Items            []acornFoxLogItem `json:"items"`
	NextCursor       any               `json:"next_cursor"`
	RetentionLimited bool              `json:"retention_limited"`
}

type acornFoxLogCursorWire struct {
	Version     int    `json:"v"`
	Application string `json:"a"`
	Deployment  string `json:"d"`
	Source      string `json:"s"`
	ScopeDigest string `json:"h"`
	RecordedAt  string `json:"t"`
	RecordKey   string `json:"k"`
	MAC         string `json:"m"`
}

func (h *AcornFoxLogsHTTPHandler) parseQuery(r *http.Request, applicationID, deploymentID domain.ID) (postgres.LogIndexCategory, int, *postgres.AcornFoxLogIndexCursor, error) {
	query := r.URL.Query()
	for key := range query {
		if key != "source" && key != "limit" && key != "cursor" {
			return "", 0, nil, errors.New("unknown query key")
		}
	}
	sourceValues, present := query["source"]
	if !present || len(sourceValues) != 1 {
		return "", 0, nil, errors.New("source is required")
	}
	source := postgres.LogIndexCategory(strings.TrimSpace(sourceValues[0]))
	if source != postgres.LogIndexBuild && source != postgres.LogIndexRuntime {
		return "", 0, nil, errors.New("source is invalid")
	}
	limit := acornFoxLogsDefaultLimit
	if values, ok := query["limit"]; ok {
		if len(values) != 1 {
			return "", 0, nil, errors.New("limit is ambiguous")
		}
		parsed, err := strconv.Atoi(values[0])
		if err != nil || parsed < 1 || parsed > acornFoxLogsMaximumLimit {
			return "", 0, nil, errors.New("limit is invalid")
		}
		limit = parsed
	}
	if _, ok := query["cursor"]; !ok {
		return source, limit, nil, nil
	}
	values := query["cursor"]
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		return "", 0, nil, errors.New("cursor is invalid")
	}
	cursor, err := h.decodeCursor(applicationID, deploymentID, source, values[0])
	if err != nil {
		return "", 0, nil, err
	}
	return source, limit, cursor, nil
}

func (h *AcornFoxLogsHTTPHandler) readRecord(record postgres.AcornFoxDeliveryLogRecord, remaining int) (string, bool, error) {
	if remaining < 0 {
		return "", true, nil
	}
	var content []byte
	limited := false
	for index := len(record.Segments) - 1; index >= 0; index-- {
		segment := record.Segments[index]
		budget := acornFoxLogMaximumBytes - len(content)
		if budget <= 0 {
			limited = true
			break
		}
		data, sourceLimited, err := h.readSegmentSuffix(record.Category, segment, budget)
		if err != nil {
			return "", false, err
		}
		if sourceLimited {
			limited = true
		}
		content = append(data, content...)
	}
	if len(content) > remaining {
		if remaining == 0 {
			content = nil
		} else {
			content = content[len(content)-remaining:]
		}
		limited = true
	}
	return string(content), limited, nil
}

func (h *AcornFoxLogsHTTPHandler) readSegmentSuffix(category postgres.LogIndexCategory, segment postgres.LogIndex, limit int) ([]byte, bool, error) {
	if h.Logs == nil || strings.TrimSpace(segment.Path) == "" || limit < 1 {
		return nil, false, errors.New("log segment is unavailable")
	}
	file, info, err := acornFoxOpenLogSegment(filepath.Join(h.Logs.RootDir(), string(category)), segment.Path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != segment.ByteSize || info.Size() > acornFoxLogSegmentCeiling {
		return nil, false, errors.New("log segment is unavailable")
	}
	defer file.Close()
	if strings.TrimSpace(segment.ContentDigest) == "" {
		return nil, false, errors.New("log segment integrity digest is unavailable")
	}
	digest, err := acornFoxOpenFileDigest(file)
	if err != nil || !hmac.Equal([]byte(digest), []byte(segment.ContentDigest)) {
		return nil, false, errors.New("log segment integrity digest is invalid")
	}
	start := info.Size() - int64(limit)
	limited := start > 0
	if start < 0 {
		start = 0
	}
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return nil, false, err
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(data) > limit {
		return nil, false, errors.New("log segment is unavailable")
	}
	return data, limited, nil
}

func acornFoxLogSegmentDigest(categoryRoot, path string) (string, int64, error) {
	file, info, err := acornFoxOpenLogSegment(categoryRoot, path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	digest, err := acornFoxOpenFileDigest(file)
	if err != nil {
		return "", 0, err
	}
	return digest, info.Size(), nil
}

func acornFoxOpenFileDigest(file *os.File) (string, error) {
	if file == nil {
		return "", errors.New("log file is unavailable")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

// acornFoxOpenLogSegment checks both the lexical and resolved containment of
// a path. Lstat plus SameFile makes a leaf or ancestor symlink swap fail
// closed between validation and open; the second resolved check catches a
// concurrent parent-directory replacement.
func acornFoxOpenLogSegment(categoryRoot, candidate string) (*os.File, os.FileInfo, error) {
	root := filepath.Clean(categoryRoot)
	clean := filepath.Clean(candidate)
	if !acornFoxPathWithin(root, clean) {
		return nil, nil, errors.New("log segment is outside store")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, nil, err
	}
	before, err := os.Lstat(clean)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, nil, errors.New("log segment is not a regular file")
	}
	resolvedCandidate, err := filepath.EvalSymlinks(clean)
	if err != nil || !acornFoxPathWithin(resolvedRoot, resolvedCandidate) {
		return nil, nil, errors.New("log segment resolves outside store")
	}
	file, err := os.Open(clean)
	if err != nil {
		return nil, nil, err
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, nil, errors.New("log segment changed while opening")
	}
	resolvedAfter, err := filepath.EvalSymlinks(clean)
	if err != nil || resolvedAfter != resolvedCandidate || !acornFoxPathWithin(resolvedRoot, resolvedAfter) {
		_ = file.Close()
		return nil, nil, errors.New("log segment changed while resolving")
	}
	return file, after, nil
}

func acornFoxPathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func minAcornFoxLogBytes(left, right int) int {
	if left < right {
		return left
	}
	return right
}

// normalizeAcornFoxLogText keeps tab/newline formatting but replaces the
// remaining C0 controls. It prevents pathological JSON escaping amplification
// while preserving a clear marker that non-text bytes were omitted.
func normalizeAcornFoxLogText(input string) string {
	return strings.Map(func(value rune) rune {
		if value < 0x20 && value != '\n' && value != '\r' && value != '\t' {
			return '\uFFFD'
		}
		return value
	}, input)
}

func (h *AcornFoxLogsHTTPHandler) redact(content string, perDeliveryValues ...string) string {
	values := append(append([]string(nil), h.redactor.Secrets...), perDeliveryValues...)
	return foundation.NewRedactor(values...).RedactString(foundation.RedactText(content))
}

func (h *AcornFoxLogsHTTPHandler) encodeCursor(applicationID, deploymentID domain.ID, source postgres.LogIndexCategory, cursor postgres.AcornFoxLogIndexCursor) string {
	wire := acornFoxLogCursorWire{Version: 1, Application: applicationID.String(), Deployment: deploymentID.String(), Source: string(source), ScopeDigest: acornFoxLogScopeDigest(applicationID, deploymentID, source), RecordedAt: cursor.RecordedAt.UTC().Format(time.RFC3339Nano), RecordKey: cursor.RecordKey}
	wire.MAC = h.cursorMAC(wire)
	encoded, _ := json.Marshal(wire)
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func (h *AcornFoxLogsHTTPHandler) decodeCursor(applicationID, deploymentID domain.ID, source postgres.LogIndexCategory, encoded string) (*postgres.AcornFoxLogIndexCursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(data) == 0 || len(data) > 2048 {
		return nil, errors.New("cursor encoding is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var wire acornFoxLogCursorWire
	if err := decoder.Decode(&wire); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("cursor has trailing data")
	}
	if wire.Version != 1 || wire.Application != applicationID.String() || wire.Deployment != deploymentID.String() || wire.Source != string(source) || wire.ScopeDigest != acornFoxLogScopeDigest(applicationID, deploymentID, source) || !hmac.Equal([]byte(wire.MAC), []byte(h.cursorMAC(wire))) {
		return nil, errors.New("cursor scope is invalid")
	}
	recordedAt, err := time.Parse(time.RFC3339Nano, wire.RecordedAt)
	if err != nil {
		return nil, err
	}
	cursor := &postgres.AcornFoxLogIndexCursor{RecordedAt: recordedAt.UTC(), RecordKey: wire.RecordKey}
	if err := cursor.Validate(); err != nil {
		return nil, err
	}
	return cursor, nil
}

func (h *AcornFoxLogsHTTPHandler) cursorMAC(wire acornFoxLogCursorWire) string {
	mac := hmac.New(sha256.New, h.cursorKey)
	_, _ = io.WriteString(mac, strings.Join([]string{strconv.Itoa(wire.Version), wire.Application, wire.Deployment, wire.Source, wire.ScopeDigest, wire.RecordedAt, wire.RecordKey}, "\x00"))
	return hex.EncodeToString(mac.Sum(nil))
}

func acornFoxLogScopeDigest(applicationID, deploymentID domain.ID, source postgres.LogIndexCategory) string {
	digest := sha256.Sum256([]byte(applicationID.String() + "\x00" + deploymentID.String() + "\x00" + string(source)))
	return "sha256:" + hex.EncodeToString(digest[:])
}
