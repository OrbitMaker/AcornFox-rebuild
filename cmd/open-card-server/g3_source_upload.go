package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
	"github.com/open-card/open-card/internal/providers/sourceupload"
)

type G3SourceUploadHTTPHandler struct {
	Store   sourceUploadStore
	Manager *sourceupload.Manager
	Clock   func() time.Time
}

type sourceUploadHTTPResponse struct {
	ID        string                    `json:"id"`
	Kind      domain.SourceUploadKind   `json:"kind"`
	Status    domain.SourceUploadStatus `json:"status"`
	Digest    string                    `json:"digest"`
	Bytes     int64                     `json:"bytes"`
	FileCount int                       `json:"file_count"`
	ExpiresAt time.Time                 `json:"expires_at"`
}

type sourceUploadStore interface {
	CreateSourceUpload(context.Context, domain.SourceUploadRecord) (domain.SourceUploadRecord, bool, error)
	GetSourceUpload(context.Context, domain.ID) (domain.SourceUploadRecord, error)
}

func (h *G3SourceUploadHTTPHandler) Handle(writer http.ResponseWriter, request *http.Request) bool {
	if h == nil || h.Store == nil {
		return false
	}
	if request.URL.Path == apiPrefix+"source-uploads" {
		switch request.Method {
		case http.MethodPost:
			h.create(writer, request)
		default:
			writer.Header().Set("Allow", "POST, OPTIONS")
			writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		}
		return true
	}
	prefix := apiPrefix + "source-uploads/"
	if strings.HasPrefix(request.URL.Path, prefix) && strings.TrimPrefix(request.URL.Path, prefix) != "" && !strings.Contains(strings.TrimPrefix(request.URL.Path, prefix), "/") {
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", "GET, OPTIONS")
			writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return true
		}
		h.get(writer, request, domain.ID(strings.TrimPrefix(request.URL.Path, prefix)))
		return true
	}
	return false
}

func (h *G3SourceUploadHTTPHandler) create(writer http.ResponseWriter, request *http.Request) {
	if h.Manager == nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "source_upload_unavailable", "source upload storage is unavailable")
		return
	}
	key := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if key == "" {
		writeJSONError(writer, http.StatusUnprocessableEntity, "validation_failed", "Idempotency-Key is required")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" {
		writeJSONError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be multipart/form-data")
		return
	}
	reader, err := request.MultipartReader()
	if err != nil {
		writeJSONError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "multipart boundary is invalid")
		return
	}
	id, err := domain.NewID("upload")
	if err != nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "source_upload_unavailable", "source upload storage is unavailable")
		return
	}
	session, err := h.Manager.Begin(id)
	if err != nil {
		writeSourceUploadError(writer, err)
		return
	}
	defer session.Abort()
	limits := h.Manager.Limits()
	var mode string
	var manifest []domain.SourceUploadFile
	modeSeen, manifestSeen, archiveSeen := false, false, false
	for {
		part, partErr := reader.NextPart()
		if errors.Is(partErr, io.EOF) {
			break
		}
		if partErr != nil {
			writeSourceUploadError(writer, sourceupload.ErrInvalidUpload)
			return
		}
		name := part.FormName()
		switch name {
		case "mode":
			if modeSeen {
				_ = part.Close()
				writeSourceUploadError(writer, sourceupload.ErrInvalidUpload)
				return
			}
			modeSeen = true
			value, readErr := readSourceUploadText(part, 32)
			_ = part.Close()
			if readErr != nil {
				writeSourceUploadError(writer, readErr)
				return
			}
			mode = value
		case "manifest":
			if manifestSeen {
				_ = part.Close()
				writeSourceUploadError(writer, sourceupload.ErrInvalidUpload)
				return
			}
			manifestSeen = true
			payload, readErr := readSourceUploadBytes(part, limits.MaxManifest)
			_ = part.Close()
			if readErr != nil || decodeSourceUploadManifest(payload, &manifest) != nil {
				writeSourceUploadError(writer, sourceupload.ErrInvalidUpload)
				return
			}
		case "archive":
			filename, filenameErr := sourceUploadPartFilename(part)
			if archiveSeen || filenameErr != nil {
				_ = part.Close()
				writeSourceUploadError(writer, sourceupload.ErrInvalidUpload)
				return
			}
			archiveSeen = true
			err = session.WriteArchive(filename, part)
			_ = part.Close()
			if err != nil {
				writeSourceUploadError(writer, err)
				return
			}
		case "files":
			filename, filenameErr := sourceUploadPartFilename(part)
			if filenameErr != nil {
				_ = part.Close()
				writeSourceUploadError(writer, sourceupload.ErrInvalidUpload)
				return
			}
			err = session.WriteDirectoryFile(filename, part)
			_ = part.Close()
			if err != nil {
				writeSourceUploadError(writer, err)
				return
			}
		default:
			_ = part.Close()
			writeSourceUploadError(writer, sourceupload.ErrInvalidUpload)
			return
		}
	}
	var kind domain.SourceUploadKind
	switch mode {
	case string(domain.SourceUploadArchive):
		kind = domain.SourceUploadArchive
		if manifestSeen || !archiveSeen {
			writeSourceUploadError(writer, sourceupload.ErrInvalidUpload)
			return
		}
	case string(domain.SourceUploadDirectory):
		kind = domain.SourceUploadDirectory
		if !manifestSeen || archiveSeen {
			writeSourceUploadError(writer, sourceupload.ErrInvalidUpload)
			return
		}
	default:
		writeSourceUploadError(writer, sourceupload.ErrInvalidUpload)
		return
	}
	stored, err := session.Finalize(kind, manifest, key)
	if err != nil {
		writeSourceUploadError(writer, err)
		return
	}
	upload, replay, err := h.Store.CreateSourceUpload(request.Context(), stored.Upload)
	if err != nil {
		_ = h.Manager.Discard(stored.Upload.ID)
		if errors.Is(err, postgres.ErrIdempotencyConflict) {
			writeJSONError(writer, http.StatusConflict, "idempotency_conflict", "idempotency key was reused with different upload content")
			return
		}
		writeJSONError(writer, http.StatusServiceUnavailable, "source_upload_unavailable", "source upload persistence is unavailable")
		return
	}
	if replay {
		_ = h.Manager.Discard(stored.Upload.ID)
	}
	writeJSON(writer, http.StatusCreated, sourceUploadResponse(upload, h.now()))
}

func sourceUploadPartFilename(part *multipart.Part) (string, error) {
	_, parameters, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
	if err != nil || parameters["filename"] == "" {
		return "", sourceupload.ErrInvalidUpload
	}
	return parameters["filename"], nil
}

func (h *G3SourceUploadHTTPHandler) get(writer http.ResponseWriter, request *http.Request, id domain.ID) {
	upload, err := h.Store.GetSourceUpload(request.Context(), id)
	if errors.Is(err, postgres.ErrNotFound) {
		writeJSONError(writer, http.StatusNotFound, "not_found", "source upload not found")
		return
	}
	if err != nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "source_upload_unavailable", "source upload persistence is unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, sourceUploadResponse(upload, h.now()))
}

func (h *G3SourceUploadHTTPHandler) now() time.Time {
	if h.Clock != nil {
		return h.Clock().UTC()
	}
	return time.Now().UTC()
}

func sourceUploadResponse(upload domain.SourceUploadRecord, now time.Time) sourceUploadHTTPResponse {
	status := upload.Status
	if status == domain.SourceUploadReady && !now.Before(upload.ExpiresAt) {
		status = domain.SourceUploadExpired
	}
	return sourceUploadHTTPResponse{ID: upload.ID.String(), Kind: upload.Kind, Status: status, Digest: upload.Digest, Bytes: upload.Bytes, FileCount: upload.FileCount, ExpiresAt: upload.ExpiresAt}
}

func readSourceUploadText(reader io.Reader, limit int64) (string, error) {
	payload, err := readSourceUploadBytes(reader, limit)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(payload)), nil
}

func readSourceUploadBytes(reader io.Reader, limit int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, sourceupload.ErrStorage
	}
	if int64(len(payload)) > limit {
		return nil, sourceupload.ErrLimitExceeded
	}
	return payload, nil
}

func decodeSourceUploadManifest(payload []byte, target *[]domain.SourceUploadFile) error {
	var value struct {
		Files []domain.SourceUploadFile `json:"files"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF || len(value.Files) == 0 {
		return sourceupload.ErrInvalidUpload
	}
	*target = value.Files
	return nil
}

func writeSourceUploadError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sourceupload.ErrLimitExceeded):
		writeJSONError(writer, http.StatusRequestEntityTooLarge, "payload_too_large", "source upload exceeds configured limits")
	case errors.Is(err, sourceupload.ErrInvalidUpload), domain.IsCode(err, domain.ErrValidation):
		writeJSONError(writer, http.StatusUnprocessableEntity, "validation_failed", "source upload is invalid")
	default:
		writeJSONError(writer, http.StatusServiceUnavailable, "source_upload_unavailable", "source upload storage is unavailable")
	}
}

func newG3SourceUploadHTTPHandler(store *postgres.Store, getenv func(string) string) *G3SourceUploadHTTPHandler {
	handler := &G3SourceUploadHTTPHandler{Store: store}
	root := strings.TrimSpace(getenv("OPEN_CARD_SOURCE_UPLOAD_ROOT"))
	if root == "" {
		return handler
	}
	limits, ttl, err := sourceUploadConfigFromEnvironment(getenv)
	if err != nil {
		log.Printf("G3 source upload storage is unavailable: %v", err)
		return handler
	}
	manager, err := sourceupload.New(sourceupload.Config{Root: root, Limits: limits, TTL: ttl})
	if err != nil {
		log.Printf("G3 source upload storage is unavailable: %v", err)
		return handler
	}
	handler.Manager = manager
	return handler
}

func sourceUploadConfigFromEnvironment(getenv func(string) string) (sourceupload.Limits, time.Duration, error) {
	limits := sourceupload.DefaultLimits()
	values := []struct {
		name string
		set  func(int64)
	}{
		{"OPEN_CARD_SOURCE_UPLOAD_MAX_TOTAL_BYTES", func(value int64) { limits.MaxTotalBytes = value }},
		{"OPEN_CARD_SOURCE_UPLOAD_MAX_FILE_BYTES", func(value int64) { limits.MaxFileBytes = value }},
		{"OPEN_CARD_SOURCE_UPLOAD_MAX_FILES", func(value int64) { limits.MaxFiles = int(value) }},
		{"OPEN_CARD_SOURCE_UPLOAD_MAX_PATH_BYTES", func(value int64) { limits.MaxPathBytes = int(value) }},
		{"OPEN_CARD_SOURCE_UPLOAD_MAX_MANIFEST_BYTES", func(value int64) { limits.MaxManifest = value }},
	}
	for _, item := range values {
		if raw := strings.TrimSpace(getenv(item.name)); raw != "" {
			value, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || value <= 0 {
				return sourceupload.Limits{}, 0, errors.New("source upload limits are invalid")
			}
			item.set(value)
		}
	}
	if err := limits.Validate(); err != nil {
		return sourceupload.Limits{}, 0, err
	}
	ttl := 24 * time.Hour
	if raw := strings.TrimSpace(getenv("OPEN_CARD_SOURCE_UPLOAD_TTL")); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil || value <= 0 {
			return sourceupload.Limits{}, 0, errors.New("source upload TTL is invalid")
		}
		ttl = value
	}
	return limits, ttl, nil
}
