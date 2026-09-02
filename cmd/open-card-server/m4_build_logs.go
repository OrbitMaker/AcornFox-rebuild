package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	"github.com/open-card/open-card/internal/observability"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type m4BuildLogSink struct {
	store          *postgres.Store
	logs           *observability.LogStore
	redactionRoots []string
	clock          func() time.Time
}

func (s *m4BuildLogSink) StoreBuildLog(ctx context.Context, request contracts.BuildRequest, content string) (string, error) {
	if s == nil || s.store == nil || s.logs == nil {
		return "", fmt.Errorf("M4 build log sink is unavailable")
	}
	now := s.now()
	baseStream := "build-" + request.BuildID.String()
	// A BuildID names one immutable successful build. Do not append a second
	// payload to an already indexed stream: that would change a previously
	// indexed file's byte size and make replay/readback ambiguous.
	var existingPath string
	err := s.store.DB().QueryRowContext(ctx, `SELECT path FROM m4_log_indexes WHERE build_id=$1 AND category='build' AND retired_at IS NULL ORDER BY segment DESC,id DESC LIMIT 1`, request.BuildID.String()).Scan(&existingPath)
	if err == nil {
		if err := m4ReconcileOrdinaryLogIndexes(ctx, s.store, s.logs, now); err != nil {
			return "", err
		}
		if m4BuildLogPathAvailable(s.logs, existingPath) {
			return existingPath, nil
		}
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	stream, files, err := s.buildLogStream(ctx, request.BuildID, baseStream)
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		content = s.redactBuildLog(request, content)
		if err := s.logs.Append(observability.LogCategoryBuild, stream, []byte(content)); err != nil {
			return "", err
		}
		files, err = s.logs.List(observability.LogCategoryBuild, stream)
		if err != nil {
			return "", err
		}
	}
	if len(files) == 0 {
		return "", fmt.Errorf("M4 build log sink did not persist a segment")
	}
	for _, file := range files {
		contentDigest, size, err := acornFoxLogSegmentDigest(filepath.Join(s.logs.RootDir(), string(observability.LogCategoryBuild)), file.Path)
		if err != nil || size != file.Bytes {
			return "", fmt.Errorf("build log segment integrity is unavailable")
		}
		indexID := m4BuildLogIndexID(stream, file)
		var exists bool
		if err := s.store.DB().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM m4_log_indexes WHERE id=$1)`, indexID.String()).Scan(&exists); err != nil {
			return "", err
		}
		if exists {
			continue
		}
		// BuildKit captures a bounded buffer but does not reveal whether that
		// buffer reached source EOF. Conservatively preserve a source-limited
		// warning rather than ever publishing this producer as complete.
		if err := s.store.AppendLogIndex(ctx, postgres.LogIndex{ID: indexID, ApplicationID: request.Source.ApplicationID, ServiceName: request.Plan.ServiceName, BuildID: request.BuildID, Category: postgres.LogIndexBuild, LogStream: postgres.LogStreamCombined, Truncation: postgres.LogTruncationSourceLimited, Path: file.Path, Segment: file.Sequence, ByteSize: file.Bytes, ContentDigest: contentDigest, CreatedAt: now}, now); err != nil {
			return "", err
		}
	}
	if err := m4ReconcileOrdinaryLogIndexes(ctx, s.store, s.logs, now); err != nil {
		return "", err
	}
	return files[len(files)-1].Path, nil
}

func (s *m4BuildLogSink) redactBuildLog(request contracts.BuildRequest, content string) string {
	values := append([]string(nil), s.redactionRoots...)
	values = append(values, request.Source.Locator, request.Source.WorkspaceRef)
	return foundation.NewRedactor(values...).RedactString(foundation.RedactText(content))
}

func (s *m4BuildLogSink) now() time.Time {
	if s != nil && s.clock != nil {
		return s.clock().UTC()
	}
	return time.Now().UTC()
}

// buildLogStream keeps the first immutable build stream for normal replay.
// Once every base segment is retired, recovery gets a new deterministic
// stream generation so the permanent (category,path,segment) ledger key is
// never reused. A crash after the recovery file write sees that same empty
// generation and indexes it instead of appending again.
func (s *m4BuildLogSink) buildLogStream(ctx context.Context, buildID domain.ID, baseStream string) (string, []observability.LogFile, error) {
	files, err := s.logs.List(observability.LogCategoryBuild, baseStream)
	if err != nil || len(files) > 0 {
		return baseStream, files, err
	}
	stream, err := s.nextBuildLogRecoveryStream(ctx, buildID, baseStream)
	if err != nil {
		return "", nil, err
	}
	files, err = s.logs.List(observability.LogCategoryBuild, stream)
	return stream, files, err
}

func (s *m4BuildLogSink) nextBuildLogRecoveryStream(ctx context.Context, buildID domain.ID, baseStream string) (string, error) {
	rows, err := s.store.DB().QueryContext(ctx, `SELECT path FROM m4_log_indexes WHERE build_id=$1 AND category='build' AND retired_at IS NOT NULL`, buildID.String())
	if err != nil {
		return "", err
	}
	defer rows.Close()
	retiredPaths := make([]string, 0)
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			return "", err
		}
		retiredPaths = append(retiredPaths, path)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(retiredPaths) == 0 {
		return baseStream, nil
	}
	for generation := 1; generation <= len(retiredPaths)+1; generation++ {
		stream := fmt.Sprintf("%s-recovery-%d", baseStream, generation)
		streamPath, err := s.logs.Path(observability.LogCategoryBuild, stream)
		if err != nil {
			return "", err
		}
		if !m4BuildLogStreamRetired(streamPath, retiredPaths) {
			return stream, nil
		}
	}
	return "", errors.New("M4 build log recovery generation is unavailable")
}

func m4BuildLogStreamRetired(streamPath string, retiredPaths []string) bool {
	for _, retiredPath := range retiredPaths {
		relative, err := filepath.Rel(streamPath, filepath.Clean(retiredPath))
		if err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func m4BuildLogPathAvailable(logs *observability.LogStore, path string) bool {
	if logs == nil {
		return false
	}
	file, _, err := acornFoxOpenLogSegment(filepath.Join(logs.RootDir(), string(observability.LogCategoryBuild)), path)
	if err != nil {
		return false
	}
	return file.Close() == nil
}

// Stream generations are immutable after an index exists, so sequence is a
// stable compact identity within that stream.
func m4BuildLogIndexID(stream string, file observability.LogFile) domain.ID {
	return m4AdapterID("log", stream+fmt.Sprint(file.Sequence))
}
