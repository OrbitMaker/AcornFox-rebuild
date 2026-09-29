package sourcebuildexecution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/foundation"
	"github.com/acornfox/acornfox/internal/observability"
)

// FileBuildLogSink stores the provider's bounded source-limited capture. It
// neither claims a complete BuildKit stream nor writes Core's SQLite database.
type FileBuildLogSink struct {
	mu    sync.Mutex
	logs  *observability.LogStore
	roots []string
}

func NewFileBuildLogSink(root string, redactionRoots []string) (*FileBuildLogSink, error) {
	logs, err := observability.NewLogStore(observability.LogStoreConfig{RootDir: root, MaxFileBytes: 2 << 20, MaxTotalBytes: 64 << 20, MaxBuildFiles: 128, MaxFilesPerStream: 1})
	if err != nil {
		return nil, err
	}
	return &FileBuildLogSink{logs: logs, roots: append([]string(nil), redactionRoots...)}, nil
}
func (s *FileBuildLogSink) StoreBuildLog(ctx context.Context, r contracts.BuildRequest, content string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if r.BuildID.Empty() || len(content) > 1<<20 {
		return "", errors.New("build log identity or size is invalid")
	}
	values := append(append([]string(nil), s.roots...), r.Source.Locator, r.Source.WorkspaceRef)
	data := []byte(foundation.NewRedactor(values...).RedactString(foundation.RedactText(content)))
	if len(data) == 0 {
		data = []byte("BuildKit emitted no log text; capture completeness is unconfirmed.\n")
	}
	stream := "build-" + r.BuildID.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.logs.List(observability.LogCategoryBuild, stream)
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		if err := s.logs.Append(observability.LogCategoryBuild, stream, data); err != nil {
			return "", err
		}
	}
	files, err = s.logs.List(observability.LogCategoryBuild, stream)
	if err != nil || len(files) != 1 {
		return "", errors.New("bounded log segment unavailable")
	}
	for _, segment := range files {
		file, err := os.Open(segment.Path)
		if err != nil {
			return "", err
		}
		if err := file.Chmod(0400); err != nil {
			file.Close()
			return "", err
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if syncErr != nil {
			return "", syncErr
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	for _, dir := range []string{filepath.Dir(files[0].Path), filepath.Join(s.logs.RootDir(), string(observability.LogCategoryBuild)), s.logs.RootDir()} {
		f, err := os.Open(dir)
		if err != nil {
			return "", err
		}
		syncErr := f.Sync()
		closeErr := f.Close()
		if syncErr != nil {
			return "", syncErr
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	actual, err := s.logs.Read(observability.LogCategoryBuild, stream)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(data, actual) {
		return "", errors.New("immutable build log replay disagrees")
	}
	sum := sha256.Sum256(actual)
	return fmt.Sprintf("buildlog:%s:sha256:%s:%d:source-limited", r.BuildID, hex.EncodeToString(sum[:]), len(actual)), nil
}
