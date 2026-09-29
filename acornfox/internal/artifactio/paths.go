package artifactio

import (
	"fmt"
	"path/filepath"
	"strings"
)

type NestedWriterSession struct {
	TargetWriter *DurableWriter
	Writers      []*DurableWriter
	FileName     string
}

func OpenParentWriterForPath(packWriter *DurableWriter, relPathInPack string, allowCreate bool) (*NestedWriterSession, error) {
	clean := filepath.ToSlash(filepath.Clean(relPathInPack))
	dir := filepath.Dir(clean)
	base := filepath.Base(clean)
	if dir == "." || dir == "" {
		return &NestedWriterSession{
			TargetWriter: packWriter,
			FileName:     base,
		}, nil
	}

	parts := strings.Split(dir, "/")
	current := packWriter
	opened := make([]*DurableWriter, 0, len(parts))

	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			for i := len(opened) - 1; i >= 0; i-- {
				_ = opened[i].Close()
			}
			return nil, fmt.Errorf("invalid path component %q", part)
		}
		if allowCreate {
			if _, err := current.CreateChildDirectory(part, 0755); err != nil {
				for i := len(opened) - 1; i >= 0; i-- {
					_ = opened[i].Close()
				}
				return nil, fmt.Errorf("create child directory %q: %w", part, err)
			}
		}
		child, err := current.OpenChildWriter(part, 0755)
		if err != nil {
			for i := len(opened) - 1; i >= 0; i-- {
				_ = opened[i].Close()
			}
			return nil, fmt.Errorf("open child writer %q: %w", part, err)
		}
		opened = append(opened, child)
		current = child
	}

	return &NestedWriterSession{
		TargetWriter: current,
		Writers:      opened,
		FileName:     base,
	}, nil
}

func (n *NestedWriterSession) SyncAndClose() error {
	var firstErr error
	for i := len(n.Writers) - 1; i >= 0; i-- {
		if err := n.Writers[i].SyncRoot(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("sync nested directory: %w", err)
		}
		if err := n.Writers[i].Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close nested directory: %w", err)
		}
	}
	return firstErr
}
