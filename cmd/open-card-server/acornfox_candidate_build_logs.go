package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	"github.com/open-card/open-card/internal/observability"
)

const acornFoxCandidateBuildLogMaxBytes = 1 << 20

func prepareAcornFoxCandidateWorkRoot(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("candidate work root is invalid")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("candidate work root is unsafe")
	}
	return nil
}

func recoverAcornFoxCandidateBuildRoot(root string) error {
	if err := prepareAcornFoxCandidateWorkRoot(root); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "build-") || len(entry.Name()) == len("build-") || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("candidate build root contains an unknown entry")
		}
		path := filepath.Join(root, entry.Name())
		if err := filepath.WalkDir(path, func(item string, dirEntry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return errors.New("candidate build residue is unreadable")
			}
			info, err := os.Lstat(item)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("candidate build residue contains a link")
			}
			if info.IsDir() {
				return nil
			}
			if !info.Mode().IsRegular() {
				return errors.New("candidate build residue contains a special file")
			}
			if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
				return errors.New("candidate build residue contains a hardlink")
			}
			return nil
		}); err != nil {
			return err
		}
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	return nil
}

type acornFoxCandidateBuildLogSink struct {
	logs           *observability.LogStore
	redactionRoots []string
}

func (s *acornFoxCandidateBuildLogSink) StoreBuildLog(_ context.Context, request contracts.BuildRequest, content string) (string, error) {
	if s == nil || s.logs == nil || !acornFoxCandidateBuildLogRequest(request) {
		return "", errors.New("candidate build log request is invalid")
	}
	redactionValues := append([]string(nil), s.redactionRoots...)
	redactionValues = append(redactionValues, request.Source.Locator, request.Source.WorkspaceRef)
	content = foundation.NewRedactor(redactionValues...).RedactString(foundation.RedactText(content))
	if content == "" {
		content = "candidate build completed without captured output\n"
	}
	if len(content) > acornFoxCandidateBuildLogMaxBytes {
		return "", errors.New("candidate build log exceeds its bounded capture")
	}
	stream := "candidate-" + request.Source.ID.String()
	prior, err := s.logs.Read(observability.LogCategoryBuild, stream)
	if err != nil {
		return "", err
	}
	if len(prior) == 0 {
		if err := s.logs.Append(observability.LogCategoryBuild, stream, []byte(content)); err != nil {
			return "", err
		}
	} else if string(prior) != content {
		return "", errors.New("candidate build log replay changed content")
	}
	stored, err := s.logs.Read(observability.LogCategoryBuild, stream)
	if err != nil || string(stored) != content {
		return "", errors.New("candidate build log readback is inconsistent")
	}
	files, err := s.logs.List(observability.LogCategoryBuild, stream)
	if err != nil || len(files) == 0 {
		return "", errors.New("candidate build log has no durable segment")
	}
	for _, file := range files {
		if _, size, err := acornFoxLogSegmentDigest(filepath.Join(s.logs.RootDir(), string(observability.LogCategoryBuild)), file.Path); err != nil || size != file.Bytes {
			return "", errors.New("candidate build log segment integrity is unavailable")
		}
	}
	digest := sha256.Sum256(stored)
	return fmt.Sprintf("candidate-log://%s/%s", request.Source.ID, "sha256:"+hex.EncodeToString(digest[:])), nil
}

func acornFoxCandidateBuildLogRequest(request contracts.BuildRequest) bool {
	id := request.Source.ID.String()
	if request.Source.Validate() != nil || request.Plan.Validate() != nil || len(id) != len("candidate_")+32 || !strings.HasPrefix(id, "candidate_") {
		return false
	}
	for _, character := range id[len("candidate_"):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return request.Source.Kind == domain.SourceUpload && request.Source.Commit == "" && request.Source.Immutable && request.Source.Locator == "candidate://"+id && request.Plan.SourceRevisionID == request.Source.ID && request.Plan.SourceDigest == request.Source.ContentDigest && request.Plan.Kind == domain.BuildDockerfile && request.Plan.ServiceName == "web" && !request.BuildID.Empty()
}
