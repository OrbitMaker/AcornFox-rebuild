package sourcebuildexecution

import (
	"errors"
	"os"
	"path/filepath"
)

type ProductionConfig struct {
	UploadRoot, WorkspaceRoot, WorkRoot, ImageStoreRoot, LogRoot string
	GitResolverEndpoints                                         []string
	Authority                                                    SourceBuildAuthority
}

func ValidateProductionConfig(c ProductionConfig) error {
	if c.Authority == nil || len(c.GitResolverEndpoints) == 0 {
		return errors.New("source-build requires Core authority and explicit public Git resolvers")
	}
	paths := []string{c.UploadRoot, c.WorkspaceRoot, c.WorkRoot, c.ImageStoreRoot, c.LogRoot}
	for i, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("source-build roots must be explicit absolute canonical directories")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return errors.New("source-build roots must be provisioned private directories")
		}
		for _, other := range paths[:i] {
			if path == other {
				return errors.New("source-build roots must be distinct")
			}
		}
	}
	return nil
}
