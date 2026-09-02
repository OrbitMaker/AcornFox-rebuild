package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/open-card/open-card/internal/observability"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// m4ReconcileOrdinaryLogIndexes converges PostgreSQL metadata after LogStore
// rotation/retention. Audit indexes are excluded by the Store query and the
// retirement API, while every ordinary path must remain beneath the configured
// root. This runs after both build/runtime writes and at startup/read recovery.
func m4ReconcileOrdinaryLogIndexes(ctx context.Context, store *postgres.Store, logs *observability.LogStore, now time.Time) error {
	if store == nil || logs == nil {
		return errors.New("M4 ordinary log reconciliation requires store and LogStore")
	}
	indexes, err := store.ListActiveOrdinaryLogIndexes(ctx, 10000)
	if err != nil {
		return err
	}
	root := filepath.Clean(logs.RootDir())
	for _, index := range indexes {
		categoryRoot := filepath.Join(root, string(index.Category))
		if !acornFoxPathWithin(categoryRoot, index.Path) {
			return fmt.Errorf("ordinary log index is outside the configured LogStore root")
		}
		file, _, err := acornFoxOpenLogSegment(categoryRoot, index.Path)
		if err == nil {
			if closeErr := file.Close(); closeErr != nil {
				return closeErr
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := store.RetireOrdinaryLogIndex(ctx, index.ID, now); err != nil && !errors.Is(err, postgres.ErrNotFound) {
			return err
		}
	}
	return nil
}
