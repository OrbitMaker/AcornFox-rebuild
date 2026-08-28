package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

type ApplicationProjection struct {
	ID            domain.ID
	Name          string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Source        ApplicationProjectionSource
	OperationID   *domain.ID
	RuntimeReady  bool
	Serving       bool
	RuntimeStatus string
}
type ApplicationProjectionSource struct {
	Kind          string
	UploadID      *domain.ID
	RepositoryURL *string
	Ref           *string
}

func (s *Store) ListApplicationProjections(ctx context.Context) ([]ApplicationProjection, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,created_at,updated_at FROM applications ORDER BY created_at,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ApplicationProjection{}
	for rows.Next() {
		var item ApplicationProjection
		if err := rows.Scan(&item.ID, &item.Name, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if err := s.fillApplicationProjection(ctx, &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
func (s *Store) ApplicationProjection(ctx context.Context, id domain.ID) (ApplicationProjection, error) {
	if err := s.requireDB(); err != nil {
		return ApplicationProjection{}, err
	}
	var item ApplicationProjection
	err := s.db.QueryRowContext(ctx, `SELECT id,name,created_at,updated_at FROM applications WHERE id=$1`, id.String()).Scan(&item.ID, &item.Name, &item.CreatedAt, &item.UpdatedAt)
	if err == sql.ErrNoRows {
		return ApplicationProjection{}, ErrNotFound
	}
	if err != nil {
		return ApplicationProjection{}, err
	}
	if err := s.fillApplicationProjection(ctx, &item); err != nil {
		return ApplicationProjection{}, err
	}
	return item, nil
}
func (s *Store) fillApplicationProjection(ctx context.Context, item *ApplicationProjection) error {
	item.Source = ApplicationProjectionSource{Kind: "unknown"}
	item.RuntimeStatus = "unknown"
	var sourceID, kind, locator, ref string
	err := s.db.QueryRowContext(ctx, `SELECT id,source_kind,locator,COALESCE(source_ref,'') FROM source_revisions WHERE application_id=$1 AND source_kind IS NOT NULL ORDER BY created_at DESC,id DESC LIMIT 1`, item.ID.String()).Scan(&sourceID, &kind, &locator, &ref)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == nil {
		switch kind {
		case "upload":
			var uploadID domain.ID
			var uploadKind string
			if err := s.db.QueryRowContext(ctx, `SELECT id,upload_kind FROM source_uploads WHERE claimed_source_revision_id=$1`, sourceID).Scan(&uploadID, &uploadKind); err == nil {
				item.Source.UploadID = &uploadID
				if uploadKind == "archive" {
					item.Source.Kind = "archive"
				} else if uploadKind == "directory" {
					item.Source.Kind = "folder"
				}
			}
		case "git_https":
			item.Source.Kind = "git"
			value := locator
			item.Source.RepositoryURL = &value
			if ref != "" {
				item.Source.Ref = &ref
			}
		}
	}
	var op domain.ID
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM operations WHERE application_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, item.ID.String()).Scan(&op); err == nil {
		item.OperationID = &op
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("latest application operation: %w", err)
	}
	return nil
}
