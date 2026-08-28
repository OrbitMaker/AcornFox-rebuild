package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
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
	Publishing    *ApplicationPublishSnapshot
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
type ApplicationPublishInput struct {
	SourceRevisionID domain.ID
	SourceKind       string
	Locator          string
	Ref              string
	ContentDigest    string
	EnvironmentID    domain.ID
	NextVersion      int
}
type ApplicationPublishSnapshot struct {
	OperationID domain.ID
	Status      string
	Sequence    int64
	LastEventID string
	Message     string
	EvidenceIDs []string
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
func (s *Store) LatestApplicationPublishInput(ctx context.Context, id domain.ID) (ApplicationPublishInput, error) {
	var out ApplicationPublishInput
	if err := s.requireDB(); err != nil {
		return out, err
	}
	if err := domain.RequireID(id, "application id"); err != nil {
		return out, err
	}
	err := s.db.QueryRowContext(ctx, `SELECT id,source_kind,locator,COALESCE(source_ref,''),content_digest FROM source_revisions WHERE application_id=$1 AND source_kind IS NOT NULL ORDER BY created_at DESC,id DESC LIMIT 1`, id.String()).Scan(&out.SourceRevisionID, &out.SourceKind, &out.Locator, &out.Ref, &out.ContentDigest)
	if err == sql.ErrNoRows {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if (out.SourceKind != "upload" && out.SourceKind != "git_https") || out.SourceRevisionID.Empty() || out.Locator == "" || out.ContentDigest == "" {
		return out, domain.ValidationError("latest publish source is invalid")
	}
	err = s.db.QueryRowContext(ctx, `SELECT id FROM environments WHERE application_id=$1 ORDER BY created_at,id LIMIT 1`, id.String()).Scan(&out.EnvironmentID)
	if err != nil {
		return out, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0)+1 FROM releases WHERE application_id=$1`, id.String()).Scan(&out.NextVersion)
	if err != nil {
		return out, err
	}
	if out.EnvironmentID.Empty() || out.NextVersion < 1 {
		return out, domain.ValidationError("latest publish input is invalid")
	}
	return out, nil
}
func (s *Store) LatestApplicationPublishSnapshot(ctx context.Context, id domain.ID) (*ApplicationPublishSnapshot, error) {
	var out ApplicationPublishSnapshot
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if err := domain.RequireID(id, "application id"); err != nil {
		return nil, err
	}
	var evidence []byte
	err := s.db.QueryRowContext(ctx, `SELECT aggregate_id,payload->>'status',stream_sequence,id,COALESCE(payload->>'message',''),COALESCE(payload->'evidence_ids','[]'::jsonb) FROM outbox_events WHERE event_type LIKE 'publish.%' AND payload->>'application_id'=$1 ORDER BY stream_sequence DESC LIMIT 1`, id.String()).Scan(&out.OperationID, &out.Status, &out.Sequence, &out.LastEventID, &out.Message, &evidence)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if out.OperationID.Empty() || out.LastEventID == "" || out.Sequence < 1 || (out.Status != "preparing" && out.Status != "building" && out.Status != "deploying" && out.Status != "succeeded" && out.Status != "failed") {
		return nil, domain.ValidationError("latest publish snapshot is invalid")
	}
	if err = json.Unmarshal(evidence, &out.EvidenceIDs); err != nil {
		return nil, err
	}
	for _, value := range out.EvidenceIDs {
		if value == "" {
			return nil, domain.ValidationError("latest publish evidence is invalid")
		}
	}
	return &out, nil
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
	snapshot, err := s.LatestApplicationPublishSnapshot(ctx, item.ID)
	if err != nil {
		return err
	}
	item.Publishing = snapshot
	if snapshot != nil {
		item.OperationID = &snapshot.OperationID
	}
	return nil
}
