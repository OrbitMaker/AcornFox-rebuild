package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/open-card/open-card/internal/domain"
)

// ListApplications returns durable applications in creation order. The
// secondary ID ordering keeps results deterministic when timestamps tie.
func (s *Store) ListApplications(ctx context.Context) ([]domain.Application, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, created_at, updated_at
		  FROM applications
		 ORDER BY created_at, id
	`)
	if err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	defer rows.Close()
	items := make([]domain.Application, 0)
	for rows.Next() {
		var item domain.Application
		if err := rows.Scan(&item.ID, &item.Name, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan application: %w", err)
		}
		item.CreatedAt = item.CreatedAt.UTC()
		item.UpdatedAt = item.UpdatedAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate applications: %w", err)
	}
	return items, nil
}

// GetApplication returns one durable application or application.ErrNotFound.
func (s *Store) GetApplication(ctx context.Context, id domain.ID) (domain.Application, error) {
	if err := s.requireDB(); err != nil {
		return domain.Application{}, err
	}
	if err := domain.RequireID(id, "application id"); err != nil {
		return domain.Application{}, err
	}
	var item domain.Application
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, created_at, updated_at
		  FROM applications
		 WHERE id = $1
	`, id.String()).Scan(&item.ID, &item.Name, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Application{}, ErrNotFound
	}
	if err != nil {
		return domain.Application{}, fmt.Errorf("get application %s: %w", id, err)
	}
	item.CreatedAt = item.CreatedAt.UTC()
	item.UpdatedAt = item.UpdatedAt.UTC()
	return item, nil
}
