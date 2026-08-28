package postgres

import (
	"context"
	"fmt"
)

// CountEnabledWebhookEndpoints exposes only an aggregate. It intentionally
// never returns endpoint URLs, secret references, or delivery payloads.
func (s *Store) CountEnabledWebhookEndpoints(ctx context.Context) (int, error) {
	if err := s.requireDB(); err != nil {
		return 0, err
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM m4_webhook_endpoints WHERE enabled=true`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count enabled webhook endpoints: %w", err)
	}
	return count, nil
}
