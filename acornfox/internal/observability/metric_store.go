package observability

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MetricStore is the narrow persistence contract for raw observations and
// time-bucket queries. It deliberately exposes database/sql-compatible
// behavior without importing or registering a PostgreSQL driver.
type MetricStore interface {
	InsertSamples(context.Context, []Sample) error
	Query(context.Context, Query) ([]Aggregate, error)
}

// SQLMetricStore persists raw samples in metric_samples and derives bucketed
// results in Go. The database schema also provides usage_aggregates for a
// controller that chooses to materialize buckets asynchronously.
type SQLMetricStore struct {
	db *sql.DB
}

var _ MetricStore = (*SQLMetricStore)(nil)

// NewMetricStore wraps a database/sql handle. The caller owns db.
func NewMetricStore(db *sql.DB) *SQLMetricStore { return &SQLMetricStore{db: db} }

// NewSQLMetricStore is an explicit constructor alias.
func NewSQLMetricStore(db *sql.DB) *SQLMetricStore { return NewMetricStore(db) }

// NewMetricRepository is a repository-named constructor alias.
func NewMetricRepository(db *sql.DB) *SQLMetricStore { return NewMetricStore(db) }

func (s *SQLMetricStore) requireDB() error {
	if s == nil || s.db == nil {
		return errors.New("observability metric store is not initialized")
	}
	return nil
}

// DB exposes the caller-owned database handle for health and migration code.
func (s *SQLMetricStore) DB() *sql.DB {
	if s == nil {
		return nil
	}
	return s.db
}

// InsertSamples validates and idempotently writes a batch. Repeated identical
// samples are no-ops; reuse of the same producer identity with a different
// fingerprint is rejected. A transaction keeps a batch all-or-nothing.
func (s *SQLMetricStore) InsertSamples(ctx context.Context, samples []Sample) error {
	if err := s.requireDB(); err != nil {
		return err
	}
	unique, err := DeduplicateSamples(samples)
	if err != nil {
		return err
	}
	if len(unique) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin metric insert: %w", err)
	}
	rollback := func(cause error) error {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			return fmt.Errorf("%w (rollback: %v)", cause, rollbackErr)
		}
		return cause
	}
	const insert = `
		INSERT INTO metric_samples
			(observed_at, sample_identity, sample_fingerprint, sample_id,
			 application_id, service_name, release_id, cpu, cpu_seconds,
			 memory_bytes, disk_bytes, network_rx_bytes, network_tx_bytes,
			 restart_count, exception_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (observed_at, sample_identity) DO NOTHING
	`
	for _, sample := range unique {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "open-card-metric-sample:"+sample.Identity()); err != nil {
			return rollback(fmt.Errorf("serialize metric sample %s: %w", sample.Identity(), err))
		}
		if producerID := strings.TrimSpace(sample.ID); producerID != "" {
			var existingAt time.Time
			var existingFingerprint string
			err := tx.QueryRowContext(ctx, `
				SELECT observed_at, sample_fingerprint
				  FROM metric_samples
				 WHERE sample_id = $1
				 ORDER BY observed_at
				 LIMIT 1
			`, producerID).Scan(&existingAt, &existingFingerprint)
			if err == nil {
				if !existingAt.Equal(sample.At.UTC()) || existingFingerprint != sample.ContentIdentity() {
					return rollback(fmt.Errorf("%w: producer id %s", ErrSampleConflict, producerID))
				}
				continue
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return rollback(fmt.Errorf("check metric sample %s: %w", producerID, err))
			}
		}
		_, err := tx.ExecContext(ctx, insert,
			sample.At.UTC(), sample.Identity(), sample.ContentIdentity(), strings.TrimSpace(sample.ID),
			strings.TrimSpace(sample.ApplicationID), strings.TrimSpace(sample.ServiceName), strings.TrimSpace(sample.ReleaseID),
			sample.CPU, sample.CPUSeconds, sample.MemoryBytes, sample.DiskBytes,
			sample.NetworkRxBytes, sample.NetworkTxBytes, sample.RestartCount, sample.ExceptionCount,
		)
		if err != nil {
			return rollback(fmt.Errorf("insert metric sample %s: %w", sample.Identity(), err))
		}
		// The immutable table rejects UPDATE. Read back the existing fingerprint
		// after ON CONFLICT DO NOTHING so equal retries are harmless and changed
		// retries fail closed without violating append-only storage.
		var storedFingerprint string
		if err := tx.QueryRowContext(ctx, `
			SELECT sample_fingerprint
			  FROM metric_samples
			 WHERE observed_at = $1 AND sample_identity = $2
		`, sample.At.UTC(), sample.Identity()).Scan(&storedFingerprint); err != nil {
			return rollback(fmt.Errorf("verify metric sample %s: %w", sample.Identity(), err))
		}
		if storedFingerprint != sample.ContentIdentity() {
			return rollback(fmt.Errorf("%w: %s", ErrSampleConflict, sample.Identity()))
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit metric insert: %w", err)
	}
	return nil
}

// Ingest is the MeterProvider-shaped alias for InsertSamples.
func (s *SQLMetricStore) Ingest(ctx context.Context, samples []Sample) error {
	return s.InsertSamples(ctx, samples)
}

// Insert is a compact alias for InsertSamples.
func (s *SQLMetricStore) Insert(ctx context.Context, samples []Sample) error {
	return s.InsertSamples(ctx, samples)
}

// Query loads raw observations in the half-open window [From, To) and returns
// deterministic bucket aggregates. Query predicates remain parameterized and
// use the indexes declared by 0005_observability.sql.
func (s *SQLMetricStore) Query(ctx context.Context, query Query) ([]Aggregate, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if err := query.Validate(); err != nil {
		return nil, err
	}
	args := []any{strings.TrimSpace(query.ApplicationID), query.From.UTC(), query.To.UTC()}
	where := []string{"application_id = $1", "observed_at >= $2", "observed_at < $3"}
	if service := strings.TrimSpace(query.ServiceName); service != "" {
		args = append(args, service)
		where = append(where, fmt.Sprintf("service_name = $%d", len(args)))
	}
	if release := strings.TrimSpace(query.ReleaseID); release != "" {
		args = append(args, release)
		where = append(where, fmt.Sprintf("release_id = $%d", len(args)))
	}
	statement := `
		SELECT sample_id, application_id, service_name, release_id, observed_at,
		       cpu, cpu_seconds, memory_bytes, disk_bytes, network_rx_bytes,
		       network_tx_bytes, restart_count, exception_count
		  FROM metric_samples
		 WHERE ` + strings.Join(where, " AND ") + `
		 ORDER BY observed_at, sample_identity`
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("query metric samples: %w", err)
	}
	defer rows.Close()
	samples := make([]Sample, 0)
	for rows.Next() {
		var sample Sample
		if err := rows.Scan(
			&sample.ID, &sample.ApplicationID, &sample.ServiceName, &sample.ReleaseID, &sample.At,
			&sample.CPU, &sample.CPUSeconds, &sample.MemoryBytes, &sample.DiskBytes,
			&sample.NetworkRxBytes, &sample.NetworkTxBytes, &sample.RestartCount, &sample.ExceptionCount,
		); err != nil {
			return nil, fmt.Errorf("scan metric sample: %w", err)
		}
		samples = append(samples, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate metric samples: %w", err)
	}
	if len(samples) == 0 {
		return []Aggregate{}, nil
	}
	return AggregateBuckets(samples, query.BucketWidth())
}

// QueryBuckets reads already materialized five-minute (or custom-width)
// buckets. It is useful for a writer/compactor that fills usage_aggregates;
// callers can use Query when raw data is authoritative.
func (s *SQLMetricStore) QueryBuckets(ctx context.Context, query Query) ([]Aggregate, error) {
	if err := s.requireDB(); err != nil {
		return nil, err
	}
	if err := query.Validate(); err != nil {
		return nil, err
	}
	args := []any{strings.TrimSpace(query.ApplicationID), query.From.UTC(), query.To.UTC()}
	where := []string{"application_id = $1", "window_start >= $2", "window_start < $3"}
	if service := strings.TrimSpace(query.ServiceName); service != "" {
		args = append(args, service)
		where = append(where, fmt.Sprintf("service_name = $%d", len(args)))
	}
	if release := strings.TrimSpace(query.ReleaseID); release != "" {
		args = append(args, release)
		where = append(where, fmt.Sprintf("release_id = $%d", len(args)))
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT application_id, service_name, release_id, window_start, window_end,
		       sample_count, average_cpu, peak_cpu, trend_cpu, cpu_seconds,
		       average_memory_bytes, peak_memory_bytes, trend_memory_bytes,
		       memory_byte_seconds, average_disk_bytes, peak_disk_bytes,
		       trend_disk_bytes, network_rx_bytes, network_tx_bytes,
		       restart_count, exception_count
		  FROM usage_aggregates
		 WHERE `+strings.Join(where, " AND ")+`
		 ORDER BY application_id, service_name, release_id, window_start`, args...)
	if err != nil {
		return nil, fmt.Errorf("query metric buckets: %w", err)
	}
	defer rows.Close()
	result := make([]Aggregate, 0)
	for rows.Next() {
		var aggregate Aggregate
		if err := rows.Scan(
			&aggregate.ApplicationID, &aggregate.ServiceName, &aggregate.ReleaseID,
			&aggregate.WindowStart, &aggregate.WindowEnd, &aggregate.SampleCount,
			&aggregate.AverageCPU, &aggregate.PeakCPU, &aggregate.TrendCPU, &aggregate.CPUSeconds,
			&aggregate.AverageMemory, &aggregate.PeakMemory, &aggregate.TrendMemory,
			&aggregate.MemoryByteSecs, &aggregate.AverageDisk, &aggregate.PeakDisk,
			&aggregate.TrendDisk, &aggregate.NetworkRx, &aggregate.NetworkTx,
			&aggregate.RestartCount, &aggregate.ExceptionCount,
		); err != nil {
			return nil, fmt.Errorf("scan metric bucket: %w", err)
		}
		aggregate.BucketStart = aggregate.WindowStart
		aggregate.BucketEnd = aggregate.WindowEnd
		aggregate.syncAliases()
		result = append(result, aggregate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate metric buckets: %w", err)
	}
	return result, nil
}

// QueryAggregates is a compatibility alias for QueryBuckets.
func (s *SQLMetricStore) QueryAggregates(ctx context.Context, query Query) ([]Aggregate, error) {
	return s.QueryBuckets(ctx, query)
}

// RetentionCutoff computes the timestamp before which raw observations are
// eligible for partition/drop cleanup. Deleting rows is intentionally not
// performed here; partition lifecycle belongs to migration/operations code.
func RetentionCutoff(now time.Time, retention time.Duration) time.Time {
	if retention <= 0 {
		retention = DefaultMetricRetention
	}
	return now.UTC().Add(-retention)
}
