// Package local implements the replaceable MeterProvider contract using only
// the control-plane PostgreSQL database and M4 runtime observations.
package local

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/usage"
	"strings"
	"time"
)

type Provider struct {
	db     *sql.DB
	bucket time.Duration
}

// DetailQuery is the operator-read model. It is application-scoped and uses a
// UTC half-open interval [From, To); no billing or AI fields exist here.
type DetailQuery struct {
	ApplicationID domain.ID
	ServiceName   string
	ReleaseID     domain.ID
	From, To      time.Time
}
type LimitSnapshot struct{ CPUMillicores, MemoryBytes, DiskBytes, PIDs int64 }
type AnomalyRef struct {
	ID, Kind, SourceID string
	ObservedAt         time.Time
}
type UsageBucket struct {
	ApplicationID, EnvironmentID, DeploymentID, ReleaseID, ServiceName string
	WindowStart, WindowEnd                                             time.Time
	SampleCount                                                        int
	CPUSeconds, MemoryByteSeconds, DiskByteSeconds                     float64
	AverageCPUMillicores, AverageMemoryBytes, AverageDiskBytes         float64
	NetworkRxBytes, NetworkTxBytes, RestartCount, ExceptionCount       int64
	PeakCPUMillicores, PeakMemoryBytes, PeakDiskBytes                  int64
	// Trends are unit-per-second slopes between first and last raw fact.
	CPUTrendMillicoresPerSecond, MemoryTrendBytesPerSecond, DiskTrendBytesPerSecond float64
	RuntimeSeconds                                                                  float64
	Limits                                                                          LimitSnapshot
	Anomalies                                                                       []AnomalyRef
}
type UsageView struct {
	ApplicationID domain.ID
	From, To      time.Time
	Buckets       []UsageBucket
}

var _ contracts.MeterProvider = (*Provider)(nil)

func New(db *sql.DB) *Provider { return &Provider{db: db, bucket: usage.DefaultBucketWidth} }
func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "local-meter", Version: "m5", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilityMeter)}
}
func (p *Provider) check() error {
	if p == nil || p.db == nil {
		return errors.New("local meter is not initialized")
	}
	return nil
}
func providerErr(code contracts.ErrorCode, msg string, cause error) *contracts.ProviderError {
	return &contracts.ProviderError{Provider: "local-meter", Code: code, Message: msg, Cause: cause, Retry: contracts.RetryNever}
}

func (p *Provider) Ingest(ctx context.Context, samples []contracts.MeterSample, op contracts.OperationContext) error {
	if err := p.check(); err != nil {
		return err
	}
	if len(samples) == 0 {
		return nil
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin usage ingest: %w", err)
	}
	defer tx.Rollback()
	if err := p.requireStorage(ctx, tx); err != nil {
		return providerErr(contracts.ErrCapacity, "local usage storage is unavailable", err)
	}
	for _, s := range samples {
		if strings.TrimSpace(s.ID) == "" || s.ApplicationID.Empty() || strings.TrimSpace(s.ServiceName) == "" || s.At.IsZero() || s.CPUMillicores < 0 || s.CPUSeconds < 0 || s.MemoryBytes < 0 || s.DiskBytes < 0 || s.RuntimeSeconds < 0 || s.LimitCPUMillicores < 0 || s.LimitMemoryBytes < 0 || s.LimitDiskBytes < 0 || s.LimitPIDs < 0 {
			return providerErr(contracts.ErrInvalidArgument, "meter sample has invalid units or identity", usage.ErrInvalidFact)
		}
		source := "meter:" + s.ID
		fp := fingerprint(s)
		memoryByteSeconds := float64(s.MemoryBytes)
		if s.RuntimeSeconds > 0 {
			memoryByteSeconds *= s.RuntimeSeconds
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO m5_usage_raw_facts(source_id,source_fingerprint,application_id,environment_id,deployment_id,release_id,service_name,observed_at,cpu_seconds,memory_byte_seconds,runtime_seconds,cpu_millicores,memory_bytes,disk_bytes,network_rx_bytes,network_tx_bytes,restart_count,exception_count,limit_cpu_millicores,limit_memory_bytes,limit_disk_bytes,limit_pids) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22) ON CONFLICT(source_id) DO NOTHING`, source, fp, s.ApplicationID.String(), s.EnvironmentID.String(), s.DeploymentID.String(), s.ReleaseID.String(), s.ServiceName, s.At.UTC(), s.CPUSeconds, memoryByteSeconds, s.RuntimeSeconds, s.CPUMillicores, s.MemoryBytes, s.DiskBytes, s.NetworkRxBytes, s.NetworkTxBytes, s.RestartCount, s.ExceptionCount, s.LimitCPUMillicores, s.LimitMemoryBytes, s.LimitDiskBytes, s.LimitPIDs)
		if err != nil {
			return fmt.Errorf("insert usage fact: %w", err)
		}
		var stored string
		if err = tx.QueryRowContext(ctx, `SELECT source_fingerprint FROM m5_usage_raw_facts WHERE source_id=$1`, source).Scan(&stored); err != nil {
			return err
		}
		if stored != fp {
			return providerErr(contracts.ErrConflict, "meter sample id was reused with different facts", usage.ErrConflict)
		}
	}
	return tx.Commit()
}
func fingerprint(s contracts.MeterSample) string {
	v := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d\x00%.17g\x00%d\x00%d\x00%d\x00%d\x00%.17g\x00%d\x00%d\x00%d\x00%d\x00%d\x00%d", s.ID, s.ApplicationID, s.EnvironmentID, s.DeploymentID, s.ServiceName, s.ReleaseID, s.At.UTC().Format(time.RFC3339Nano), s.CPUMillicores, s.CPUSeconds, s.MemoryBytes, s.DiskBytes, s.NetworkRxBytes, s.NetworkTxBytes, s.RuntimeSeconds, s.RestartCount, s.ExceptionCount, s.LimitCPUMillicores, s.LimitMemoryBytes, s.LimitDiskBytes, s.LimitPIDs)
	d := sha256.Sum256([]byte(v))
	return "sha256:" + hex.EncodeToString(d[:])
}
func (p *Provider) requireStorage(ctx context.Context, tx *sql.Tx) error {
	var s usage.StorageState
	err := tx.QueryRowContext(ctx, `SELECT total_bytes,used_bytes,hard_watermark_bytes FROM m5_usage_storage_state WHERE singleton`).Scan(&s.TotalBytes, &s.UsedBytes, &s.HardWatermarkBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.AllowsWrite()
}

// ProjectM4 copies immutable M4 runtime facts into the M5 raw ledger. It is
// safe to rerun after process restart and preserves configured limits apart
// from actual measurements. It never crosses the requested application.
func (p *Provider) ProjectM4(ctx context.Context, applicationID domain.ID, from, to time.Time) error {
	if err := p.check(); err != nil {
		return err
	}
	if applicationID.Empty() || from.IsZero() || to.IsZero() || !from.Before(to) {
		return usage.ErrInvalidFact
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := p.requireStorage(ctx, tx); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT o.sample_id,o.application_id,o.environment_id,o.deployment_id,o.release_id,o.service_name,o.observed_at,o.cpu_millicores,o.memory_bytes,o.disk_bytes,o.network_rx_bytes,o.network_tx_bytes,o.restart_count,o.applied_cpu_millicores,o.applied_memory_bytes,o.applied_pids,CASE WHEN o.healthy THEN 0 ELSE 1 END,GREATEST(EXTRACT(EPOCH FROM (o.observed_at-d.created_at)),0) FROM m4_service_observations o JOIN deployments d ON d.id=o.deployment_id WHERE o.application_id=$1 AND o.observed_at >= $2 AND o.observed_at < $3 ORDER BY o.observed_at,o.id`, applicationID.String(), from.UTC(), to.UTC())
	if err != nil {
		return err
	}
	defer rows.Close()
	facts := []usage.Fact{}
	for rows.Next() {
		var f usage.Fact
		if err := rows.Scan(&f.SourceID, &f.ApplicationID, &f.EnvironmentID, &f.DeploymentID, &f.ReleaseID, &f.ServiceName, &f.ObservedAt, &f.CPUMillicores, &f.MemoryBytes, &f.DiskBytes, &f.NetworkRxBytes, &f.NetworkTxBytes, &f.RestartCount, &f.LimitCPUMillicores, &f.LimitMemoryBytes, &f.LimitPIDs, &f.ExceptionCount, &f.RuntimeSeconds); err != nil {
			return err
		}
		f.SourceID = "m4:" + f.SourceID
		if err := f.Validate(); err != nil {
			rows.Close()
			return err
		}
		facts = append(facts, f)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, f := range facts {
		fp := factFingerprint(f)
		_, err = tx.ExecContext(ctx, `INSERT INTO m5_usage_raw_facts(source_id,source_fingerprint,application_id,environment_id,deployment_id,release_id,service_name,observed_at,runtime_seconds,cpu_millicores,memory_bytes,disk_bytes,network_rx_bytes,network_tx_bytes,restart_count,exception_count,limit_cpu_millicores,limit_memory_bytes,limit_pids) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) ON CONFLICT(source_id) DO NOTHING`, f.SourceID, fp, f.ApplicationID, f.EnvironmentID, f.DeploymentID, f.ReleaseID, f.ServiceName, f.ObservedAt.UTC(), f.RuntimeSeconds, f.CPUMillicores, f.MemoryBytes, f.DiskBytes, f.NetworkRxBytes, f.NetworkTxBytes, f.RestartCount, f.ExceptionCount, f.LimitCPUMillicores, f.LimitMemoryBytes, f.LimitPIDs)
		if err != nil {
			return err
		}
		if f.ExceptionCount > 0 {
			_, err = tx.ExecContext(ctx, `INSERT INTO m5_usage_anomalies(id,source_id,application_id,kind,observed_at) VALUES($1,$2,$3,'runtime_unhealthy',$4) ON CONFLICT(source_id,kind) DO NOTHING`, digest("anomaly:"+f.SourceID), f.SourceID, f.ApplicationID, f.ObservedAt.UTC())
			if err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
func digest(v string) string {
	d := sha256.Sum256([]byte(v))
	return "m5_" + hex.EncodeToString(d[:16])
}
func factFingerprint(f usage.Fact) string { return digest(fmt.Sprintf("%+v", f)) }

// Query reads materialized current buckets; callers explicitly Compact after
// ingestion/projection, which keeps query paths read-only and restart-safe.
func (p *Provider) Query(ctx context.Context, q contracts.MeterQuery) ([]domain.UsageAggregate, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	if q.ApplicationID.Empty() || q.From.IsZero() || q.To.IsZero() || !q.From.Before(q.To) {
		return nil, providerErr(contracts.ErrInvalidArgument, "meter query application and window are required", usage.ErrInvalidFact)
	}
	args := []any{q.ApplicationID.String(), q.From.UTC(), q.To.UTC()}
	where := []string{"application_id=$1", "window_start >= $2", "window_start < $3"}
	if q.ServiceName != "" {
		args = append(args, q.ServiceName)
		where = append(where, fmt.Sprintf("service_name=$%d", len(args)))
	}
	if !q.ReleaseID.Empty() {
		args = append(args, q.ReleaseID.String())
		where = append(where, fmt.Sprintf("release_id=$%d", len(args)))
	}
	rows, err := p.db.QueryContext(ctx, `SELECT application_id,environment_id,deployment_id,service_name,release_id,window_start,max(window_end),sum(sample_count),sum(cpu_seconds),sum(memory_byte_seconds),sum(disk_byte_seconds),sum(runtime_seconds),max(average_cpu_millicores),max(average_memory_bytes),max(average_disk_bytes),max(trend_cpu_millicores_per_second),max(trend_memory_bytes_per_second),max(trend_disk_bytes_per_second),sum(network_rx_bytes),sum(network_tx_bytes),sum(restart_count),sum(exception_count),max(peak_cpu_millicores),max(peak_memory_bytes),max(peak_disk_bytes),max(limit_cpu_millicores),max(limit_memory_bytes),max(limit_disk_bytes),max(limit_pids) FROM m5_usage_bucket_current WHERE `+strings.Join(where, " AND ")+` GROUP BY application_id,environment_id,deployment_id,service_name,release_id,window_start ORDER BY service_name,release_id,window_start`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.UsageAggregate{}
	for rows.Next() {
		var a domain.UsageAggregate
		var sampleCount, rx, tx, restarts, exceptions int64
		if err := rows.Scan(&a.ApplicationID, &a.EnvironmentID, &a.DeploymentID, &a.ServiceName, &a.ReleaseID, &a.WindowStart, &a.WindowEnd, &sampleCount, &a.CPUSeconds, &a.MemoryByteSeconds, &a.DiskByteSeconds, &a.RuntimeSeconds, &a.AverageCPUMillicores, &a.AverageMemoryBytes, &a.AverageDiskBytes, &a.TrendCPUMillicoresPerSecond, &a.TrendMemoryBytesPerSecond, &a.TrendDiskBytesPerSecond, &rx, &tx, &restarts, &exceptions, &a.PeakCPUMillicores, &a.PeakMemoryBytes, &a.PeakDiskBytes, &a.LimitCPUMillicores, &a.LimitMemoryBytes, &a.LimitDiskBytes, &a.LimitPIDs); err != nil {
			return nil, err
		}
		a.SampleCount = uint64(sampleCount)
		a.NetworkRxBytes = uint64(rx)
		a.NetworkTxBytes = uint64(tx)
		a.RestartCount = uint64(restarts)
		a.ExceptionCount = uint64(exceptions)
		a.ID = domain.ID(digest(a.ApplicationID.String() + a.ServiceName + a.WindowStart.String()))
		out = append(out, a)
	}
	return out, rows.Err()
}

// QueryUsageFacts is the detailed, read-only M5 operator query. It keeps
// limits separate from actuals and binds anomaly references to source facts.
func (p *Provider) QueryUsageFacts(ctx context.Context, q DetailQuery) (UsageView, error) {
	if err := p.check(); err != nil {
		return UsageView{}, err
	}
	if q.ApplicationID.Empty() || q.From.IsZero() || q.To.IsZero() || !q.From.Before(q.To) {
		return UsageView{}, usage.ErrInvalidFact
	}
	args := []any{q.ApplicationID.String(), q.From.UTC(), q.To.UTC()}
	where := []string{"application_id=$1", "window_end > $2", "window_start < $3"}
	if q.ServiceName != "" {
		args = append(args, q.ServiceName)
		where = append(where, fmt.Sprintf("service_name=$%d", len(args)))
	}
	if !q.ReleaseID.Empty() {
		args = append(args, q.ReleaseID.String())
		where = append(where, fmt.Sprintf("release_id=$%d", len(args)))
	}
	rows, err := p.db.QueryContext(ctx, `SELECT application_id,environment_id,deployment_id,release_id,service_name,window_start,window_end,sample_count,cpu_seconds,memory_byte_seconds,disk_byte_seconds,runtime_seconds,average_cpu_millicores,average_memory_bytes,average_disk_bytes,trend_cpu_millicores_per_second,trend_memory_bytes_per_second,trend_disk_bytes_per_second,network_rx_bytes,network_tx_bytes,restart_count,exception_count,peak_cpu_millicores,peak_memory_bytes,peak_disk_bytes,limit_cpu_millicores,limit_memory_bytes,limit_disk_bytes,limit_pids FROM m5_usage_bucket_current WHERE `+strings.Join(where, " AND ")+` ORDER BY service_name,release_id,window_start,deployment_id`, args...)
	if err != nil {
		return UsageView{}, err
	}
	defer rows.Close()
	view := UsageView{ApplicationID: q.ApplicationID, From: q.From.UTC(), To: q.To.UTC(), Buckets: []UsageBucket{}}
	for rows.Next() {
		var bucket UsageBucket
		if err := rows.Scan(&bucket.ApplicationID, &bucket.EnvironmentID, &bucket.DeploymentID, &bucket.ReleaseID, &bucket.ServiceName, &bucket.WindowStart, &bucket.WindowEnd, &bucket.SampleCount, &bucket.CPUSeconds, &bucket.MemoryByteSeconds, &bucket.DiskByteSeconds, &bucket.RuntimeSeconds, &bucket.AverageCPUMillicores, &bucket.AverageMemoryBytes, &bucket.AverageDiskBytes, &bucket.CPUTrendMillicoresPerSecond, &bucket.MemoryTrendBytesPerSecond, &bucket.DiskTrendBytesPerSecond, &bucket.NetworkRxBytes, &bucket.NetworkTxBytes, &bucket.RestartCount, &bucket.ExceptionCount, &bucket.PeakCPUMillicores, &bucket.PeakMemoryBytes, &bucket.PeakDiskBytes, &bucket.Limits.CPUMillicores, &bucket.Limits.MemoryBytes, &bucket.Limits.DiskBytes, &bucket.Limits.PIDs); err != nil {
			return UsageView{}, err
		}
		view.Buckets = append(view.Buckets, bucket)
	}
	if err := rows.Err(); err != nil {
		return UsageView{}, err
	}
	anomalyRows, err := p.db.QueryContext(ctx, `SELECT a.id,a.kind,a.source_id,a.observed_at,r.service_name,r.release_id FROM m5_usage_anomalies a JOIN m5_usage_raw_facts r ON r.source_id=a.source_id WHERE a.application_id=$1 AND a.observed_at >= $2 AND a.observed_at < $3 ORDER BY a.observed_at,a.id`, q.ApplicationID.String(), q.From.UTC(), q.To.UTC())
	if err != nil {
		return UsageView{}, err
	}
	defer anomalyRows.Close()
	for anomalyRows.Next() {
		var anomaly AnomalyRef
		var serviceName, releaseID string
		if err := anomalyRows.Scan(&anomaly.ID, &anomaly.Kind, &anomaly.SourceID, &anomaly.ObservedAt, &serviceName, &releaseID); err != nil {
			return UsageView{}, err
		}
		for index := range view.Buckets {
			bucket := &view.Buckets[index]
			if bucket.ServiceName == serviceName && bucket.ReleaseID == releaseID && !anomaly.ObservedAt.Before(bucket.WindowStart) && anomaly.ObservedAt.Before(bucket.WindowEnd) {
				bucket.Anomalies = append(bucket.Anomalies, anomaly)
				break
			}
		}
	}
	if err := anomalyRows.Err(); err != nil {
		return UsageView{}, err
	}
	for index := range view.Buckets {
		bucket := &view.Buckets[index]
		if bucket.ExceptionCount > 0 && len(bucket.Anomalies) == 0 {
			bucket.Anomalies = append(bucket.Anomalies, AnomalyRef{ID: digest("aggregate-anomaly:" + bucket.ApplicationID + bucket.ServiceName + bucket.ReleaseID + bucket.WindowStart.UTC().Format(time.RFC3339Nano)), Kind: "runtime_unhealthy_aggregate", ObservedAt: bucket.WindowEnd.UTC()})
		}
	}
	return view, nil
}

func (p *Provider) Compact(ctx context.Context, q contracts.MeterQuery) error {
	if err := p.check(); err != nil {
		return err
	}
	if q.ApplicationID.Empty() || q.From.IsZero() || q.To.IsZero() || !q.From.Before(q.To) {
		return usage.ErrInvalidFact
	}
	rows, err := p.db.QueryContext(ctx, `SELECT source_id,application_id,environment_id,deployment_id,release_id,service_name,observed_at,cpu_seconds,memory_byte_seconds,runtime_seconds,cpu_millicores,memory_bytes,disk_bytes,network_rx_bytes,network_tx_bytes,restart_count,exception_count,limit_cpu_millicores,limit_memory_bytes,limit_disk_bytes,limit_pids FROM m5_usage_raw_facts WHERE application_id=$1 AND observed_at >= $2 AND observed_at < $3 ORDER BY observed_at,source_id`, q.ApplicationID.String(), q.From.UTC(), q.To.UTC())
	if err != nil {
		return err
	}
	defer rows.Close()
	fs := []usage.Fact{}
	for rows.Next() {
		var f usage.Fact
		if err := rows.Scan(&f.SourceID, &f.ApplicationID, &f.EnvironmentID, &f.DeploymentID, &f.ReleaseID, &f.ServiceName, &f.ObservedAt, &f.CPUSeconds, &f.MemoryByteSeconds, &f.RuntimeSeconds, &f.CPUMillicores, &f.MemoryBytes, &f.DiskBytes, &f.NetworkRxBytes, &f.NetworkTxBytes, &f.RestartCount, &f.ExceptionCount, &f.LimitCPUMillicores, &f.LimitMemoryBytes, &f.LimitDiskBytes, &f.LimitPIDs); err != nil {
			return err
		}
		if q.ServiceName != "" && f.ServiceName != q.ServiceName {
			continue
		}
		if !q.ReleaseID.Empty() && f.ReleaseID != q.ReleaseID.String() {
			continue
		}
		fs = append(fs, f)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(fs) == 0 {
		return nil
	}
	as, err := usage.AggregateFacts(fs, p.bucket)
	if err != nil {
		return err
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, a := range as {
		if err := a.Validate(); err != nil {
			return err
		}
		d := digest(fmt.Sprintf("%+v", a))
		var old string
		err := tx.QueryRowContext(ctx, `SELECT source_digest FROM m5_usage_bucket_current WHERE application_id=$1 AND environment_id=$2 AND deployment_id=$3 AND release_id=$4 AND service_name=$5 AND window_start=$6`, a.ApplicationID, a.EnvironmentID, a.DeploymentID, a.ReleaseID, a.ServiceName, a.WindowStart).Scan(&old)
		if err == nil && old == d {
			continue
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var rev int
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(max(revision),0)+1 FROM m5_usage_bucket_facts WHERE application_id=$1 AND environment_id=$2 AND deployment_id=$3 AND release_id=$4 AND service_name=$5 AND window_start=$6`, a.ApplicationID, a.EnvironmentID, a.DeploymentID, a.ReleaseID, a.ServiceName, a.WindowStart).Scan(&rev); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO m5_usage_bucket_facts(application_id,environment_id,deployment_id,release_id,service_name,window_start,window_end,revision,source_digest,sample_count,cpu_seconds,memory_byte_seconds,disk_byte_seconds,runtime_seconds,average_cpu_millicores,average_memory_bytes,average_disk_bytes,trend_cpu_millicores_per_second,trend_memory_bytes_per_second,trend_disk_bytes_per_second,network_rx_bytes,network_tx_bytes,restart_count,exception_count,peak_cpu_millicores,peak_memory_bytes,peak_disk_bytes,limit_cpu_millicores,limit_memory_bytes,limit_disk_bytes,limit_pids) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31)`, a.ApplicationID, a.EnvironmentID, a.DeploymentID, a.ReleaseID, a.ServiceName, a.WindowStart, a.WindowEnd, rev, d, a.SampleCount, a.CPUSeconds, a.MemoryByteSeconds, a.DiskByteSeconds, a.RuntimeSeconds, a.AverageCPUMillicores, a.AverageMemoryBytes, a.AverageDiskBytes, a.TrendCPUMillicoresPerSecond, a.TrendMemoryBytesPerSecond, a.TrendDiskBytesPerSecond, a.NetworkRxBytes, a.NetworkTxBytes, a.RestartCount, a.ExceptionCount, a.PeakCPUMillicores, a.PeakMemoryBytes, a.PeakDiskBytes, a.LimitCPUMillicores, a.LimitMemoryBytes, a.LimitDiskBytes, a.LimitPIDs)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (p *Provider) Prune(ctx context.Context, now time.Time, rawRetention, aggregateRetention time.Duration) error {
	if err := p.check(); err != nil {
		return err
	}
	if rawRetention <= 0 || aggregateRetention <= 0 {
		return usage.ErrInvalidFact
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SET LOCAL open_card.m5_retention = 'approved'`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM m5_usage_anomalies WHERE observed_at < $1`, now.UTC().Add(-rawRetention)); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM m5_usage_raw_facts WHERE observed_at < $1`, now.UTC().Add(-rawRetention))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM m5_usage_bucket_facts b WHERE b.window_end < $1 AND EXISTS (SELECT 1 FROM m5_usage_bucket_facts newer WHERE newer.application_id=b.application_id AND newer.service_name=b.service_name AND newer.release_id=b.release_id AND newer.window_start>b.window_start)`, now.UTC().Add(-aggregateRetention))
	if err != nil {
		return err
	}
	return tx.Commit()
}
