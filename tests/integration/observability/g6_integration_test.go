//go:build integration

package observability_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/observability"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

func TestG6MetricScaleDedupAndQueryGate(t *testing.T) {
	databaseURL := os.Getenv("OPEN_CARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("OPEN_CARD_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	store, err := postgres.OpenStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const applicationID = "app_g6_scale"
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO applications(id,name) VALUES($1,'G6 scale fixture') ON CONFLICT DO NOTHING`, applicationID); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-7 * 24 * time.Hour).Truncate(time.Minute)
	started := time.Now()
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO metric_samples(
			observed_at,sample_identity,sample_fingerprint,sample_id,
			application_id,service_name,release_id,cpu,cpu_seconds,
			memory_bytes,disk_bytes,network_rx_bytes,network_tx_bytes,
			restart_count,exception_count)
		SELECT $1::timestamptz + minute_index * interval '1 minute',
		       'identity-' || service_index || '-' || minute_index,
		       'fingerprint-' || service_index || '-' || minute_index,
		       'sample-' || service_index || '-' || minute_index,
		       $2,
		       'service-' || lpad(service_index::text,3,'0'),
		       'release-g6',
		       (service_index % 10)::double precision / 10,
		       0,
		       1048576 + service_index * 1024,
		       2097152 + minute_index,
		       minute_index * 10,
		       minute_index * 5,
		       CASE WHEN minute_index % 1440 = 0 THEN 1 ELSE 0 END,
		       CASE WHEN minute_index % 2000 = 0 THEN 1 ELSE 0 END
		  FROM generate_series(0,99) AS service_index
		 CROSS JOIN generate_series(0,10079) AS minute_index
		ON CONFLICT DO NOTHING
	`, base, applicationID); err != nil {
		t.Fatal(err)
	}
	insertDuration := time.Since(started)
	var sampleCount int
	if err := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM metric_samples WHERE application_id=$1`, applicationID).Scan(&sampleCount); err != nil {
		t.Fatal(err)
	}
	if sampleCount != 100*7*24*60 {
		t.Fatalf("expected 100 services x 7 days of minute samples, got %d", sampleCount)
	}
	if _, err := store.DB().ExecContext(ctx, `ANALYZE metric_samples`); err != nil {
		t.Fatal(err)
	}

	metricStore := observability.NewMetricStore(store.DB())
	sample := observability.Sample{ID: "g6-live-dedup", ApplicationID: applicationID, ServiceName: "service-000", ReleaseID: "release-g6", At: base.Add(10080 * time.Minute), CPU: 0.25, MemoryBytes: 2 << 20, DiskBytes: 3 << 20}
	if err := metricStore.InsertSamples(ctx, []observability.Sample{sample, sample}); err != nil {
		t.Fatal(err)
	}
	changed := sample
	changed.MemoryBytes++
	if err := metricStore.InsertSamples(ctx, []observability.Sample{changed}); !errors.Is(err, observability.ErrSampleConflict) {
		t.Fatalf("changed producer retry was not rejected: %v", err)
	}

	durations := make([]time.Duration, 0, 20)
	for iteration := 0; iteration < 20; iteration++ {
		queryStarted := time.Now()
		buckets, err := metricStore.Query(ctx, observability.Query{ApplicationID: applicationID, ServiceName: "service-042", From: base, To: base.Add(7 * 24 * time.Hour), Bucket: 5 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		if len(buckets) != 7*24*12 {
			t.Fatalf("expected 2016 five-minute buckets, got %d", len(buckets))
		}
		durations = append(durations, time.Since(queryStarted))
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p95 := durations[(len(durations)*95+99)/100-1]
	t.Logf("sample_count=%d insert_duration=%s query_samples=%d query_p95=%s", sampleCount, insertDuration, len(durations), p95)
	if p95 > 500*time.Millisecond {
		t.Fatalf("G6 aggregate query p95 exceeded 500ms: %s", p95)
	}

	var immutableRejected bool
	if _, err := store.DB().ExecContext(ctx, `UPDATE metric_samples SET cpu=cpu+1 WHERE application_id=$1 AND service_name='service-000'`, applicationID); err != nil {
		immutableRejected = true
	}
	if !immutableRejected {
		t.Fatal("append-only metric sample accepted UPDATE")
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO audit_evidence(id,actor_type,actor_id,action,reason,input_digest,result,record_hash) VALUES($1,'test','g6','metric-gc','retention isolation','sha256:test','pass',$2)`, "audit_g6_"+fmt.Sprint(time.Now().UnixNano()), "sha256:audit-"+fmt.Sprint(time.Now().UnixNano())); err != nil {
		t.Fatal(err)
	}
	var auditCount int
	if err := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM audit_evidence WHERE action='metric-gc'`).Scan(&auditCount); err != nil || auditCount == 0 {
		t.Fatalf("audit evidence was not retained: count=%d err=%v", auditCount, err)
	}
}
