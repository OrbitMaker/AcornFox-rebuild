//go:build integration

package usage_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/providers/meter/local"
)

type dockerFactsFile struct {
	TaskPrefix   string `json:"task_prefix"`
	ContainerID  string `json:"container_id"`
	ImageDigest  string `json:"image_digest"`
	NoHostMounts bool   `json:"no_host_mounts"`
	NoDockerSock bool   `json:"no_docker_socket"`
	Samples      []struct {
		ID                 string    `json:"id"`
		ObservedAt         time.Time `json:"observed_at"`
		Healthy            bool      `json:"healthy"`
		CPUMillicores      int64     `json:"cpu_millicores"`
		MemoryBytes        int64     `json:"memory_bytes"`
		DiskBytes          int64     `json:"disk_bytes"`
		NetworkRxBytes     int64     `json:"network_rx_bytes"`
		NetworkTxBytes     int64     `json:"network_tx_bytes"`
		RestartCount       int64     `json:"restart_count"`
		LimitCPUMillicores int64     `json:"limit_cpu_millicores"`
		LimitMemoryBytes   int64     `json:"limit_memory_bytes"`
		LimitPIDs          int64     `json:"limit_pids"`
	} `json:"samples"`
}

func TestM5ProjectsM4CompactsAndKeepsApplicationScope(t *testing.T) {
	dsn := os.Getenv("OPEN_CARD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("OPEN_CARD_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	s := strings.ToLower(domain.MustNewID("m5").String())
	app := domain.ID("app_" + s)
	env, src, def, rel, dep := domain.ID("env_"+s), domain.ID("src_"+s), domain.ID("def_"+s), domain.ID("rel_"+s), domain.ID("dep_"+s)
	now := time.Now().UTC().Truncate(5 * time.Minute).Add(time.Minute)
	for _, x := range []struct {
		q string
		a []any
	}{{`INSERT INTO applications(id,name) VALUES($1,$2)`, []any{app.String(), "m5-" + s}}, {`INSERT INTO environments(id,application_id,name) VALUES($1,$2,'m5')`, []any{env.String(), app.String()}}, {`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable) VALUES($1,$2,'upload','upload','x',$3,$4,'x','prepared',true)`, []any{src.String(), app.String(), s, "sha256:" + strings.Repeat("a", 64)}}, {`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES($1,$2,$3,1,'{}')`, []any{def.String(), app.String(), src.String()}}, {`INSERT INTO releases(id,application_id,definition_id,version,service_digests) VALUES($1,$2,$3,1,jsonb_build_object('web',$4::text))`, []any{rel.String(), app.String(), def.String(), "sha256:" + strings.Repeat("b", 64)}}, {`INSERT INTO deployments(id,environment_id,release_id,state,runtime_healthy,created_at,updated_at) VALUES($1,$2,$3,'serving',true,$4,$4)`, []any{dep.String(), env.String(), rel.String(), now}}} {
		if _, err := db.ExecContext(ctx, x.q, x.a...); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		_, err := db.ExecContext(ctx, `INSERT INTO m4_service_observations(id,sample_id,application_id,environment_id,deployment_id,release_id,service_name,service_role,runtime_status,healthy,required,cpu_millicores,memory_bytes,disk_bytes,network_rx_bytes,network_tx_bytes,restart_count,observed_at,container_id,host_port,pids_current,applied_cpu_millicores,applied_memory_bytes,applied_pids,cgroup_verified,metrics_known) VALUES($1,$2,$3,$4,$5,$6,'web','ingress','running',$7,true,$8,$9,$10,$11,$12,0,$13,$14,0,1,$15,$16,$17,true,true)`, "obs_"+s+string(rune('a'+i)), "sample_"+s+string(rune('a'+i)), app.String(), env.String(), dep.String(), rel.String(), i == 0, 1000, 100+i, 10, 10+i*10, 5+i*5, now.Add(time.Duration(i)*time.Minute), strings.Repeat("b", 64), 1000, 1024, 64)
		if err != nil {
			t.Fatal(err)
		}
	}
	p := local.New(db)
	if err := p.ProjectM4(ctx, app, now.Add(-time.Second), now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	q := contracts.MeterQuery{ApplicationID: app, From: now.Add(-time.Second), To: now.Add(5 * time.Minute)}
	if err := p.Compact(ctx, q); err != nil {
		t.Fatal(err)
	}
	got, err := p.QueryUsageFacts(ctx, local.DetailQuery{ApplicationID: app, From: q.From, To: q.To})
	if err != nil || len(got.Buckets) != 1 {
		t.Fatalf("detail=%+v err=%v", got, err)
	}
	b := got.Buckets[0]
	if b.AverageCPUMillicores != 1000 || b.AverageMemoryBytes != 100.5 || b.AverageDiskBytes != 10 || b.PeakDiskBytes != 10 || b.Limits.CPUMillicores != 1000 || len(b.Anomalies) != 1 || b.RuntimeSeconds != 60 {
		t.Fatalf("detail separation/anomaly/runtime mismatch: %+v", b)
	}
}

func TestM5RealDockerFactsAggregateWithoutCrossApplicationLeak(t *testing.T) {
	dsn, factsPath := os.Getenv("OPEN_CARD_TEST_DATABASE_URL"), os.Getenv("OPEN_CARD_M5_DOCKER_FACTS")
	if dsn == "" || factsPath == "" {
		t.Skip("OPEN_CARD_TEST_DATABASE_URL and OPEN_CARD_M5_DOCKER_FACTS are required")
	}
	payload, err := os.ReadFile(factsPath)
	if err != nil {
		t.Fatal(err)
	}
	var facts dockerFactsFile
	if err := json.Unmarshal(payload, &facts); err != nil {
		t.Fatal(err)
	}
	if facts.TaskPrefix != "opencard-mvp-fa8f8eab" || !facts.NoHostMounts || !facts.NoDockerSock || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(facts.ContainerID) || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(facts.ImageDigest) || len(facts.Samples) < 2 {
		t.Fatalf("Docker fact boundary is invalid: %+v", facts)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	suffix := strings.ToLower(domain.MustNewID("m5docker").String())
	app, other := domain.ID("app_"+suffix), domain.ID("app_other_"+suffix)
	env, src, def, rel, dep := domain.ID("env_"+suffix), domain.ID("src_"+suffix), domain.ID("def_"+suffix), domain.ID("rel_"+suffix), domain.ID("dep_"+suffix)
	createdAt := facts.Samples[0].ObservedAt.Add(-time.Minute).UTC()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO applications(id,name) VALUES($1,'m5 docker')`, []any{app.String()}},
		{`INSERT INTO applications(id,name) VALUES($1,'m5 isolated')`, []any{other.String()}},
		{`INSERT INTO environments(id,application_id,name) VALUES($1,$2,'m5')`, []any{env.String(), app.String()}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable) VALUES($1,$2,'upload','upload','x','main',$3,'x','prepared',true)`, []any{src.String(), app.String(), facts.ImageDigest}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration) VALUES($1,$2,$3,1,'{}')`, []any{def.String(), app.String(), src.String()}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests) VALUES($1,$2,$3,1,jsonb_build_object('load',$4::text))`, []any{rel.String(), app.String(), def.String(), facts.ImageDigest}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,runtime_healthy,created_at,updated_at) VALUES($1,$2,$3,'serving',true,$4,$4)`, []any{dep.String(), env.String(), rel.String(), createdAt}},
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, sample := range facts.Samples {
		if sample.CPUMillicores < 0 || sample.MemoryBytes <= 0 || sample.DiskBytes <= 0 || sample.NetworkRxBytes <= 0 || sample.NetworkTxBytes <= 0 || sample.LimitCPUMillicores != 500 || sample.LimitMemoryBytes != 64<<20 || sample.LimitPIDs != 64 {
			t.Fatalf("independent Docker sample is incomplete: %+v", sample)
		}
		_, err := db.ExecContext(ctx, `INSERT INTO m4_service_observations(id,sample_id,application_id,environment_id,deployment_id,release_id,service_name,service_role,runtime_status,healthy,required,cpu_millicores,memory_bytes,disk_bytes,network_rx_bytes,network_tx_bytes,restart_count,observed_at,container_id,pids_current,applied_cpu_millicores,applied_memory_bytes,applied_pids,cgroup_verified,metrics_known) VALUES($1,$2,$3,$4,$5,$6,'load','worker','running',$7,true,$8,$9,$10,$11,$12,$13,$14,$15,1,$16,$17,$18,true,true)`, "obs_"+sample.ID, sample.ID, app.String(), env.String(), dep.String(), rel.String(), sample.Healthy, sample.CPUMillicores, sample.MemoryBytes, sample.DiskBytes, sample.NetworkRxBytes, sample.NetworkTxBytes, sample.RestartCount, sample.ObservedAt.UTC(), facts.ContainerID, sample.LimitCPUMillicores, sample.LimitMemoryBytes, sample.LimitPIDs)
		if err != nil {
			t.Fatal(err)
		}
	}
	provider := local.New(db)
	from, to := facts.Samples[0].ObservedAt.Add(-time.Second), facts.Samples[len(facts.Samples)-1].ObservedAt.Add(time.Second)
	if err := provider.ProjectM4(ctx, app, from, to); err != nil {
		t.Fatal(err)
	}
	if err := provider.Compact(ctx, contracts.MeterQuery{ApplicationID: app, From: from, To: to}); err != nil {
		t.Fatal(err)
	}
	view, err := provider.QueryUsageFacts(ctx, local.DetailQuery{ApplicationID: app, ServiceName: "load", ReleaseID: rel, From: from, To: to})
	if err != nil || len(view.Buckets) == 0 {
		t.Fatalf("real Docker usage view=%+v err=%v", view, err)
	}
	last := view.Buckets[len(view.Buckets)-1]
	if last.PeakMemoryBytes <= 0 || last.PeakDiskBytes <= 0 || last.NetworkRxBytes <= 0 || last.NetworkTxBytes <= 0 || last.Limits.CPUMillicores != 500 || last.Limits.MemoryBytes != 64<<20 || len(last.Anomalies) == 0 {
		t.Fatalf("real Docker aggregate is incomplete: %+v", last)
	}
	isolated, err := provider.QueryUsageFacts(ctx, local.DetailQuery{ApplicationID: other, From: from, To: to})
	if err != nil || len(isolated.Buckets) != 0 {
		t.Fatalf("cross-application data leaked: %+v err=%v", isolated, err)
	}
}

func TestM5WatermarkRejectsRawWriteAndRetentionKeepsLatestAggregateAndAudit(t *testing.T) {
	dsn := os.Getenv("OPEN_CARD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("OPEN_CARD_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC().Truncate(time.Second)
	suffix := strings.ToLower(domain.MustNewID("m5retention").String())
	app := domain.ID("app_" + suffix)
	if _, err := db.ExecContext(ctx, `INSERT INTO applications(id,name) VALUES($1,'m5 retention')`, app.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO m5_usage_storage_state(singleton,total_bytes,used_bytes,hard_watermark_bytes,observed_at) VALUES(true,100,90,10,$1) ON CONFLICT(singleton) DO UPDATE SET total_bytes=100,used_bytes=90,hard_watermark_bytes=10,observed_at=$1`, now); err != nil {
		t.Fatal(err)
	}
	provider := local.New(db)
	err = provider.Ingest(ctx, []contracts.MeterSample{{ID: "blocked-" + suffix, ApplicationID: app, ServiceName: "web", ReleaseID: domain.ID("rel_" + suffix), At: now, MemoryBytes: 1}}, contracts.OperationContext{IdempotencyKey: "m5-watermark-" + suffix})
	var providerErr *contracts.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != contracts.ErrCapacity {
		t.Fatalf("watermark did not fail closed: %T %v", err, err)
	}
	var blockedRows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m5_usage_raw_facts WHERE application_id=$1`, app.String()).Scan(&blockedRows); err != nil || blockedRows != 0 {
		t.Fatalf("watermark left raw rows=%d err=%v", blockedRows, err)
	}
	insertBucket := func(start time.Time, revision int) {
		t.Helper()
		_, err := db.ExecContext(ctx, `INSERT INTO m5_usage_bucket_facts(application_id,service_name,window_start,window_end,revision,source_digest,sample_count,cpu_seconds,memory_byte_seconds,disk_byte_seconds,runtime_seconds,average_cpu_millicores,average_memory_bytes,average_disk_bytes,trend_cpu_millicores_per_second,trend_memory_bytes_per_second,trend_disk_bytes_per_second,network_rx_bytes,network_tx_bytes,restart_count,exception_count,peak_cpu_millicores,peak_memory_bytes,peak_disk_bytes,limit_cpu_millicores,limit_memory_bytes,limit_disk_bytes,limit_pids) VALUES($1,'web',$2,$3,$4,$5,1,1,1,1,60,1,1,1,0,0,0,1,1,0,0,1,1,1,2,2,2,2)`, app.String(), start, start.Add(5*time.Minute), revision, "digest-"+suffix+start.Format("20060102"))
		if err != nil {
			t.Fatal(err)
		}
	}
	insertBucket(now.Add(-200*24*time.Hour), 1)
	insertBucket(now.Add(-100*24*time.Hour), 1)
	auditID := "audit_" + suffix
	if _, err := db.ExecContext(ctx, `INSERT INTO audit_evidence(id,actor_type,actor_id,action,reason,input_digest,result,previous_hash,record_hash) VALUES($1,'test','m5','usage-retention','retention isolation','sha256:m5-retention','pass',(SELECT record_hash FROM audit_evidence ORDER BY sequence DESC LIMIT 1),$2)`, auditID, "sha256:audit-"+suffix); err != nil {
		t.Fatal(err)
	}
	if err := provider.Prune(ctx, now, 7*24*time.Hour, 90*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	var bucketCount, auditCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM m5_usage_bucket_current WHERE application_id=$1`, app.String()).Scan(&bucketCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_evidence WHERE id=$1`, auditID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if bucketCount != 1 || auditCount != 1 {
		t.Fatalf("retention result buckets=%d audit=%d", bucketCount, auditCount)
	}
	retained, err := provider.QueryUsageFacts(ctx, local.DetailQuery{ApplicationID: app, From: now.Add(-110 * 24 * time.Hour), To: now.Add(-99 * 24 * time.Hour)})
	if err != nil || len(retained.Buckets) != 1 || retained.Buckets[0].AverageCPUMillicores != 1 {
		t.Fatalf("retained aggregate was not queryable after raw cleanup: %+v err=%v", retained, err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM m5_usage_storage_state WHERE singleton`); err != nil {
		t.Fatal(err)
	}
}
