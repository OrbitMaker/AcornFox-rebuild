package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	meterlocal "github.com/open-card/open-card/internal/providers/meter/local"
)

const (
	m5DefaultQueryWindow        = time.Hour
	m5MaximumQueryWindow        = 31 * 24 * time.Hour
	m5DefaultRawRetention       = 7 * 24 * time.Hour
	m5DefaultAggregateRetention = 90 * 24 * time.Hour
)

type M5UsageHTTPHandler struct {
	DB                    *sql.DB
	Meter                 *meterlocal.Provider
	Now                   func() time.Time
	AllowAISummaryContext bool
}

type m5Measurement struct {
	Actual float64 `json:"actual"`
	Limit  float64 `json:"limit"`
	Unit   string  `json:"unit"`
}

type m5ResourceMeasurements struct {
	CPU     m5Measurement `json:"cpu"`
	Memory  m5Measurement `json:"memory"`
	Disk    m5Measurement `json:"disk"`
	Network m5Measurement `json:"network"`
}

type m5TrendPoint struct {
	ObservedAt time.Time `json:"observed_at"`
	m5ResourceMeasurements
}

type m5Anomaly struct {
	ID               string    `json:"id"`
	ObservedAt       time.Time `json:"observed_at"`
	Severity         string    `json:"severity"`
	Summary          string    `json:"summary"`
	RelatedServiceID string    `json:"related_service_id,omitempty"`
	RelatedReleaseID string    `json:"related_release_id,omitempty"`
}

type m5ServiceUsage struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	ReleaseID  string                 `json:"release_id"`
	Runtime    string                 `json:"runtime"`
	StartedAt  time.Time              `json:"started_at"`
	Actual     m5ResourceMeasurements `json:"actual"`
	Average    m5ResourceMeasurements `json:"average"`
	Peak       m5ResourceMeasurements `json:"peak"`
	Configured m5ResourceMeasurements `json:"configured"`
	Trend      []m5TrendPoint         `json:"trend"`
	Anomalies  []m5Anomaly            `json:"anomalies"`
}

type m5ApplicationUsage struct {
	Version         string           `json:"version"`
	ObservedAt      time.Time        `json:"observed_at"`
	ApplicationID   string           `json:"application_id"`
	ApplicationName string           `json:"application_name"`
	Services        []m5ServiceUsage `json:"services"`
	Anomalies       []m5Anomaly      `json:"anomalies"`
	AI              string           `json:"ai"`
}

func (h *M5UsageHTTPHandler) HandleApplication(w http.ResponseWriter, r *http.Request) bool {
	prefix := apiPrefix + "applications/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, prefix), "/"), "/")
	if len(parts) < 2 || parts[1] != "usage" || len(parts) > 3 || (len(parts) == 3 && parts[2] != "context") {
		return false
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, OPTIONS")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "usage facts require GET")
		return true
	}
	if h == nil || h.DB == nil || h.Meter == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "m5_usage_unavailable", "M5 usage dependencies are not configured")
		return true
	}
	appID := domain.ID(strings.TrimSpace(parts[0]))
	if err := domain.RequireID(appID, "usage application id"); err != nil {
		writeJSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return true
	}
	mode := strings.TrimSpace(r.URL.Query().Get("mode"))
	if mode == "" {
		mode = "normal"
	}
	if mode != "normal" && mode != "operations" {
		writeJSONError(w, http.StatusBadRequest, "validation_failed", "usage view mode is unsupported")
		return true
	}
	contextRequest := len(parts) == 3
	if (mode == "operations" || contextRequest) && !m4Operator(r) {
		writeJSONError(w, http.StatusForbidden, "forbidden", "detailed usage facts require operator role")
		return true
	}
	if contextRequest && !h.AllowAISummaryContext {
		writeJSONError(w, http.StatusForbidden, "ai_summary_disabled", "AI usage summary context is disabled")
		return true
	}
	now := time.Now().UTC()
	if h.Now != nil {
		now = h.Now().UTC()
	}
	from, to, err := m5UsageWindow(r, now)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return true
	}
	service := strings.TrimSpace(r.URL.Query().Get("service"))
	release := domain.ID(strings.TrimSpace(r.URL.Query().Get("release")))
	if service != "" && (len(service) > 128 || strings.ContainsAny(service, "\x00\r\n")) {
		writeJSONError(w, http.StatusBadRequest, "validation_failed", "usage service filter is invalid")
		return true
	}
	if !release.Empty() && domain.RequireID(release, "usage release id") != nil {
		writeJSONError(w, http.StatusBadRequest, "validation_failed", "usage release filter is invalid")
		return true
	}
	var name string
	if err := h.DB.QueryRowContext(r.Context(), `SELECT name FROM applications WHERE id=$1`, appID.String()).Scan(&name); errors.Is(err, sql.ErrNoRows) {
		writeJSONError(w, http.StatusNotFound, "not_found", "application not found")
		return true
	} else if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "usage_query_failed", "usage application facts are unavailable")
		return true
	}
	view, err := h.Meter.QueryUsageFacts(r.Context(), meterlocal.DetailQuery{ApplicationID: appID, ServiceName: service, ReleaseID: release, From: from, To: to})
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "usage_query_failed", "usage facts are unavailable")
		return true
	}
	response := projectM5Usage(name, view, to)
	if contextRequest {
		writeJSON(w, http.StatusOK, map[string]any{"version": response.Version, "observed_at": response.ObservedAt, "application_id": response.ApplicationID, "service_count": len(response.Services), "anomaly_count": len(response.Anomalies), "source": "authorized_usage_aggregate"})
		return true
	}
	writeJSON(w, http.StatusOK, response)
	return true
}

func m5UsageWindow(r *http.Request, now time.Time) (time.Time, time.Time, error) {
	to := now.UTC()
	from := to.Add(-m5DefaultQueryWindow)
	parse := func(name string, fallback time.Time) (time.Time, error) {
		raw := strings.TrimSpace(r.URL.Query().Get(name))
		if raw == "" {
			return fallback, nil
		}
		value, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return time.Time{}, fmt.Errorf("usage %s must be RFC3339", name)
		}
		return value.UTC(), nil
	}
	var err error
	if to, err = parse("to", to); err != nil {
		return time.Time{}, time.Time{}, err
	}
	if from, err = parse("from", from); err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !from.Before(to) || to.Sub(from) > m5MaximumQueryWindow {
		return time.Time{}, time.Time{}, errors.New("usage window must be positive and no longer than 31 days")
	}
	return from, to, nil
}

func projectM5Usage(applicationName string, view meterlocal.UsageView, fallback time.Time) m5ApplicationUsage {
	type key struct{ deployment, release, service string }
	groups := map[key][]meterlocal.UsageBucket{}
	for _, bucket := range view.Buckets {
		group := key{bucket.DeploymentID, bucket.ReleaseID, bucket.ServiceName}
		groups[group] = append(groups[group], bucket)
	}
	keys := make([]key, 0, len(groups))
	for group := range groups {
		keys = append(keys, group)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].service != keys[j].service {
			return keys[i].service < keys[j].service
		}
		if keys[i].release != keys[j].release {
			return keys[i].release < keys[j].release
		}
		return keys[i].deployment < keys[j].deployment
	})
	response := m5ApplicationUsage{ObservedAt: fallback.UTC(), ApplicationID: view.ApplicationID.String(), ApplicationName: applicationName, Services: []m5ServiceUsage{}, Anomalies: []m5Anomaly{}, AI: "disabled"}
	for _, group := range keys {
		buckets := groups[group]
		sort.Slice(buckets, func(i, j int) bool { return buckets[i].WindowStart.Before(buckets[j].WindowStart) })
		service := m5ServiceUsage{ID: strings.Join([]string{view.ApplicationID.String(), group.deployment, group.release, group.service}, ":"), Name: group.service, ReleaseID: group.release, StartedAt: buckets[0].WindowStart.UTC(), Trend: []m5TrendPoint{}, Anomalies: []m5Anomaly{}}
		var runtime float64
		var averageSum m5ResourceMeasurements
		var sampleCount float64
		for _, bucket := range buckets {
			if bucket.RuntimeSeconds > runtime {
				runtime = bucket.RuntimeSeconds
			}
			network := float64(bucket.NetworkRxBytes + bucket.NetworkTxBytes)
			average := m5ResourceMeasurements{CPU: m5Measurement{Actual: bucket.AverageCPUMillicores, Limit: float64(bucket.Limits.CPUMillicores), Unit: "mCPU"}, Memory: m5Measurement{Actual: bucket.AverageMemoryBytes, Limit: float64(bucket.Limits.MemoryBytes), Unit: "B"}, Disk: m5Measurement{Actual: bucket.AverageDiskBytes, Limit: float64(bucket.Limits.DiskBytes), Unit: "B"}, Network: m5Measurement{Actual: network / float64(maxM5Int(bucket.SampleCount, 1)), Unit: "B"}}
			peak := m5ResourceMeasurements{CPU: m5Measurement{Actual: float64(bucket.PeakCPUMillicores), Limit: float64(bucket.Limits.CPUMillicores), Unit: "mCPU"}, Memory: m5Measurement{Actual: float64(bucket.PeakMemoryBytes), Limit: float64(bucket.Limits.MemoryBytes), Unit: "B"}, Disk: m5Measurement{Actual: float64(bucket.PeakDiskBytes), Limit: float64(bucket.Limits.DiskBytes), Unit: "B"}, Network: m5Measurement{Actual: network, Unit: "B"}}
			configured := m5ResourceMeasurements{CPU: m5Measurement{Actual: float64(bucket.Limits.CPUMillicores), Limit: float64(bucket.Limits.CPUMillicores), Unit: "mCPU"}, Memory: m5Measurement{Actual: float64(bucket.Limits.MemoryBytes), Limit: float64(bucket.Limits.MemoryBytes), Unit: "B"}, Disk: m5Measurement{Actual: float64(bucket.Limits.DiskBytes), Limit: float64(bucket.Limits.DiskBytes), Unit: "B"}, Network: m5Measurement{Unit: "B"}}
			count := float64(maxM5Int(bucket.SampleCount, 1))
			averageSum = addM5Measurements(averageSum, average, count)
			sampleCount += count
			service.Peak = maxM5Measurements(service.Peak, peak)
			service.Actual = service.Peak
			service.Configured = maxM5Measurements(service.Configured, configured)
			service.Trend = append(service.Trend, m5TrendPoint{ObservedAt: bucket.WindowEnd.UTC(), m5ResourceMeasurements: average})
			if bucket.WindowEnd.After(response.ObservedAt) {
				response.ObservedAt = bucket.WindowEnd.UTC()
			}
			for _, anomaly := range bucket.Anomalies {
				item := m5Anomaly{ID: anomaly.ID, ObservedAt: anomaly.ObservedAt.UTC(), Severity: "warning", Summary: "运行时观察到异常状态", RelatedServiceID: service.ID, RelatedReleaseID: group.release}
				service.Anomalies = append(service.Anomalies, item)
				response.Anomalies = append(response.Anomalies, item)
			}
		}
		service.Average = divideM5Measurements(averageSum, sampleCount)
		service.Runtime = strconv.FormatInt(int64(runtime), 10) + " 秒"
		response.Services = append(response.Services, service)
	}
	payload, _ := json.Marshal(struct {
		ApplicationID string
		ObservedAt    time.Time
		Services      []m5ServiceUsage
		Anomalies     []m5Anomaly
	}{response.ApplicationID, response.ObservedAt, response.Services, response.Anomalies})
	digest := sha256.Sum256(payload)
	response.Version = "usage-v1:" + hex.EncodeToString(digest[:12])
	return response
}

func maxM5Int(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func addM5Measurements(total, value m5ResourceMeasurements, weight float64) m5ResourceMeasurements {
	add := func(left, right m5Measurement) m5Measurement {
		left.Actual += right.Actual * weight
		if right.Limit > left.Limit {
			left.Limit = right.Limit
		}
		if left.Unit == "" {
			left.Unit = right.Unit
		}
		return left
	}
	return m5ResourceMeasurements{CPU: add(total.CPU, value.CPU), Memory: add(total.Memory, value.Memory), Disk: add(total.Disk, value.Disk), Network: add(total.Network, value.Network)}
}

func divideM5Measurements(total m5ResourceMeasurements, count float64) m5ResourceMeasurements {
	if count <= 0 {
		return total
	}
	divide := func(value m5Measurement) m5Measurement { value.Actual /= count; return value }
	return m5ResourceMeasurements{CPU: divide(total.CPU), Memory: divide(total.Memory), Disk: divide(total.Disk), Network: divide(total.Network)}
}

func maxM5Measurements(left, right m5ResourceMeasurements) m5ResourceMeasurements {
	maxOne := func(a, b m5Measurement) m5Measurement {
		if b.Actual > a.Actual {
			a.Actual = b.Actual
		}
		if b.Limit > a.Limit {
			a.Limit = b.Limit
		}
		if a.Unit == "" {
			a.Unit = b.Unit
		}
		return a
	}
	return m5ResourceMeasurements{CPU: maxOne(left.CPU, right.CPU), Memory: maxOne(left.Memory, right.Memory), Disk: maxOne(left.Disk, right.Disk), Network: maxOne(left.Network, right.Network)}
}

type M5UsageWorker struct {
	DB                 *sql.DB
	Meter              *meterlocal.Provider
	Interval           time.Duration
	StorageCapacity    int64
	StorageHardReserve int64
	Now                func() time.Time
}

func validateM5UsageSchema(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("M5 usage PostgreSQL dependency is missing")
	}
	var count int
	err := db.QueryRowContext(ctx, `SELECT count(*) FROM (VALUES (to_regclass('public.m5_usage_raw_facts')),(to_regclass('public.m5_usage_bucket_facts')),(to_regclass('public.m5_usage_anomalies')),(to_regclass('public.m5_usage_storage_state'))) required(relation) WHERE relation IS NOT NULL`).Scan(&count)
	if err != nil {
		return fmt.Errorf("validate M5 usage schema: %w", err)
	}
	if count != 4 {
		return errors.New("M5 usage schema 0020 is incomplete")
	}
	return nil
}

func (w *M5UsageWorker) RunOnce(ctx context.Context) error {
	if w == nil || w.DB == nil || w.Meter == nil {
		return errors.New("M5 usage worker dependencies are missing")
	}
	now := time.Now().UTC()
	if w.Now != nil {
		now = w.Now().UTC()
	}
	if err := w.Meter.Prune(ctx, now, m5DefaultRawRetention, m5DefaultAggregateRetention); err != nil {
		return fmt.Errorf("prune usage facts: %w", err)
	}
	if err := w.refreshStorageState(ctx, now); err != nil {
		return err
	}
	rows, err := w.DB.QueryContext(ctx, `SELECT id FROM applications ORDER BY id`)
	if err != nil {
		return fmt.Errorf("list usage applications: %w", err)
	}
	defer rows.Close()
	apps := []domain.ID{}
	for rows.Next() {
		var id domain.ID
		if err := rows.Scan(&id); err != nil {
			return err
		}
		apps = append(apps, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	from, to := now.Add(-m5DefaultRawRetention), now.Add(time.Second)
	for _, app := range apps {
		if err := w.Meter.ProjectM4(ctx, app, from, to); err != nil {
			return fmt.Errorf("project M4 usage for %s: %w", app, err)
		}
		if err := w.Meter.Compact(ctx, contracts.MeterQuery{ApplicationID: app, From: from, To: to}); err != nil {
			return fmt.Errorf("compact usage for %s: %w", app, err)
		}
	}
	return nil
}

func (w *M5UsageWorker) refreshStorageState(ctx context.Context, now time.Time) error {
	total := w.StorageCapacity
	if total <= 0 {
		total = 8 << 30
	}
	hard := w.StorageHardReserve
	if hard <= 0 {
		hard = 512 << 20
	}
	var used int64
	if err := w.DB.QueryRowContext(ctx, `SELECT pg_database_size(current_database())`).Scan(&used); err != nil {
		return fmt.Errorf("measure usage storage: %w", err)
	}
	if used > total {
		used = total
	}
	_, err := w.DB.ExecContext(ctx, `INSERT INTO m5_usage_storage_state(singleton,total_bytes,used_bytes,hard_watermark_bytes,observed_at) VALUES(true,$1,$2,$3,$4) ON CONFLICT(singleton) DO UPDATE SET total_bytes=excluded.total_bytes,used_bytes=excluded.used_bytes,hard_watermark_bytes=excluded.hard_watermark_bytes,observed_at=excluded.observed_at`, total, used, hard, now)
	if err != nil {
		return fmt.Errorf("record usage storage state: %w", err)
	}
	return nil
}

func (w *M5UsageWorker) Run(ctx context.Context) error {
	interval := w.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	if err := w.RunOnce(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := w.RunOnce(ctx); err != nil {
				return err
			}
		}
	}
}
