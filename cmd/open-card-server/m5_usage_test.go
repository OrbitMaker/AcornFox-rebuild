package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
	meterlocal "github.com/open-card/open-card/internal/providers/meter/local"
)

func TestM5UsageWindowIsUTCHalfOpenAndBounded(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.FixedZone("CST", 8*3600))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/applications/app_1/usage?from=2026-08-25T01:00:00%2B08:00&to=2026-08-25T02:00:00%2B08:00", nil)
	from, to, err := m5UsageWindow(r, now)
	if err != nil || from.Format(time.RFC3339) != "2026-08-24T17:00:00Z" || to.Format(time.RFC3339) != "2026-08-24T18:00:00Z" {
		t.Fatalf("window from=%s to=%s err=%v", from, to, err)
	}
	tooLarge := httptest.NewRequest(http.MethodGet, "/?from=2026-01-01T00:00:00Z&to=2026-08-25T00:00:00Z", nil)
	if _, _, err := m5UsageWindow(tooLarge, now); err == nil {
		t.Fatal("oversized usage query was accepted")
	}
}

func TestProjectM5UsageSeparatesActualLimitsAndRawFromAI(t *testing.T) {
	start := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	view := meterlocal.UsageView{ApplicationID: domain.ID("app_1"), From: start, To: start.Add(time.Hour), Buckets: []meterlocal.UsageBucket{{ApplicationID: "app_1", DeploymentID: "dep_1", ReleaseID: "rel_1", ServiceName: "web", WindowStart: start, WindowEnd: start.Add(5 * time.Minute), SampleCount: 2, RuntimeSeconds: 300, AverageCPUMillicores: 200, AverageMemoryBytes: 48 << 20, AverageDiskBytes: 6 << 20, PeakCPUMillicores: 250, PeakMemoryBytes: 64 << 20, PeakDiskBytes: 8 << 20, NetworkRxBytes: 100, NetworkTxBytes: 50, Limits: meterlocal.LimitSnapshot{CPUMillicores: 500, MemoryBytes: 128 << 20, DiskBytes: 16 << 20}, Anomalies: []meterlocal.AnomalyRef{{ID: "an_1", Kind: "runtime_unhealthy", SourceID: "m4:sample", ObservedAt: start.Add(time.Minute)}}}}}
	got := projectM5Usage("Example", view, view.To)
	if len(got.Services) != 1 || got.Services[0].Average.CPU.Actual != 200 || got.Services[0].Peak.CPU.Actual != 250 || got.Services[0].Actual.CPU.Actual != 250 || got.Services[0].Configured.CPU.Actual != 500 || got.Services[0].Actual.Memory.Actual != 64<<20 || got.AI != "disabled" || len(got.Anomalies) != 1 {
		t.Fatalf("usage projection=%#v", got)
	}
	payload, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"price", "invoice", "payment", "balance", "raw_log", "ai_context"} {
		if strings.Contains(strings.ToLower(string(payload)), forbidden) {
			t.Fatalf("usage projection leaked forbidden field %q: %s", forbidden, payload)
		}
	}
}

func TestM5UsageHandlerFailsClosedForOperatorAndAIContext(t *testing.T) {
	h := &M5UsageHTTPHandler{DB: &sql.DB{}, Meter: meterlocal.New(&sql.DB{})}
	operator := httptest.NewRecorder()
	h.HandleApplication(operator, httptest.NewRequest(http.MethodGet, "/api/v1/applications/app_1/usage?mode=operations", nil))
	if operator.Code != http.StatusForbidden {
		t.Fatalf("operator view without role=%d %s", operator.Code, operator.Body.String())
	}
	contextRequest := httptest.NewRequest(http.MethodGet, "/api/v1/applications/app_1/usage/context", nil)
	contextRequest = withControlPlaneIdentity(contextRequest, "admin_test")
	contextResponse := httptest.NewRecorder()
	h.HandleApplication(contextResponse, contextRequest)
	if contextResponse.Code != http.StatusForbidden || !strings.Contains(contextResponse.Body.String(), "ai_summary_disabled") {
		t.Fatalf("AI summary default=%d %s", contextResponse.Code, contextResponse.Body.String())
	}
}

func TestM5UsageWorkerMissingDependenciesFailsClosed(t *testing.T) {
	if err := (&M5UsageWorker{}).RunOnce(context.Background()); err == nil {
		t.Fatal("worker started without dependencies")
	}
}
