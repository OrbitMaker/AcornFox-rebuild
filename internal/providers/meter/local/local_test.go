package local

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func TestMeterFingerprintCoversActualLimitsAndScope(t *testing.T) {
	base := contracts.MeterSample{ID: "sample-1", ApplicationID: domain.ID("app_1"), EnvironmentID: domain.ID("env_1"), DeploymentID: domain.ID("dep_1"), ReleaseID: domain.ID("rel_1"), ServiceName: "web", At: time.Unix(1, 0).UTC(), CPUMillicores: 10, CPUSeconds: 1, MemoryBytes: 20, DiskBytes: 30, NetworkRxBytes: 40, NetworkTxBytes: 50, RuntimeSeconds: 60, LimitCPUMillicores: 100, LimitMemoryBytes: 200, LimitDiskBytes: 300, LimitPIDs: 10}
	want := fingerprint(base)
	mutations := []func(*contracts.MeterSample){
		func(value *contracts.MeterSample) { value.ApplicationID = "app_2" },
		func(value *contracts.MeterSample) { value.EnvironmentID = "env_2" },
		func(value *contracts.MeterSample) { value.DeploymentID = "dep_2" },
		func(value *contracts.MeterSample) { value.DiskBytes++ },
		func(value *contracts.MeterSample) { value.RuntimeSeconds++ },
		func(value *contracts.MeterSample) { value.LimitMemoryBytes++ },
	}
	for index, mutate := range mutations {
		changed := base
		mutate(&changed)
		if fingerprint(changed) == want {
			t.Fatalf("mutation %d was absent from the sample fingerprint", index)
		}
	}
}

func TestM5MigrationIsAdditiveImmutableAndNonCommercial(t *testing.T) {
	payload, err := os.ReadFile("../../../../migrations/control-plane/0020_m5_usage.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(payload))
	for _, required := range []string{"m5_usage_raw_facts", "m5_usage_bucket_facts", "m5_usage_anomalies", "m5_usage_storage_state", "source_fingerprint", "runtime_seconds", "average_cpu_millicores", "peak_cpu_millicores", "trend_cpu_millicores_per_second", "limit_cpu_millicores", "m5_reject_usage_mutation"} {
		if !strings.Contains(text, required) {
			t.Fatalf("0020 missing %q", required)
		}
	}
	for _, forbidden := range []string{"drop table", "truncate", "m5_billing", "price_", "invoice_", "payment_", "balance_"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("0020 contains out-of-scope or destructive token %q", forbidden)
		}
	}
}
