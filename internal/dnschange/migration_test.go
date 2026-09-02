package dnschange

import (
	"os"
	"strings"
	"testing"
)

func TestMigrationHasLocalLedgerWithoutCredentialOrProviderWrite(t *testing.T) {
	payload, err := os.ReadFile("../../migrations/control-plane/0030_dns_change_provider_neutral.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(payload))
	for _, required := range []string{"dns_change_owned_records", "installation_id", "zone_id", "record_id type text", "record_type in ('a','cname','txt')", "legacy-dnspod"} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing %q", required)
		}
	}
	for _, forbidden := range []string{"secretid", "secretkey", "accesskey", "tccli", "createrecord", "modifyrecord", "deleterecord", "adddomainrecord", "updatedomainrecord", "deletedomainrecord"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("forbidden %q", forbidden)
		}
	}
}

func TestExecutionMigrationPersistsOnlyPhaseAndChangeFingerprint(t *testing.T) {
	payload, err := os.ReadFile("../../migrations/control-plane/0032_dns_change_execution.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(payload))
	for _, required := range []string{"dns_change_execution_steps", "dns_change_execution_scopes", "request_fingerprint", "write_started", "reconcile_required", "applied"} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing %q", required)
		}
	}
	for _, forbidden := range []string{"accesskey", "secret", "authorization", "endpoint", "adddomainrecord", "updatedomainrecord", "deletedomainrecord"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("forbidden %q", forbidden)
		}
	}
}
