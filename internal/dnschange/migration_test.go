package dnschange

import (
	"os"
	"strings"
	"testing"
)

func TestMigrationHasLocalLedgerWithoutCredentialOrProviderWrite(t *testing.T) {
	payload, err := os.ReadFile("../../migrations/control-plane/0024_dns_change_ledger.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(payload))
	for _, required := range []string{"dns_change_owned_records", "dns_change_plans", "dns_change_reconcile_state", "unique (provider, domain_id, record_id)"} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing %q", required)
		}
	}
	for _, forbidden := range []string{"secretid", "secretkey", "tccli", "createrecord", "modifyrecord", "deleterecord"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("forbidden %q", forbidden)
		}
	}
}
