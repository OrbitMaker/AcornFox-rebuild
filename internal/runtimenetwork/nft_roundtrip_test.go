package runtimenetwork

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The fixture is unmodified `nft -j list table inet acornfox_runtime_guard`
// output captured by the parent task on 2026-09-06 using nft 1.0.9 in a private
// network namespace on its authorized Aliyun fixture. It did not touch host
// rules. Its all-zero owner is a test value, not production ownership evidence.
func TestActualNFT109RoundTripMatchesCompiledPolicy(t *testing.T) {
	raw, err := os.ReadFile("testdata/nft-1.0.9-runtime-guard.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := fingerprint(raw)
	want, wantErr := policyFingerprint(strings.Repeat("0", 64))
	if err != nil || wantErr != nil || got != want {
		t.Fatalf("nft 1.0.9 differs from compiled structure: got=%s want=%s errors=%v/%v", got, want, err, wantErr)
	}
	// Changing an action or rule precedence must still fail; matching the
	// kernel format must not broaden fingerprint normalization.
	changed := bytes.Replace(raw, []byte(`"drop":null`), []byte(`"accept":null`), 1)
	if bytes.Equal(raw, changed) {
		changed = bytes.Replace(raw, []byte(`"drop": null`), []byte(`"accept": null`), 1)
	}
	if bytes.Equal(raw, changed) {
		t.Fatal("ineffective action mutation")
	}
	if hash, err := fingerprint(changed); err == nil && hash == want {
		t.Fatal("accepted altered rule action")
	}
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	first, second := -1, -1
	for i, entry := range doc.NFTables {
		if entry["rule"] != nil {
			if first < 0 {
				first = i
			} else {
				second = i
				break
			}
		}
	}
	if second < 0 {
		t.Fatal("missing rule order fixture")
	}
	doc.NFTables[first], doc.NFTables[second] = doc.NFTables[second], doc.NFTables[first]
	reordered, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if hash, err := fingerprint(reordered); err == nil && hash == want {
		t.Fatal("accepted reordered rules")
	}
}
