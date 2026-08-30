package install

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func bootstrapJournalAt(t *testing.T, state BootstrapState) BootstrapJournalV1 {
	t.Helper()
	states := []BootstrapState{BootstrapPrepared, BootstrapCandidateDBCreated, BootstrapMigrated0024, BootstrapActivationWritten, BootstrapPointersPublished, BootstrapInternalHealthy, BootstrapEdgeHealthy, BootstrapCommitted}
	created := time.Unix(1, 0).UTC()
	j := BootstrapJournalV1{
		SchemaVersion: 1, TransactionID: "bootstrap-txn-1", Revision: 1, State: BootstrapPrepared,
		CreatedAt: created, UpdatedAt: created, InstallationIDSHA256: strings.Repeat("a", 64),
		Release:               ReleaseV1{ID: "release-rc2", Version: Gate6CandidateVersion, SourceCommit: strings.Repeat("b", 40), Architecture: "amd64", ManifestSHA256: strings.Repeat("c", 64)},
		CandidateActivationID: "activation-rc2", CandidateDatabaseName: "open_card_act_0123456789abcdef", MarkerTransactionID: "bootstrap-txn-1",
		History: []BootstrapHistoryV1{{Revision: 1, From: "", To: BootstrapPrepared, At: created, EvidenceSHA256: strings.Repeat("1", 64)}},
	}
	if state != BootstrapPrepared {
		for index, next := range states[1:] {
			from := states[index]
			at := created.Add(time.Duration(index+1) * time.Second)
			j.Revision++
			j.State, j.UpdatedAt = next, at
			j.History = append(j.History, BootstrapHistoryV1{Revision: j.Revision, From: from, To: next, At: at, EvidenceSHA256: strings.Repeat(string(rune('2'+index)), 64)})
			if next == state {
				break
			}
		}
	}
	rank := bootstrapRank(j.State)
	if rank >= 2 {
		j.CandidateDatabaseSchemaSHA256 = strings.Repeat("d", 64)
	}
	if rank >= 3 {
		j.ActivationJSONSHA256 = strings.Repeat("e", 64)
	}
	if rank >= 4 {
		j.PointerStateSHA256 = strings.Repeat("f", 64)
	}
	if rank >= 5 {
		j.InternalHealthSHA256 = strings.Repeat("8", 64)
		j.ServiceSnapshot = &ServiceSnapshotV1{Edge: UnitSnapshotV1{Active: true, Enabled: true}, Agent: UnitSnapshotV1{Active: true, Enabled: true}, Server: UnitSnapshotV1{Active: true, Enabled: true}, Caddy: UnitSnapshotV1{Active: true, Enabled: true}, BuildKit: UnitSnapshotV1{Active: true, Enabled: true}}
	}
	if rank >= 6 {
		j.EdgeHealthSHA256 = strings.Repeat("9", 64)
	}
	return j
}

func TestBootstrapJournalProgressiveStatesAndStrictRoundTrip(t *testing.T) {
	for _, state := range []BootstrapState{BootstrapPrepared, BootstrapCandidateDBCreated, BootstrapMigrated0024, BootstrapActivationWritten, BootstrapPointersPublished, BootstrapInternalHealthy, BootstrapEdgeHealthy, BootstrapCommitted} {
		t.Run(string(state), func(t *testing.T) {
			journal := bootstrapJournalAt(t, state)
			raw, err := MarshalBootstrapJournalV1(journal)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseBootstrapJournalV1(raw)
			if err != nil || parsed.State != state || parsed.Revision != journal.Revision {
				t.Fatalf("round trip state=%s parsed=%#v err=%v", state, parsed, err)
			}
		})
	}
	journal := bootstrapJournalAt(t, BootstrapActivationWritten)
	at := journal.UpdatedAt.Add(time.Second)
	journal.Revision++
	journal.State = BootstrapRecoveryRequired
	journal.UpdatedAt = at
	journal.Failure = &BootstrapFailureV1{Code: "activation_write_unknown", Digest: strings.Repeat("7", 64)}
	journal.History = append(journal.History, BootstrapHistoryV1{Revision: journal.Revision, From: BootstrapActivationWritten, To: BootstrapRecoveryRequired, At: at, EvidenceSHA256: strings.Repeat("6", 64)})
	if err := journal.Validate(); err != nil {
		t.Fatalf("recovery journal rejected: %v", err)
	}
}

func TestBootstrapJournalRejectsEvidenceHistoryAndTerminalDrift(t *testing.T) {
	for name, mutate := range map[string]func(*BootstrapJournalV1){
		"missing-db":       func(j *BootstrapJournalV1) { j.CandidateDatabaseSchemaSHA256 = "" },
		"early-pointer":    func(j *BootstrapJournalV1) { j.PointerStateSHA256 = strings.Repeat("1", 64) },
		"missing-pointer":  func(j *BootstrapJournalV1) { j.PointerStateSHA256 = "" },
		"missing-internal": func(j *BootstrapJournalV1) { j.InternalHealthSHA256, j.ServiceSnapshot = "", nil },
		"missing-edge":     func(j *BootstrapJournalV1) { j.EdgeHealthSHA256 = "" },
		"revision":         func(j *BootstrapJournalV1) { j.Revision++ },
		"history-from":     func(j *BootstrapJournalV1) { j.History[1].From = BootstrapCandidateDBCreated },
		"history-state":    func(j *BootstrapJournalV1) { j.State = BootstrapPrepared },
		"history-time":     func(j *BootstrapJournalV1) { j.History[1].At = j.CreatedAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			state := BootstrapCommitted
			if name == "early-pointer" {
				state = BootstrapPrepared
			} else if name == "missing-db" {
				state = BootstrapMigrated0024
			} else if name == "missing-pointer" {
				state = BootstrapPointersPublished
			} else if name == "missing-internal" {
				state = BootstrapInternalHealthy
			} else if name == "missing-edge" {
				state = BootstrapEdgeHealthy
			}
			journal := bootstrapJournalAt(t, state)
			mutate(&journal)
			if err := journal.Validate(); err == nil {
				t.Fatal("invalid bootstrap journal accepted")
			}
		})
	}
	if ValidateBootstrapTransition(BootstrapCommitted, BootstrapRecoveryRequired) == nil || ValidateBootstrapTransition(BootstrapRecoveryRequired, BootstrapPrepared) == nil {
		t.Fatal("terminal bootstrap state accepted a transition")
	}
	unknown := BootstrapState("UNKNOWN")
	if ValidateBootstrapTransition(unknown, BootstrapPrepared) == nil || ValidateBootstrapTransition(unknown, BootstrapRecoveryRequired) == nil {
		t.Fatal("unknown bootstrap state accepted a transition")
	}
}

func TestBootstrapJournalStrictJSONAndSecretFreeShape(t *testing.T) {
	raw, err := MarshalBootstrapJournalV1(bootstrapJournalAt(t, BootstrapCommitted))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"postgresql://", "password", "OPEN_CARD_DATABASE_URL", "command", "/opt/open-card"} {
		if bytes.Contains(bytes.ToLower(raw), bytes.ToLower([]byte(forbidden))) {
			t.Fatalf("bootstrap journal contains %q", forbidden)
		}
	}
	for name, candidate := range map[string][]byte{
		"duplicate": append([]byte(`{"schema_version":1,`), raw[1:]...),
		"unknown":   append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...),
		"trailing":  append(raw, []byte(` {}`)...),
		"null":      bytes.Replace(raw, []byte(`"candidate_database_schema_sha256":"`+strings.Repeat("d", 64)+`"`), []byte(`"candidate_database_schema_sha256":null`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBootstrapJournalV1(candidate); err == nil {
				t.Fatal("invalid bootstrap JSON accepted")
			}
		})
	}
}
