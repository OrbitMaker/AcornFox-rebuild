package install

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sha(c string) string { return strings.Repeat(c, 64) }

func activationFixture() ActivationV1 {
	return ActivationV1{1, "activation-1", "install", ReleaseV1{"release-2", "1.2.3", strings.Repeat("a", 40), "amd64", sha("b")}, DatabaseV1{"open_card", "0024", sha("c")}, sha("d"), time.Unix(1, 0).UTC(), "txn-1", &LegacyProjectionV1{"/opt/open-card/releases/release-2"}}
}

func journalFixture() UpgradeJournalV1 {
	now := time.Unix(1, 0).UTC()
	return UpgradeJournalV1{SchemaVersion: 1, TransactionID: "txn-1", Revision: 1, State: JournalPreflighted, CreatedAt: now, UpdatedAt: now, RequestedManifestSHA256: sha("e"), OldActivationID: "activation-old", OldActivationJSONSHA256: sha("f"), CandidateActivationID: "activation-1", CandidateDatabaseName: "open_card_act_0123456789abcdef", ServiceSnapshot: ServiceSnapshotV1{Edge: UnitSnapshotV1{Active: true, Enabled: true}, Agent: UnitSnapshotV1{Active: true}, Server: UnitSnapshotV1{Enabled: true}, Caddy: UnitSnapshotV1{Active: true, Enabled: true}}, History: []JournalTransitionV1{}}
}

func appendTransition(j *UpgradeJournalV1, to JournalState) {
	at := j.UpdatedAt.Add(time.Second)
	j.History = append(j.History, JournalTransitionV1{Revision: int64(len(j.History) + 2), From: j.State, To: to, At: at, EvidenceSHA256: sha("a")})
	j.State, j.Revision, j.UpdatedAt = to, int64(len(j.History)+1), at
}

func addEvidence(j *UpgradeJournalV1) {
	rank, err := j.effectiveEvidenceRank()
	if err != nil {
		panic(err)
	}
	if rank >= 2 {
		j.Snapshot = &ArtifactV1{Path: artifactPath(j.TransactionID, "control-plane.dump"), SHA256: sha("b"), Size: 1, SourceDatabase: "open_card"}
	}
	if rank >= 4 {
		j.CandidateDatabase = &DatabaseV1{Name: j.CandidateDatabaseName, Migration: "0024", SchemaMigrationsSHA256: sha("c")}
		j.Migration = &MigrationV1{From: "0023", To: "0024", ManifestSHA256: sha("d")}
	}
	if rank >= 5 {
		j.CandidateActivationJSONSHA256 = sha("e")
		j.Validation = &ArtifactV1{Path: artifactPath(j.TransactionID, "validation.json"), SHA256: sha("f"), Size: 1}
	}
	if failureState(j.State) {
		j.Failure = &FailureV1{Code: "upgrade_failed", Phase: j.History[len(j.History)-1].From, MessageDigest: sha("a")}
	}
}

func journalAt(state JournalState, legacy bool) UpgradeJournalV1 {
	j := journalFixture()
	if state == JournalPreflighted {
		return j
	}
	if legacy {
		appendTransition(&j, JournalLegacyProjected)
		if state == JournalLegacyProjected {
			return j
		}
	}
	for _, next := range []JournalState{JournalQuiesced, JournalSnapshotCreated, JournalCandidateDBReady, JournalMigrated, JournalValidated, JournalActiveSwitched, JournalHealthy, JournalEdgeArmed, JournalCommitted} {
		appendTransition(&j, next)
		if next == state {
			addEvidence(&j)
			return j
		}
	}
	panic("unsupported ordinary journal state")
}

func terminalJournal(state, from JournalState, legacy bool) UpgradeJournalV1 {
	j := journalAt(from, legacy)
	appendTransition(&j, state)
	addEvidence(&j)
	return j
}

func TestUpgradeJournalValidProgressiveStates(t *testing.T) {
	states := []JournalState{JournalPreflighted, JournalLegacyProjected, JournalQuiesced, JournalSnapshotCreated, JournalCandidateDBReady, JournalMigrated, JournalValidated, JournalActiveSwitched, JournalHealthy, JournalEdgeArmed, JournalCommitted}
	for _, legacy := range []bool{false, true} {
		for _, state := range states {
			if state == JournalLegacyProjected && !legacy {
				continue
			}
			j := journalAt(state, legacy)
			if err := j.Validate(); err != nil {
				t.Fatalf("legacy=%v state=%s: %v", legacy, state, err)
			}
			raw, err := MarshalUpgradeJournalV1(j)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = ParseUpgradeJournalV1(raw); err != nil {
				t.Fatalf("parse legacy=%v state=%s: %v", legacy, state, err)
			}
		}
	}
}

func TestUpgradeJournalTerminalEvidenceAndTransitions(t *testing.T) {
	for _, from := range []JournalState{JournalPreflighted, JournalLegacyProjected, JournalQuiesced, JournalSnapshotCreated, JournalCandidateDBReady, JournalMigrated, JournalValidated} {
		if err := terminalJournal(JournalAbortedPreSwitch, from, from != JournalPreflighted).Validate(); err != nil {
			t.Fatalf("abort from %s: %v", from, err)
		}
	}
	for _, from := range []JournalState{JournalActiveSwitched, JournalHealthy, JournalEdgeArmed} {
		j := terminalJournal(JournalRollbackSwitched, from, true)
		if err := j.Validate(); err != nil {
			t.Fatal(err)
		}
		appendTransition(&j, JournalRolledBack)
		addEvidence(&j)
		if err := j.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, from := range []JournalState{JournalPreflighted, JournalSnapshotCreated, JournalActiveSwitched} {
		j := journalAt(from, from != JournalPreflighted)
		appendTransition(&j, JournalRecoveryRequired)
		addEvidence(&j)
		if err := j.Validate(); err != nil {
			t.Fatalf("recovery from %s: %v", from, err)
		}
	}
	j := terminalJournal(JournalRollbackSwitched, JournalActiveSwitched, true)
	appendTransition(&j, JournalRecoveryRequired)
	addEvidence(&j)
	if err := j.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateJournalTransition(JournalPreflighted, JournalQuiesced); err != nil {
		t.Fatal(err)
	}
	if ValidateJournalTransition(JournalValidated, JournalQuiesced) == nil || ValidateJournalTransition(JournalCommitted, JournalHealthy) == nil {
		t.Fatal("illegal transition accepted")
	}
}

func TestUpgradeJournalRejectsMissingAndEarlyEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		j    UpgradeJournalV1
	}{
		{"missing snapshot", func() UpgradeJournalV1 { j := journalAt(JournalSnapshotCreated, false); j.Snapshot = nil; return j }()},
		{"early snapshot", func() UpgradeJournalV1 {
			j := journalAt(JournalPreflighted, false)
			j.Snapshot = &ArtifactV1{}
			return j
		}()},
		{"missing candidate", func() UpgradeJournalV1 { j := journalAt(JournalMigrated, false); j.CandidateDatabase = nil; return j }()},
		{"early migration", func() UpgradeJournalV1 {
			j := journalAt(JournalCandidateDBReady, false)
			j.Migration = &MigrationV1{}
			return j
		}()},
		{"missing validation", func() UpgradeJournalV1 { j := journalAt(JournalValidated, false); j.Validation = nil; return j }()},
		{"early validation digest", func() UpgradeJournalV1 {
			j := journalAt(JournalMigrated, false)
			j.CandidateActivationJSONSHA256 = sha("z")
			return j
		}()},
		{"happy failure", func() UpgradeJournalV1 { j := journalAt(JournalValidated, false); j.Failure = &FailureV1{}; return j }()},
		{"missing terminal failure", func() UpgradeJournalV1 {
			j := terminalJournal(JournalAbortedPreSwitch, JournalQuiesced, false)
			j.Failure = nil
			return j
		}()},
		{"nil history placeholder", func() UpgradeJournalV1 {
			j := journalAt(JournalPreflighted, false)
			j.History = nil
			return j
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.j.Validate(); err == nil {
				t.Fatal("invalid journal accepted")
			}
		})
	}
}

func TestUpgradeJournalPreUpgradePreviousPair(t *testing.T) {
	j := journalAt(JournalPreflighted, false)
	j.PreUpgradePreviousActivationID, j.PreUpgradePreviousActivationJSONSHA256 = "activation-previous", sha("a")
	raw, err := MarshalUpgradeJournalV1(j)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseUpgradeJournalV1(raw); err != nil || got.PreUpgradePreviousActivationID != j.PreUpgradePreviousActivationID {
		t.Fatal(err)
	}
	j.PreUpgradePreviousActivationJSONSHA256 = ""
	if err := j.Validate(); err == nil {
		t.Fatal("unpaired previous baseline accepted")
	}
}

func TestUpgradeJournalPreviousBaselineAbsentAndPresentRoundTrip(t *testing.T) {
	for _, previous := range []bool{false, true} {
		j := journalFixture()
		if previous {
			j.PreUpgradePreviousActivationID = "activation-previous"
			j.PreUpgradePreviousActivationJSONSHA256 = sha("a")
		}
		raw, err := MarshalUpgradeJournalV1(j)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseUpgradeJournalV1(raw)
		if err != nil || (got.PreUpgradePreviousActivationID != j.PreUpgradePreviousActivationID) || (got.PreUpgradePreviousActivationJSONSHA256 != j.PreUpgradePreviousActivationJSONSHA256) {
			t.Fatalf("previous=%v got=%+v err=%v", previous, got, err)
		}
	}
}

func TestUpgradeJournalRejectsBrokenHistory(t *testing.T) {
	valid := journalAt(JournalValidated, true)
	for _, tc := range []struct {
		name string
		edit func(*UpgradeJournalV1)
	}{
		{"revision", func(j *UpgradeJournalV1) { j.History[0].Revision++ }}, {"chain", func(j *UpgradeJournalV1) { j.History[1].From = JournalQuiesced }}, {"time", func(j *UpgradeJournalV1) { j.History[1].At = j.CreatedAt.Add(-time.Second) }}, {"evidence", func(j *UpgradeJournalV1) { j.History[1].EvidenceSHA256 = "not-a-digest" }}, {"state", func(j *UpgradeJournalV1) { j.State = JournalHealthy }}, {"updated", func(j *UpgradeJournalV1) { j.UpdatedAt = j.CreatedAt }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := valid
			j.History = append([]JournalTransitionV1(nil), valid.History...)
			tc.edit(&j)
			if err := j.Validate(); err == nil {
				t.Fatal("broken history accepted")
			}
		})
	}
}

func TestServiceSnapshotCanonicalDigest(t *testing.T) {
	snapshot := journalFixture().ServiceSnapshot
	first := CanonicalServiceSnapshotSHA256(snapshot)
	if first != CanonicalServiceSnapshotSHA256(snapshot) || !validSHA(first) {
		t.Fatal("non-deterministic digest")
	}
	snapshot.Caddy.Active = !snapshot.Caddy.Active
	if CanonicalServiceSnapshotSHA256(snapshot) == first {
		t.Fatal("service change did not change digest")
	}
}

func TestUpgradeJournalStrictJSONAndFailureSafety(t *testing.T) {
	j := terminalJournal(JournalAbortedPreSwitch, JournalSnapshotCreated, false)
	raw, err := MarshalUpgradeJournalV1(j)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseUpgradeJournalV1(raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "message\"") || strings.Contains(string(raw), "database-password") {
		t.Fatal("failure serialization can expose raw diagnostics")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "service_snapshot")
	missingService, _ := json.Marshal(fields)
	preflight, err := MarshalUpgradeJournalV1(journalAt(JournalPreflighted, false))
	if err != nil {
		t.Fatal(err)
	}
	var earlyFields map[string]json.RawMessage
	if err := json.Unmarshal(preflight, &earlyFields); err != nil {
		t.Fatal(err)
	}
	earlyFields["snapshot"] = json.RawMessage(`{"path":"/var/lib/open-card/upgrade-artifacts/txn-1/control-plane.dump","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1,"source_database":"open_card"}`)
	earlySnapshot, _ := json.Marshal(earlyFields)
	for _, bad := range [][]byte{[]byte(`{"schema_version":1,"schema_version":1}`), append(raw, []byte(" {}")...), []byte(`{"unknown":1}`), missingService, earlySnapshot} {
		if _, err := ParseUpgradeJournalV1(bad); err == nil {
			t.Fatal("unsafe journal JSON accepted")
		}
	}
}

func TestStrictContracts(t *testing.T) {
	raw, err := MarshalActivationV1(activationFixture())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseActivationV1(raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{[]byte(`{"schema_version":1,"schema_version":1}`), append(raw, []byte(" {}")...), []byte(`{"unknown":1}`)} {
		if _, err = ParseActivationV1(bad); err == nil {
			t.Fatal("unsafe activation JSON accepted")
		}
	}
}

func TestDatabaseEnvPercentEncoded(t *testing.T) {
	dsn := "postgresql://us%40er:p%2Fass@localhost:5432/open%2Dcard?sslmode=disable"
	raw, err := FormatDatabaseEnv(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseDatabaseEnv(raw); err != nil || got != dsn {
		t.Fatal(err)
	}
	for _, bad := range []string{"postgres://u:p@h/db name", "postgres://u:p@h/db#x", "postgres://u:p@h/", "postgres://u:p@h/db\\x"} {
		if _, err := FormatDatabaseEnv(bad); err == nil {
			t.Fatal("bad dsn")
		}
	}
}
