package install

import (
	"strings"
	"testing"
	"time"
)

func sha(c string) string { return strings.Repeat(c, 64) }
func activationFixture() ActivationV1 {
	return ActivationV1{1, "activation-1", "install", ReleaseV1{"release-2", "1.2.3", sha("a"), "amd64", sha("b")}, DatabaseV1{"open_card", "0024", sha("c")}, sha("d"), time.Unix(1, 0).UTC(), "txn-1", &LegacyProjectionV1{"/opt/open-card/releases/release-2"}}
}
func journalFixture() UpgradeJournalV1 {
	a := activationFixture()
	return UpgradeJournalV1{1, "txn-1", 1, JournalPreflighted, time.Unix(1, 0).UTC(), time.Unix(1, 0).UTC(), sha("e"), "activation-old", sha("f"), a.ActivationID, sha("a"), a.Database, ArtifactV1{artifactPath("txn-1", "snapshot.sql.zst"), sha("b"), 1, "open_card"}, MigrationV1{"0023", "0024", sha("c")}, ArtifactV1{artifactPath("txn-1", "validation.json"), sha("d"), 1, ""}, sha("e"), nil, nil}
}
func TestStrictContracts(t *testing.T) {
	a := activationFixture()
	raw, e := MarshalActivationV1(a)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ParseActivationV1(raw); e != nil {
		t.Fatal(e)
	}
	if _, e = MarshalUpgradeJournalV1(journalFixture()); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{[]byte(`{"schema_version":1,"schema_version":1}`), append(raw, []byte(" {}")...), []byte(`{"unknown":1}`)} {
		if _, e = ParseActivationV1(bad); e == nil {
			t.Fatal("unsafe JSON accepted")
		}
	}
	for _, p := range [][2]JournalState{{JournalHealthy, JournalEdgeArmed}, {JournalEdgeArmed, JournalCommitted}, {JournalActiveSwitched, JournalRollbackSwitched}, {JournalRollbackSwitched, JournalRolledBack}} {
		if e = ValidateJournalTransition(p[0], p[1]); e != nil {
			t.Fatal(e)
		}
	}
	if ValidateJournalTransition(JournalHealthy, JournalCommitted) == nil || ValidateJournalTransition(JournalCommitted, JournalHealthy) == nil {
		t.Fatal("illegal transition")
	}
}
func TestDatabaseEnvPercentEncoded(t *testing.T) {
	dsn := "postgresql://us%40er:p%2Fass@localhost:5432/open%2Dcard?sslmode=disable"
	raw, e := FormatDatabaseEnv(dsn)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := ParseDatabaseEnv(raw); e != nil || got != dsn {
		t.Fatal(e)
	}
	for _, bad := range []string{"postgres://u:p@h/db name", "postgres://u:p@h/db#x", "postgres://u:p@h/", "postgres://u:p@h/db\\x"} {
		if _, e := FormatDatabaseEnv(bad); e == nil {
			t.Fatal("bad dsn")
		}
	}
}
