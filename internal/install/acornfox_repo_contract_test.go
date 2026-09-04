package install

import (
	"bytes"
	"strings"
	"testing"
)

func acornFoxRepoDigest(letter string) string { return strings.Repeat(letter, 64) }

func newAcornFoxRepoJournal() AcornFoxRepoJournalV1 {
	binding := acornFoxRepoDigest("a")
	return AcornFoxRepoJournalV1{
		SchemaVersion: AcornFoxRepoJournalV1Schema,
		TransactionID: "repo-install-test",
		Revision:      1,
		Phase:         AcornFoxRepoPrepared,
		BindingSHA256: binding,
		History: []AcornFoxRepoHistoryV1{{
			Revision: 1, To: AcornFoxRepoPrepared, EvidenceSHA256: binding,
		}},
	}
}

func advanceAcornFoxRepoJournal(t *testing.T, journal AcornFoxRepoJournalV1, phase AcornFoxRepoPhase, digest string) AcornFoxRepoJournalV1 {
	t.Helper()
	next := journal
	next.Revision++
	next.Phase = phase
	switch phase {
	case AcornFoxRepoLiveMaterialized:
		next.LiveTreeSHA256 = digest
	case AcornFoxRepoStaticVerified:
		next.OwnershipPlanSHA256 = acornFoxRepoDigest("c")
		next.StaticSetSHA256 = digest
	case AcornFoxRepoActivationWritten:
		next.ActivationSHA256 = digest
	case AcornFoxRepoActivePublished:
		next.ActivePointerSHA256 = digest
	case AcornFoxRepoCurrentPublished:
		next.CurrentPointerSHA256 = digest
	case AcornFoxRepoPreparedFinal:
		next.SubstrateReceiptSHA256 = digest
	default:
		t.Fatalf("unsupported test phase %q", phase)
	}
	next.History = append(next.History, AcornFoxRepoHistoryV1{Revision: next.Revision, From: journal.Phase, To: phase, EvidenceSHA256: acornFoxRepoPhaseEvidence(next, phase)})
	if err := next.Validate(); err != nil {
		t.Fatalf("advance %q: %v", phase, err)
	}
	return next
}

func TestAcornFoxRepoJournalPhaseEvidenceMatrix(t *testing.T) {
	journal := newAcornFoxRepoJournal()
	if err := journal.Validate(); err != nil {
		t.Fatal(err)
	}
	for index, phase := range []AcornFoxRepoPhase{AcornFoxRepoLiveMaterialized, AcornFoxRepoStaticVerified, AcornFoxRepoActivationWritten, AcornFoxRepoActivePublished, AcornFoxRepoCurrentPublished, AcornFoxRepoPreparedFinal} {
		journal = advanceAcornFoxRepoJournal(t, journal, phase, acornFoxRepoDigest([]string{"b", "c", "d", "e", "f", "a"}[index]))
	}
	if journal.Phase != AcornFoxRepoPreparedFinal || journal.NeedsRecovery || journal.SubstrateReceiptSHA256 == "" {
		t.Fatal("terminal repository journal was not fully evidenced")
	}
	tooEarly := newAcornFoxRepoJournal()
	tooEarly.LiveTreeSHA256 = acornFoxRepoDigest("b")
	if tooEarly.Validate() == nil {
		t.Fatal("early evidence was accepted")
	}
	terminal := journal
	terminal.Phase = AcornFoxRepoPrepared
	if terminal.Validate() == nil {
		t.Fatal("terminal evidence was accepted at prepared")
	}
}

func TestAcornFoxRepoJournalRecoveryKeepsLastConfirmedPhase(t *testing.T) {
	journal := advanceAcornFoxRepoJournal(t, newAcornFoxRepoJournal(), AcornFoxRepoLiveMaterialized, acornFoxRepoDigest("b"))
	recovery := journal
	recovery.Revision++
	recovery.NeedsRecovery = true
	recovery.Failure = &AcornFoxRepoFailureV1{Code: "write_unknown", Digest: acornFoxRepoDigest("f")}
	recovery.History = append(recovery.History, AcornFoxRepoHistoryV1{Revision: recovery.Revision, From: journal.Phase, To: journal.Phase, EvidenceSHA256: recovery.Failure.Digest})
	if err := recovery.Validate(); err != nil || recovery.Phase != AcornFoxRepoLiveMaterialized {
		t.Fatalf("recovery journal invalid: %v", err)
	}
	if ValidateAcornFoxRepoTransition(AcornFoxRepoPreparedFinal, AcornFoxRepoPreparedFinal) == nil {
		t.Fatal("repository terminal phase advanced")
	}
}

func TestAcornFoxRepoJournalRejectsNonCanonicalJSON(t *testing.T) {
	raw, err := MarshalAcornFoxRepoJournalV1(newAcornFoxRepoJournal())
	if err != nil {
		t.Fatal(err)
	}
	for name, malformed := range map[string][]byte{
		"whitespace": append(append([]byte(nil), raw...), ' '),
		"unknown":    append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...),
		"duplicate":  bytes.Replace(raw, []byte(`"revision":1`), []byte(`"revision":1,"revision":1`), 1),
		"null":       bytes.Replace(raw, []byte(`"binding_sha256":"`), []byte(`"binding_sha256":null,"x":"`), 1),
		"trailing":   append(append([]byte(nil), raw...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAcornFoxRepoJournalV1(malformed); err == nil {
				t.Fatal("malformed canonical journal was accepted")
			}
		})
	}
}

func TestAcornFoxRepoActivationIDIsBindingDeterministic(t *testing.T) {
	one, err := AcornFoxRepoActivationID(acornFoxRepoDigest("a"))
	if err != nil {
		t.Fatal(err)
	}
	two, err := AcornFoxRepoActivationID(acornFoxRepoDigest("a"))
	if err != nil || one != two || !validID(one) {
		t.Fatalf("activation id is not deterministic: %q %v", one, err)
	}
	if other, _ := AcornFoxRepoActivationID(acornFoxRepoDigest("b")); other == one {
		t.Fatal("distinct bindings produced one activation id")
	}
	if _, err := AcornFoxRepoActivationID("bad"); err == nil {
		t.Fatal("invalid binding produced activation id")
	}
}
