package install

import (
	"bytes"
	"strings"
	"testing"
)

func acornFoxRepoDigest(letter string) string { return strings.Repeat(letter, 64) }

func newAcornFoxRepoJournal() AcornFoxRepoJournalV1 {
	binding := acornFoxRepoDigest("a")
	substrate := acornFoxRepoDigest("b")
	prepared, _ := AcornFoxRepoPreparedEvidence(binding, substrate)
	return AcornFoxRepoJournalV1{
		SchemaVersion:          AcornFoxRepoJournalV1Schema,
		TransactionID:          "repo-install-test",
		Revision:               1,
		Phase:                  AcornFoxRepoPrepared,
		BindingSHA256:          binding,
		SubstrateReceiptSHA256: substrate,
		History: []AcornFoxRepoHistoryV1{{
			Revision: 1, Kind: AcornFoxRepoHistoryAdvance, To: AcornFoxRepoPrepared, EvidenceSHA256: prepared,
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
		// The substrate receipt is part of PREPARED authority and immutable.
	default:
		t.Fatalf("unsupported test phase %q", phase)
	}
	next.History = append(next.History, AcornFoxRepoHistoryV1{Revision: next.Revision, Kind: AcornFoxRepoHistoryAdvance, From: journal.Phase, To: phase, EvidenceSHA256: acornFoxRepoPhaseEvidence(next, phase)})
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
	journal := advanceAcornFoxRepoJournal(t, newAcornFoxRepoJournal(), AcornFoxRepoLiveMaterialized, acornFoxRepoDigest("c"))
	recovery := journal
	recovery.Revision++
	recovery.NeedsRecovery = true
	recovery.Failure = &AcornFoxRepoFailureV1{Code: "write_unknown", Digest: acornFoxRepoDigest("f")}
	recovery.History = append(recovery.History, AcornFoxRepoHistoryV1{Revision: recovery.Revision, Kind: AcornFoxRepoHistoryFailure, From: journal.Phase, To: journal.Phase, EvidenceSHA256: recovery.Failure.Digest})
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

func TestAcornFoxRepoPreparedAndFinalEvidenceBindEveryDigest(t *testing.T) {
	journal := newAcornFoxRepoJournal()
	prepared, err := AcornFoxRepoPreparedEvidence(journal.BindingSHA256, journal.SubstrateReceiptSHA256)
	if err != nil || prepared != journal.History[0].EvidenceSHA256 {
		t.Fatalf("prepared evidence = %q, %v", prepared, err)
	}
	otherSubstrate := journal
	otherSubstrate.SubstrateReceiptSHA256 = acornFoxRepoDigest("c")
	if otherSubstrate.Validate() == nil {
		t.Fatal("same binding with different substrate authority was accepted")
	}
	for _, phase := range []AcornFoxRepoPhase{AcornFoxRepoLiveMaterialized, AcornFoxRepoStaticVerified, AcornFoxRepoActivationWritten, AcornFoxRepoActivePublished, AcornFoxRepoCurrentPublished, AcornFoxRepoPreparedFinal} {
		journal = advanceAcornFoxRepoJournal(t, journal, phase, acornFoxRepoDigest("d"))
	}
	final, err := AcornFoxRepoFinalEvidence(journal)
	if err != nil || final != journal.History[len(journal.History)-1].EvidenceSHA256 {
		t.Fatalf("final aggregate = %q, %v", final, err)
	}
	for _, mutate := range []func(*AcornFoxRepoJournalV1){
		func(j *AcornFoxRepoJournalV1) { j.LiveTreeSHA256 = acornFoxRepoDigest("e") },
		func(j *AcornFoxRepoJournalV1) { j.OwnershipPlanSHA256 = acornFoxRepoDigest("e") },
		func(j *AcornFoxRepoJournalV1) { j.StaticSetSHA256 = acornFoxRepoDigest("e") },
		func(j *AcornFoxRepoJournalV1) { j.ActivationSHA256 = acornFoxRepoDigest("e") },
		func(j *AcornFoxRepoJournalV1) { j.ActivePointerSHA256 = acornFoxRepoDigest("e") },
		func(j *AcornFoxRepoJournalV1) { j.CurrentPointerSHA256 = acornFoxRepoDigest("e") },
	} {
		changed := journal
		mutate(&changed)
		if changedFinal, err := AcornFoxRepoFinalEvidence(changed); err != nil || changedFinal == final {
			t.Fatalf("aggregate did not bind changed field: %q, %v", changedFinal, err)
		}
	}
}

func TestAcornFoxRepoHistoryKindsAreClosed(t *testing.T) {
	journal := advanceAcornFoxRepoJournal(t, newAcornFoxRepoJournal(), AcornFoxRepoLiveMaterialized, acornFoxRepoDigest("c"))
	badAdvance := journal
	badAdvance.Revision++
	badAdvance.Phase = AcornFoxRepoStaticVerified
	badAdvance.NeedsRecovery = true
	badAdvance.Failure = &AcornFoxRepoFailureV1{Code: "bad", Digest: acornFoxRepoDigest("f")}
	badAdvance.OwnershipPlanSHA256, badAdvance.StaticSetSHA256 = acornFoxRepoDigest("d"), acornFoxRepoDigest("e")
	badAdvance.History = append(badAdvance.History, AcornFoxRepoHistoryV1{Revision: badAdvance.Revision, Kind: AcornFoxRepoHistoryAdvance, From: journal.Phase, To: badAdvance.Phase, EvidenceSHA256: badAdvance.StaticSetSHA256})
	if badAdvance.Validate() == nil {
		t.Fatal("advance while recovery was accepted")
	}
	failure := journal
	failure.Revision++
	failure.NeedsRecovery = true
	failure.Failure = &AcornFoxRepoFailureV1{Code: "write_unknown", Digest: acornFoxRepoDigest("f")}
	failure.History = append(failure.History, AcornFoxRepoHistoryV1{Revision: failure.Revision, Kind: AcornFoxRepoHistoryFailure, From: journal.Phase, To: journal.Phase, EvidenceSHA256: failure.Failure.Digest})
	if err := failure.Validate(); err != nil {
		t.Fatal(err)
	}
	recovered := failure
	recovered.Revision++
	recovered.NeedsRecovery, recovered.Failure = false, nil
	recovered.History = append(recovered.History, AcornFoxRepoHistoryV1{Revision: recovered.Revision, Kind: AcornFoxRepoHistoryRecovered, From: failure.Phase, To: failure.Phase, EvidenceSHA256: acornFoxRepoDigest("e")})
	if err := recovered.Validate(); err != nil {
		t.Fatal(err)
	}
}
