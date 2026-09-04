package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

type AcornFoxRepoPhase string

const (
	AcornFoxRepoPrepared          AcornFoxRepoPhase = "PREPARED"
	AcornFoxRepoLiveMaterialized  AcornFoxRepoPhase = "LIVE_MATERIALIZED"
	AcornFoxRepoStaticVerified    AcornFoxRepoPhase = "STATIC_VERIFIED"
	AcornFoxRepoActivationWritten AcornFoxRepoPhase = "ACTIVATION_WRITTEN"
	AcornFoxRepoActivePublished   AcornFoxRepoPhase = "ACTIVE_PUBLISHED"
	AcornFoxRepoCurrentPublished  AcornFoxRepoPhase = "CURRENT_PUBLISHED"
	AcornFoxRepoPreparedFinal     AcornFoxRepoPhase = "REPO_PREPARED"
)

type AcornFoxRepoHistoryKind string

const (
	AcornFoxRepoHistoryAdvance   AcornFoxRepoHistoryKind = "advance"
	AcornFoxRepoHistoryFailure   AcornFoxRepoHistoryKind = "failure"
	AcornFoxRepoHistoryRecovered AcornFoxRepoHistoryKind = "recovered"
)

const AcornFoxRepoJournalV1Schema = 1

// AcornFoxRepoFailureV1 is deliberately diagnostic-digest-only. Paths,
// credentials, DSNs, and host configuration have no representation.
type AcornFoxRepoFailureV1 struct {
	Code   string `json:"code"`
	Digest string `json:"digest"`
}

type AcornFoxRepoHistoryV1 struct {
	Revision       int64                   `json:"revision"`
	Kind           AcornFoxRepoHistoryKind `json:"kind"`
	From           AcornFoxRepoPhase       `json:"from"`
	To             AcornFoxRepoPhase       `json:"to"`
	EvidenceSHA256 string                  `json:"evidence_sha256"`
}

// AcornFoxRepoJournalV1 ends at repository preparation only. It has neither
// a host lifecycle state nor a host-side authority field.
type AcornFoxRepoJournalV1 struct {
	SchemaVersion          int                     `json:"schema_version"`
	TransactionID          string                  `json:"transaction_id"`
	Revision               int64                   `json:"revision"`
	Phase                  AcornFoxRepoPhase       `json:"phase"`
	NeedsRecovery          bool                    `json:"needs_recovery"`
	BindingSHA256          string                  `json:"binding_sha256"`
	SubstrateReceiptSHA256 string                  `json:"substrate_receipt_sha256"`
	LiveTreeSHA256         string                  `json:"live_tree_sha256,omitempty"`
	OwnershipPlanSHA256    string                  `json:"ownership_plan_sha256,omitempty"`
	StaticSetSHA256        string                  `json:"static_set_sha256,omitempty"`
	ActivationSHA256       string                  `json:"activation_sha256,omitempty"`
	ActivePointerSHA256    string                  `json:"active_pointer_sha256,omitempty"`
	CurrentPointerSHA256   string                  `json:"current_pointer_sha256,omitempty"`
	Failure                *AcornFoxRepoFailureV1  `json:"failure,omitempty"`
	History                []AcornFoxRepoHistoryV1 `json:"history"`
}

func acornFoxRepoRank(phase AcornFoxRepoPhase) int {
	for index, candidate := range []AcornFoxRepoPhase{AcornFoxRepoPrepared, AcornFoxRepoLiveMaterialized, AcornFoxRepoStaticVerified, AcornFoxRepoActivationWritten, AcornFoxRepoActivePublished, AcornFoxRepoCurrentPublished, AcornFoxRepoPreparedFinal} {
		if phase == candidate {
			return index
		}
	}
	return -1
}

func acornFoxRepoEvidence(domain string, digests ...string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	for _, digest := range digests {
		_, _ = hash.Write([]byte(digest))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// AcornFoxRepoPreparedEvidence binds the two authorities required before any
// repository work starts. The exact byte sequence is fixed by this function.
func AcornFoxRepoPreparedEvidence(bindingSHA256, substrateReceiptSHA256 string) (string, error) {
	if !validSHA(bindingSHA256) || !validSHA(substrateReceiptSHA256) {
		return "", errors.New("AcornFox repository prepared evidence inputs are invalid")
	}
	return acornFoxRepoEvidence("acornfox-repo-prepared-v1\x00", bindingSHA256, substrateReceiptSHA256), nil
}

// AcornFoxRepoFinalEvidence covers every immutable digest accepted by the
// closed repository protocol, preventing a final receipt from omitting one.
func AcornFoxRepoFinalEvidence(journal AcornFoxRepoJournalV1) (string, error) {
	for _, digest := range []string{journal.BindingSHA256, journal.SubstrateReceiptSHA256, journal.LiveTreeSHA256, journal.OwnershipPlanSHA256, journal.StaticSetSHA256, journal.ActivationSHA256, journal.ActivePointerSHA256, journal.CurrentPointerSHA256} {
		if !validSHA(digest) {
			return "", errors.New("AcornFox repository final evidence input is invalid")
		}
	}
	return acornFoxRepoEvidence("acornfox-repo-final-v1\x00", journal.BindingSHA256, journal.SubstrateReceiptSHA256, journal.LiveTreeSHA256, journal.OwnershipPlanSHA256, journal.StaticSetSHA256, journal.ActivationSHA256, journal.ActivePointerSHA256, journal.CurrentPointerSHA256), nil
}

func AcornFoxRepoActivationID(bindingSHA256 string) (string, error) {
	if !validSHA(bindingSHA256) {
		return "", errors.New("AcornFox repository binding digest is invalid")
	}
	return "acornfox-repo-" + acornFoxRepoEvidence("acornfox-repo-activation-v1\x00", bindingSHA256), nil
}

func (j AcornFoxRepoJournalV1) Validate() error {
	if j.SchemaVersion != AcornFoxRepoJournalV1Schema || !validID(j.TransactionID) || j.Revision < 1 || acornFoxRepoRank(j.Phase) < 0 || !validSHA(j.BindingSHA256) || !validSHA(j.SubstrateReceiptSHA256) || int64(len(j.History)) != j.Revision || len(j.History) == 0 {
		return errors.New("AcornFox repository journal identity is invalid")
	}
	prepared, _ := AcornFoxRepoPreparedEvidence(j.BindingSHA256, j.SubstrateReceiptSHA256)
	phase := AcornFoxRepoPrepared
	recovering := false
	for index, entry := range j.History {
		if entry.Revision != int64(index+1) || !validSHA(entry.EvidenceSHA256) {
			return errors.New("AcornFox repository history entry is invalid")
		}
		if index == 0 {
			if entry.Kind != AcornFoxRepoHistoryAdvance || entry.From != "" || entry.To != AcornFoxRepoPrepared || entry.EvidenceSHA256 != prepared {
				return errors.New("AcornFox repository initial history is invalid")
			}
			continue
		}
		switch entry.Kind {
		case AcornFoxRepoHistoryAdvance:
			if recovering || entry.From != phase || ValidateAcornFoxRepoTransition(phase, entry.To) != nil || entry.EvidenceSHA256 != acornFoxRepoPhaseEvidence(j, entry.To) {
				return errors.New("AcornFox repository advance history is invalid")
			}
			phase = entry.To
		case AcornFoxRepoHistoryFailure:
			if recovering || entry.From != phase || entry.To != phase {
				return errors.New("AcornFox repository failure history is invalid")
			}
			recovering = true
		case AcornFoxRepoHistoryRecovered:
			if !recovering || entry.From != phase || entry.To != phase {
				return errors.New("AcornFox repository recovery history is invalid")
			}
			recovering = false
		default:
			return errors.New("AcornFox repository history kind is invalid")
		}
	}
	if phase != j.Phase || recovering != j.NeedsRecovery || (j.NeedsRecovery && (j.Failure == nil || !validID(j.Failure.Code) || !validSHA(j.Failure.Digest))) || (!j.NeedsRecovery && j.Failure != nil) {
		return errors.New("AcornFox repository recovery state is invalid")
	}
	if j.NeedsRecovery && j.History[len(j.History)-1].EvidenceSHA256 != j.Failure.Digest {
		return errors.New("AcornFox repository failure evidence is invalid")
	}
	if j.Phase == AcornFoxRepoPreparedFinal && (j.NeedsRecovery || j.Failure != nil) {
		return errors.New("AcornFox repository final phase cannot recover")
	}
	return j.validateEvidence()
}

func (j AcornFoxRepoJournalV1) validateEvidence() error {
	rank := acornFoxRepoRank(j.Phase)
	for _, check := range []struct {
		at           int
		value, label string
	}{{1, j.LiveTreeSHA256, "live tree"}, {2, j.OwnershipPlanSHA256, "ownership plan"}, {2, j.StaticSetSHA256, "static set"}, {3, j.ActivationSHA256, "activation"}, {4, j.ActivePointerSHA256, "active pointer"}, {5, j.CurrentPointerSHA256, "current pointer"}} {
		if check.at <= rank && !validSHA(check.value) {
			return fmt.Errorf("AcornFox repository %s evidence is invalid", check.label)
		}
		if check.at > rank && check.value != "" {
			return fmt.Errorf("AcornFox repository %s evidence appears too early", check.label)
		}
	}
	return nil
}

func ValidateAcornFoxRepoTransition(from, to AcornFoxRepoPhase) error {
	if acornFoxRepoRank(from) < 0 || acornFoxRepoRank(to) < 0 || from == AcornFoxRepoPreparedFinal || acornFoxRepoRank(to) != acornFoxRepoRank(from)+1 {
		return errors.New("AcornFox repository transition is invalid")
	}
	return nil
}

func ParseAcornFoxRepoJournalV1(raw []byte) (AcornFoxRepoJournalV1, error) {
	var journal AcornFoxRepoJournalV1
	if err := strictCanonicalJSON(raw, &journal, "AcornFox repository journal"); err != nil {
		return journal, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return journal, err
	}
	for _, field := range []string{"schema_version", "transaction_id", "revision", "phase", "needs_recovery", "binding_sha256", "substrate_receipt_sha256", "history"} {
		value, present := fields[field]
		if !present || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return journal, fmt.Errorf("AcornFox repository journal field %q is missing", field)
		}
	}
	for field, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return journal, fmt.Errorf("AcornFox repository journal field %q is null", field)
		}
	}
	if err := journal.Validate(); err != nil {
		return AcornFoxRepoJournalV1{}, err
	}
	return journal, nil
}

func MarshalAcornFoxRepoJournalV1(journal AcornFoxRepoJournalV1) ([]byte, error) {
	if err := journal.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(journal)
}

func sameAcornFoxRepoJournal(left, right AcornFoxRepoJournalV1) bool {
	a, ae := MarshalAcornFoxRepoJournalV1(left)
	b, be := MarshalAcornFoxRepoJournalV1(right)
	return ae == nil && be == nil && bytes.Equal(a, b)
}

func acornFoxRepoPhaseEvidence(journal AcornFoxRepoJournalV1, phase AcornFoxRepoPhase) string {
	switch phase {
	case AcornFoxRepoPrepared:
		evidence, _ := AcornFoxRepoPreparedEvidence(journal.BindingSHA256, journal.SubstrateReceiptSHA256)
		return evidence
	case AcornFoxRepoLiveMaterialized:
		return journal.LiveTreeSHA256
	case AcornFoxRepoStaticVerified:
		return journal.StaticSetSHA256
	case AcornFoxRepoActivationWritten:
		return journal.ActivationSHA256
	case AcornFoxRepoActivePublished:
		return journal.ActivePointerSHA256
	case AcornFoxRepoCurrentPublished:
		return journal.CurrentPointerSHA256
	case AcornFoxRepoPreparedFinal:
		evidence, _ := AcornFoxRepoFinalEvidence(journal)
		return evidence
	default:
		return ""
	}
}
