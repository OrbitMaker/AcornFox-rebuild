package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// AcornFoxRepoPhase is the closed, repository-only preparation protocol.  It
// deliberately stops before any host lifecycle operation. It has no
// host-level terminal representations.
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

const AcornFoxRepoJournalV1Schema = 1

// AcornFoxRepoFailureV1 contains only a stable code and a digest of any
// diagnostic material.  It intentionally cannot serialize paths, secrets, or
// DSNs.
type AcornFoxRepoFailureV1 struct {
	Code   string `json:"code"`
	Digest string `json:"digest"`
}

type AcornFoxRepoHistoryV1 struct {
	Revision       int64             `json:"revision"`
	From           AcornFoxRepoPhase `json:"from"`
	To             AcornFoxRepoPhase `json:"to"`
	EvidenceSHA256 string            `json:"evidence_sha256"`
}

// AcornFoxRepoJournalV1 is secret-free and path-free.  Its sole terminal
// phase, REPO_PREPARED, means that repository preparation has completed; it
// makes no claim about a host, a service, a database, or a public endpoint.
type AcornFoxRepoJournalV1 struct {
	SchemaVersion          int                     `json:"schema_version"`
	TransactionID          string                  `json:"transaction_id"`
	Revision               int64                   `json:"revision"`
	Phase                  AcornFoxRepoPhase       `json:"phase"`
	NeedsRecovery          bool                    `json:"needs_recovery"`
	BindingSHA256          string                  `json:"binding_sha256"`
	SubstrateReceiptSHA256 string                  `json:"substrate_receipt_sha256,omitempty"`
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
	for index, candidate := range []AcornFoxRepoPhase{
		AcornFoxRepoPrepared,
		AcornFoxRepoLiveMaterialized,
		AcornFoxRepoStaticVerified,
		AcornFoxRepoActivationWritten,
		AcornFoxRepoActivePublished,
		AcornFoxRepoCurrentPublished,
		AcornFoxRepoPreparedFinal,
	} {
		if phase == candidate {
			return index
		}
	}
	return -1
}

// AcornFoxRepoActivationID derives the only activation identifier accepted by
// this protocol.  It is domain separated so a raw binding digest cannot be
// reused as an identifier in another contract.
func AcornFoxRepoActivationID(bindingSHA256 string) (string, error) {
	if !validSHA(bindingSHA256) {
		return "", errors.New("AcornFox repository binding digest is invalid")
	}
	sum := sha256.Sum256([]byte("acornfox-repo-activation-v1\x00" + bindingSHA256))
	return "acornfox-repo-" + hex.EncodeToString(sum[:]), nil
}

func (j AcornFoxRepoJournalV1) Validate() error {
	if j.SchemaVersion != AcornFoxRepoJournalV1Schema || !validID(j.TransactionID) || j.Revision < 1 || acornFoxRepoRank(j.Phase) < 0 || !validSHA(j.BindingSHA256) {
		return errors.New("AcornFox repository journal identity is invalid")
	}
	if int64(len(j.History)) != j.Revision || len(j.History) == 0 {
		return errors.New("AcornFox repository history length is invalid")
	}
	for index, entry := range j.History {
		if entry.Revision != int64(index+1) || !validSHA(entry.EvidenceSHA256) || acornFoxRepoRank(entry.To) < 0 {
			return errors.New("AcornFox repository history entry is invalid")
		}
		if index == 0 {
			if entry.From != "" || entry.To != AcornFoxRepoPrepared || entry.EvidenceSHA256 != j.BindingSHA256 {
				return errors.New("AcornFox repository initial history is invalid")
			}
			continue
		}
		previous := j.History[index-1]
		if entry.From != previous.To || acornFoxRepoRank(entry.From) < 0 || acornFoxRepoRank(entry.To) < acornFoxRepoRank(entry.From) || (entry.To != entry.From && acornFoxRepoRank(entry.To) != acornFoxRepoRank(entry.From)+1) {
			return errors.New("AcornFox repository history is not monotonic")
		}
	}
	if j.History[len(j.History)-1].To != j.Phase {
		return errors.New("AcornFox repository history does not match phase")
	}
	if !j.NeedsRecovery && j.Failure != nil {
		return errors.New("AcornFox repository failure requires recovery")
	}
	if j.NeedsRecovery && (j.Failure == nil || !validID(j.Failure.Code) || !validSHA(j.Failure.Digest)) {
		return errors.New("AcornFox repository recovery failure is invalid")
	}
	return j.validateEvidence()
}

func (j AcornFoxRepoJournalV1) validateEvidence() error {
	rank := acornFoxRepoRank(j.Phase)
	checks := []struct {
		at    int
		value string
		label string
	}{
		{0, j.BindingSHA256, "binding"},
		{1, j.LiveTreeSHA256, "live tree"},
		{2, j.OwnershipPlanSHA256, "ownership plan"},
		{2, j.StaticSetSHA256, "static set"},
		{3, j.ActivationSHA256, "activation"},
		{4, j.ActivePointerSHA256, "active pointer"},
		{5, j.CurrentPointerSHA256, "current pointer"},
		{6, j.SubstrateReceiptSHA256, "substrate receipt"},
	}
	for _, check := range checks {
		if check.at <= rank {
			if !validSHA(check.value) {
				return fmt.Errorf("AcornFox repository %s evidence is invalid", check.label)
			}
		} else if check.value != "" {
			return fmt.Errorf("AcornFox repository %s evidence appears too early", check.label)
		}
	}
	return nil
}

func ValidateAcornFoxRepoTransition(from, to AcornFoxRepoPhase) error {
	if acornFoxRepoRank(from) < 0 || acornFoxRepoRank(to) < 0 || from == AcornFoxRepoPreparedFinal {
		return errors.New("AcornFox repository transition is invalid")
	}
	if to == from || acornFoxRepoRank(to) == acornFoxRepoRank(from)+1 {
		return nil
	}
	return errors.New("AcornFox repository transition is not adjacent")
}

func ParseAcornFoxRepoJournalV1(raw []byte) (AcornFoxRepoJournalV1, error) {
	var journal AcornFoxRepoJournalV1
	if err := strictCanonicalJSON(raw, &journal, "AcornFox repository journal"); err != nil {
		return AcornFoxRepoJournalV1{}, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return AcornFoxRepoJournalV1{}, err
	}
	for _, field := range []string{"schema_version", "transaction_id", "revision", "phase", "needs_recovery", "binding_sha256", "history"} {
		value, present := fields[field]
		if !present || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return AcornFoxRepoJournalV1{}, fmt.Errorf("AcornFox repository journal field %q is missing", field)
		}
	}
	for field, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return AcornFoxRepoJournalV1{}, fmt.Errorf("AcornFox repository journal field %q is null", field)
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
	leftRaw, leftErr := MarshalAcornFoxRepoJournalV1(left)
	rightRaw, rightErr := MarshalAcornFoxRepoJournalV1(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}
