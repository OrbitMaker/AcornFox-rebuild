package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
)

type BootstrapState string

const (
	BootstrapPrepared           BootstrapState = "PREPARED"
	BootstrapCandidateDBCreated BootstrapState = "CANDIDATE_DB_CREATED"
	BootstrapMigrated0024       BootstrapState = "MIGRATED_0024"
	BootstrapActivationWritten  BootstrapState = "ACTIVATION_WRITTEN"
	BootstrapPointersPublished  BootstrapState = "POINTERS_PUBLISHED"
	BootstrapInternalHealthy    BootstrapState = "INTERNAL_HEALTHY"
	BootstrapEdgeHealthy        BootstrapState = "EDGE_HEALTHY"
	BootstrapCommitted          BootstrapState = "COMMITTED"
	BootstrapRecoveryRequired   BootstrapState = "RECOVERY_REQUIRED"
)

type BootstrapFailureV1 struct {
	Code   string `json:"code"`
	Digest string `json:"digest"`
}
type BootstrapHistoryV1 struct {
	Revision       int64          `json:"revision"`
	From           BootstrapState `json:"from"`
	To             BootstrapState `json:"to"`
	At             time.Time      `json:"at"`
	EvidenceSHA256 string         `json:"evidence_sha256"`
}
type BootstrapJournalV1 struct {
	SchemaVersion                 int                  `json:"schema_version"`
	TransactionID                 string               `json:"transaction_id"`
	Revision                      int64                `json:"revision"`
	State                         BootstrapState       `json:"state"`
	CreatedAt                     time.Time            `json:"created_at"`
	UpdatedAt                     time.Time            `json:"updated_at"`
	InstallationIDSHA256          string               `json:"installation_id_sha256"`
	Release                       ReleaseV1            `json:"release"`
	CandidateActivationID         string               `json:"candidate_activation_id"`
	CandidateDatabaseName         string               `json:"candidate_database_name"`
	CandidateDatabaseSchemaSHA256 string               `json:"candidate_database_schema_sha256,omitempty"`
	ActivationJSONSHA256          string               `json:"activation_json_sha256,omitempty"`
	PointerStateSHA256            string               `json:"pointer_state_sha256,omitempty"`
	InternalHealthSHA256          string               `json:"internal_health_sha256,omitempty"`
	EdgeHealthSHA256              string               `json:"edge_health_sha256,omitempty"`
	MarkerTransactionID           string               `json:"marker_transaction_id"`
	ServiceSnapshot               *ServiceSnapshotV1   `json:"service_snapshot,omitempty"`
	Failure                       *BootstrapFailureV1  `json:"failure,omitempty"`
	History                       []BootstrapHistoryV1 `json:"history"`
}

func bootstrapRank(s BootstrapState) int {
	for i, v := range []BootstrapState{BootstrapPrepared, BootstrapCandidateDBCreated, BootstrapMigrated0024, BootstrapActivationWritten, BootstrapPointersPublished, BootstrapInternalHealthy, BootstrapEdgeHealthy, BootstrapCommitted} {
		if s == v {
			return i
		}
	}
	return -1
}
func (j BootstrapJournalV1) Validate() error {
	architecture, architectureErr := NormalizeArchitecture(j.Release.Architecture)
	if j.SchemaVersion != 1 || !validID(j.TransactionID) || j.Revision < 1 || !validSHA(j.InstallationIDSHA256) || !j.Release.valid() || j.Release.Version != Gate6CandidateVersion || architectureErr != nil || architecture != j.Release.Architecture || !validID(j.CandidateActivationID) || !candidateDatabaseName.MatchString(j.CandidateDatabaseName) || j.MarkerTransactionID != j.TransactionID || j.CreatedAt.IsZero() || j.UpdatedAt.Before(j.CreatedAt) {
		return errors.New("invalid bootstrap journal")
	}
	if int64(len(j.History)) != j.Revision || len(j.History) == 0 {
		return errors.New("invalid bootstrap history length")
	}
	var effective BootstrapState
	for index, transition := range j.History {
		if transition.Revision != int64(index+1) || transition.At.IsZero() || !validSHA(transition.EvidenceSHA256) {
			return errors.New("invalid bootstrap history entry")
		}
		if index == 0 {
			if transition.From != "" || transition.To != BootstrapPrepared || !transition.At.Equal(j.CreatedAt) {
				return errors.New("invalid bootstrap initial history")
			}
		} else {
			previous := j.History[index-1]
			if transition.From != previous.To || transition.At.Before(previous.At) || ValidateBootstrapTransition(transition.From, transition.To) != nil {
				return errors.New("invalid bootstrap history chain")
			}
		}
		if transition.To == BootstrapRecoveryRequired {
			effective = transition.From
		} else {
			effective = transition.To
		}
	}
	last := j.History[len(j.History)-1]
	if last.To != j.State || !last.At.Equal(j.UpdatedAt) {
		return errors.New("bootstrap history does not match state")
	}
	if j.State == BootstrapRecoveryRequired {
		if j.Failure == nil || !validID(j.Failure.Code) || !validSHA(j.Failure.Digest) || bootstrapRank(effective) < 0 {
			return errors.New("invalid bootstrap failure")
		}
	} else if bootstrapRank(j.State) < 0 || j.Failure != nil {
		return errors.New("invalid bootstrap state")
	}
	r := bootstrapRank(effective)
	if (r >= 2 && !validSHA(j.CandidateDatabaseSchemaSHA256)) || (r < 2 && j.CandidateDatabaseSchemaSHA256 != "") {
		return errors.New("invalid bootstrap database evidence")
	}
	if (r >= 3 && !validSHA(j.ActivationJSONSHA256)) || (r < 3 && j.ActivationJSONSHA256 != "") {
		return errors.New("invalid bootstrap activation evidence")
	}
	if (r >= 4 && !validSHA(j.PointerStateSHA256)) || (r < 4 && j.PointerStateSHA256 != "") {
		return errors.New("invalid bootstrap pointer evidence")
	}
	if (r >= 5 && (!validSHA(j.InternalHealthSHA256) || j.ServiceSnapshot == nil)) || (r < 5 && (j.InternalHealthSHA256 != "" || j.ServiceSnapshot != nil)) {
		return errors.New("invalid bootstrap service evidence")
	}
	if (r >= 6 && !validSHA(j.EdgeHealthSHA256)) || (r < 6 && j.EdgeHealthSHA256 != "") {
		return errors.New("invalid bootstrap edge evidence")
	}
	return nil
}
func ValidateBootstrapTransition(from, to BootstrapState) error {
	if bootstrapRank(from) < 0 {
		return errors.New("invalid bootstrap transition source")
	}
	if from == BootstrapCommitted || from == BootstrapRecoveryRequired {
		return errors.New("bootstrap terminal")
	}
	if to == BootstrapRecoveryRequired {
		return nil
	}
	if bootstrapRank(to) != bootstrapRank(from)+1 {
		return errors.New("invalid bootstrap transition")
	}
	return nil
}
func ParseBootstrapJournalV1(raw []byte) (BootstrapJournalV1, error) {
	var j BootstrapJournalV1
	if err := decodeStrict(raw, &j); err != nil {
		return j, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return j, err
	}
	for _, name := range []string{"schema_version", "transaction_id", "revision", "state", "created_at", "updated_at", "installation_id_sha256", "release", "candidate_activation_id", "candidate_database_name", "marker_transaction_id", "history"} {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return j, errors.New("bootstrap journal field is missing")
		}
	}
	for name, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return j, errors.New("bootstrap journal field is null: " + name)
		}
	}
	if err := j.Validate(); err != nil {
		return j, err
	}
	return j, nil
}

func MarshalBootstrapJournalV1(j BootstrapJournalV1) ([]byte, error) {
	if err := j.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(j)
}
