package install

import (
	"bytes"
	"context"
	"errors"
	"os"
)

var ErrBootstrapFinalization = errors.New("bootstrap finalization failed")

type BootstrapFinalizationReceipt struct {
	TransactionID          string `json:"transaction_id"`
	ActivationID           string `json:"activation_id"`
	ActivationJSONSHA256   string `json:"activation_json_sha256"`
	BootstrapEnvSHA256     string `json:"bootstrap_env_sha256,omitempty"`
	BootstrapEnvWasPresent bool   `json:"bootstrap_env_was_present"`
}

func (r BootstrapFinalizationReceipt) Validate() error {
	if !validID(r.TransactionID) || !validID(r.ActivationID) || !validSHA(r.ActivationJSONSHA256) || (r.BootstrapEnvWasPresent && !validSHA(r.BootstrapEnvSHA256)) || (!r.BootstrapEnvWasPresent && r.BootstrapEnvSHA256 != "") {
		return ErrBootstrapFinalization
	}
	return nil
}

func VerifyProductionCommittedBootstrap(ctx context.Context, request BootstrapRequest) error {
	store, err := ProductionBootstrapStore()
	if err != nil {
		return ErrBootstrapFinalization
	}
	defer store.Close()
	lock, err := store.Acquire(ctx, request.TransactionID)
	if err != nil {
		return err
	}
	defer lock.Release()
	_, err = store.verifyCommittedLocked(ctx, request, true)
	return err
}

func FinalizeProductionBootstrapEnvironment(ctx context.Context, request BootstrapRequest) (BootstrapFinalizationReceipt, error) {
	store, err := ProductionBootstrapStore()
	if err != nil {
		return BootstrapFinalizationReceipt{}, ErrBootstrapFinalization
	}
	defer store.Close()
	lock, err := store.Acquire(ctx, request.TransactionID)
	if err != nil {
		return BootstrapFinalizationReceipt{}, err
	}
	defer lock.Release()
	return store.finalizeEnvironmentLocked(ctx, request)
}

func (s *BootstrapStore) verifyCommittedLocked(ctx context.Context, request BootstrapRequest, allowSameTransactionMarker bool) (BootstrapJournalV1, error) {
	if s == nil || s.upgrade == nil || !s.upgrade.ownsLock() || request.Validate() != nil || s.upgrade.lock.tx != request.TransactionID {
		return BootstrapJournalV1{}, ErrBootstrapFinalization
	}
	journal, err := s.Load(ctx, request.TransactionID)
	if err != nil || journal.Validate() != nil || journal.State != BootstrapCommitted || !sameBootstrapRequest(journal, request) {
		return BootstrapJournalV1{}, ErrBootstrapFinalization
	}
	state, err := s.ReadInitialPointerState(ctx, request.CandidateActivationID)
	markerOK := state.MarkerTransactionID == "" || allowSameTransactionMarker && state.MarkerTransactionID == request.TransactionID
	if err != nil || !state.ActivationExists || state.ActivationJSONSHA256 != journal.ActivationJSONSHA256 || state.ActiveID != request.CandidateActivationID || !state.CurrentPresent || state.PreviousPresent || !markerOK || state.PointerStateSHA256 != journal.PointerStateSHA256 {
		return BootstrapJournalV1{}, ErrBootstrapFinalization
	}
	return journal, nil
}

func (s *BootstrapStore) finalizeEnvironmentLocked(ctx context.Context, request BootstrapRequest) (BootstrapFinalizationReceipt, error) {
	journal, err := s.verifyCommittedLocked(ctx, request, false)
	if err != nil {
		return BootstrapFinalizationReceipt{}, err
	}
	receipt := BootstrapFinalizationReceipt{TransactionID: request.TransactionID, ActivationID: request.CandidateActivationID, ActivationJSONSHA256: journal.ActivationJSONSHA256}
	bootstrapEnv, err := s.upgrade.configDurable.ReadMetadata(bootstrapRuntimeDatabaseEnvName)
	if errors.Is(err, os.ErrNotExist) {
		if receipt.Validate() != nil {
			return BootstrapFinalizationReceipt{}, ErrBootstrapFinalization
		}
		return receipt, nil
	}
	if err != nil || validateBootstrapRuntimeDatabaseEnvOnly(bootstrapEnv) != nil {
		return BootstrapFinalizationReceipt{}, ErrBootstrapFinalization
	}
	active, err := s.upgrade.ReadActiveForRestore(ctx)
	if err != nil || active.Activation.ActivationID != request.CandidateActivationID || active.JSONSHA256 != journal.ActivationJSONSHA256 {
		return BootstrapFinalizationReceipt{}, ErrBootstrapFinalization
	}
	expectedActiveEnv, err := CandidateDatabaseEnv(bootstrapEnv, active.Activation.Database.Name)
	if err != nil || !bytes.Equal(expectedActiveEnv, active.DatabaseEnv) {
		return BootstrapFinalizationReceipt{}, ErrBootstrapFinalization
	}
	receipt.BootstrapEnvSHA256, receipt.BootstrapEnvWasPresent = sha256Bytes(bootstrapEnv), true
	if err := s.upgrade.configDurable.RemoveMetadata(bootstrapRuntimeDatabaseEnvName); err != nil {
		if !errors.Is(err, ErrDurableCommitUnknown) {
			return BootstrapFinalizationReceipt{}, ErrBootstrapFinalization
		}
	}
	if _, err := s.upgrade.configDurable.ReadMetadata(bootstrapRuntimeDatabaseEnvName); !errors.Is(err, os.ErrNotExist) {
		return BootstrapFinalizationReceipt{}, ErrBootstrapFinalization
	}
	if receipt.Validate() != nil {
		return BootstrapFinalizationReceipt{}, ErrBootstrapFinalization
	}
	return receipt, nil
}
