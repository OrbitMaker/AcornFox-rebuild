package install

import (
	"bytes"
	"context"
	"errors"
	"os"
)

type UpgradeMarkerClassification string

const (
	UpgradeMarkerAbsent  UpgradeMarkerClassification = "absent"
	UpgradeMarkerSame    UpgradeMarkerClassification = "same"
	UpgradeMarkerForeign UpgradeMarkerClassification = "foreign"
	UpgradeMarkerUnknown UpgradeMarkerClassification = "unknown"
)

// UpgradeStatusDisposition is conservative by design. Only a terminal state
// with its exact durable pointer and marker postconditions is terminal.
type UpgradeStatusDisposition string

const (
	UpgradeStatusInProgress       UpgradeStatusDisposition = "in_progress"
	UpgradeStatusRecoveryRequired UpgradeStatusDisposition = "recovery_required"
	UpgradeStatusTerminal         UpgradeStatusDisposition = "terminal"
	UpgradeStatusUnknown          UpgradeStatusDisposition = "unknown"
)

type PendingTransaction struct {
	TransactionID string                      `json:"transaction_id,omitempty"`
	Marker        UpgradeMarkerClassification `json:"marker"`
}

// UpgradeStatusV1 contains no failure, database, environment, artifact, or
// raw pointer-target material. The disposition and Recovery flag are safe for
// a caller to act on without interpreting secrets or opaque failure text.
type UpgradeStatusV1 struct {
	SchemaVersion int                         `json:"schema_version"`
	TransactionID string                      `json:"transaction_id"`
	RequestKind   RequestKind                 `json:"request_kind"`
	State         JournalState                `json:"state"`
	Revision      int64                       `json:"revision"`
	UpdatedAt     string                      `json:"updated_at"`
	Marker        UpgradeMarkerClassification `json:"marker"`
	Disposition   UpgradeStatusDisposition    `json:"disposition"`
	ActiveID      string                      `json:"active_id,omitempty"`
	PreviousID    string                      `json:"previous_id,omitempty"`
	Recovery      bool                        `json:"recovery"`
}

type upgradeStatusObservation struct {
	state          UpgradeActivationState
	activeTarget   string
	previousTarget string
	legacyAbsent   bool
	unprovable     bool
}

type upgradeStatusSample struct {
	status       UpgradeStatusV1
	journalBytes []byte
	markerBytes  []byte
	observation  upgradeStatusObservation
}

// PendingTransaction reads only the fixed marker. It does not acquire or
// create a lock, and never calls database or service code.
func (s *UpgradeStore) PendingTransaction(_ context.Context) (PendingTransaction, error) {
	if s == nil || s.dataWriter == nil || s.verifyLiveRoots() != nil {
		return PendingTransaction{}, ErrUpgradeJournalConflict
	}
	raw, err := s.dataWriter.ReadMetadata(storeUpgradeInProgressPath)
	if errors.Is(err, os.ErrNotExist) {
		return PendingTransaction{Marker: UpgradeMarkerAbsent}, nil
	}
	if err != nil {
		return PendingTransaction{Marker: UpgradeMarkerUnknown}, nil
	}
	transactionID, ok := safeMarkerTransaction(raw)
	if !ok {
		return PendingTransaction{Marker: UpgradeMarkerUnknown}, nil
	}
	return PendingTransaction{TransactionID: transactionID, Marker: UpgradeMarkerSame}, nil
}

func safeMarkerTransaction(raw []byte) (string, bool) {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' || bytes.Count(raw, []byte{'\n'}) != 1 {
		return "", false
	}
	transactionID := string(raw[:len(raw)-1])
	return transactionID, validID(transactionID)
}

// ReadUpgradeStatus performs two independent read-only snapshots. It remains
// usable when an upgrade owns the flock, but refuses to stitch together data
// from different journal/marker/pointer revisions.
func (s *UpgradeStore) ReadUpgradeStatus(ctx context.Context, transactionID string) (UpgradeStatusV1, error) {
	if s == nil || !validID(transactionID) || s.verifyLiveRoots() != nil {
		return UpgradeStatusV1{}, ErrUpgradeJournalConflict
	}
	first, err := s.readUpgradeStatusSample(ctx, transactionID)
	if err != nil {
		return UpgradeStatusV1{}, ErrUpgradeJournalConflict
	}
	if s.statusReadHook != nil {
		s.statusReadHook()
	}
	second, err := s.readUpgradeStatusSample(ctx, transactionID)
	if err != nil || !sameUpgradeStatusSample(first, second) {
		return UpgradeStatusV1{}, ErrUpgradeJournalConflict
	}
	return first.status, nil
}

func (s *UpgradeStore) readUpgradeStatusSample(ctx context.Context, transactionID string) (upgradeStatusSample, error) {
	raw, err := s.dataWriter.ReadMetadata(s.journal(transactionID))
	if err != nil {
		return upgradeStatusSample{}, err
	}
	journal, err := ParseUpgradeJournalV1(raw)
	if err != nil || journal.TransactionID != transactionID || journal.Validate() != nil {
		return upgradeStatusSample{}, ErrUpgradeJournalConflict
	}
	pending, markerRaw, err := s.readPendingSnapshot(ctx)
	if err != nil {
		return upgradeStatusSample{}, err
	}
	marker := pending.Marker
	if marker == UpgradeMarkerSame && pending.TransactionID != transactionID {
		marker = UpgradeMarkerForeign
	}
	observation, err := s.readStatusActivationObservation(journal)
	if err != nil {
		return upgradeStatusSample{}, err
	}
	disposition := s.statusDisposition(journal, marker, observation)
	return upgradeStatusSample{
		status: UpgradeStatusV1{
			SchemaVersion: ActivationSchemaVersion,
			TransactionID: transactionID,
			RequestKind:   journal.RequestKind,
			State:         journal.State,
			Revision:      journal.Revision,
			UpdatedAt:     journal.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			Marker:        marker,
			Disposition:   disposition,
			ActiveID:      observation.state.ActiveID,
			PreviousID:    observation.state.PreviousID,
			Recovery:      disposition != UpgradeStatusTerminal,
		},
		journalBytes: append([]byte(nil), raw...),
		markerBytes:  markerRaw,
		observation:  observation,
	}, nil
}

func (s *UpgradeStore) readPendingSnapshot(ctx context.Context) (PendingTransaction, []byte, error) {
	pending, err := s.PendingTransaction(ctx)
	if err != nil {
		return PendingTransaction{}, nil, err
	}
	raw, err := s.dataWriter.ReadMetadata(storeUpgradeInProgressPath)
	if errors.Is(err, os.ErrNotExist) && pending.Marker == UpgradeMarkerAbsent {
		return pending, nil, nil
	}
	if err != nil {
		if pending.Marker == UpgradeMarkerUnknown {
			return pending, nil, nil
		}
		return PendingTransaction{}, nil, err
	}
	return pending, append([]byte(nil), raw...), nil
}

func (s *UpgradeStore) readStatusActivationObservation(j UpgradeJournalV1) (upgradeStatusObservation, error) {
	if s == nil || s.activationWriter == nil {
		return upgradeStatusObservation{}, ErrUpgradeJournalConflict
	}
	activeTarget, err := s.activationWriter.ReadActivationLink(ActivationLinkActive)
	if errors.Is(err, os.ErrNotExist) {
		if j.State == JournalPreflighted && j.PlannedOldActivation != nil && j.PlannedOldActivation.Validate() == nil && s.legacyCurrentMatches(j.PlannedOldActivation.Release.ID) {
			previous, previousTarget, err := s.readStatusPrevious()
			if err != nil {
				return upgradeStatusObservation{}, err
			}
			return upgradeStatusObservation{state: UpgradeActivationState{PreviousID: previous.ID, PreviousJSONSHA256: previous.JSONSHA256}, previousTarget: previousTarget, legacyAbsent: true}, nil
		}
		return upgradeStatusObservation{unprovable: true}, nil
	}
	if err != nil {
		return upgradeStatusObservation{unprovable: true}, nil
	}
	activeID, ok := activationIDFromTarget(activeTarget)
	if !ok {
		return upgradeStatusObservation{unprovable: true}, nil
	}
	_, activeDigest, err := s.readActivation(activeID)
	if err != nil {
		return upgradeStatusObservation{unprovable: true}, nil
	}
	current, err := s.activationWriter.ReadActivationLink(ActivationLinkCurrent)
	if err != nil || current != legacyCurrentTarget {
		return upgradeStatusObservation{unprovable: true}, nil
	}
	previous, previousTarget, err := s.readStatusPrevious()
	if err != nil {
		return upgradeStatusObservation{unprovable: true}, nil
	}
	return upgradeStatusObservation{state: UpgradeActivationState{ActiveID: activeID, ActiveActivationJSONSHA256: activeDigest, PreviousID: previous.ID, PreviousJSONSHA256: previous.JSONSHA256}, activeTarget: activeTarget, previousTarget: previousTarget}, nil
}

func (s *UpgradeStore) readStatusPrevious() (ActivationPointerIdentity, string, error) {
	target, err := s.activationWriter.ReadActivationLink(ActivationLinkPreviousActive)
	if errors.Is(err, os.ErrNotExist) {
		return ActivationPointerIdentity{}, "", nil
	}
	if err != nil {
		return ActivationPointerIdentity{}, "", ErrUpgradeJournalConflict
	}
	id, ok := activationIDFromTarget(target)
	if !ok {
		return ActivationPointerIdentity{}, "", ErrUpgradeJournalConflict
	}
	_, digest, err := s.readActivation(id)
	if err != nil {
		return ActivationPointerIdentity{}, "", ErrUpgradeJournalConflict
	}
	return ActivationPointerIdentity{ID: id, JSONSHA256: digest}, target, nil
}

func (s *UpgradeStore) legacyCurrentMatches(releaseID string) bool {
	if !validID(releaseID) {
		return false
	}
	info, err := s.activationWriter.ops.Lstat("current")
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return false
	}
	target, err := s.activationWriter.ops.Readlink("current")
	return err == nil && target == "releases/"+releaseID
}

func (s *UpgradeStore) statusDisposition(j UpgradeJournalV1, marker UpgradeMarkerClassification, observed upgradeStatusObservation) UpgradeStatusDisposition {
	if marker == UpgradeMarkerUnknown {
		return UpgradeStatusUnknown
	}
	if j.State == JournalRecoveryRequired {
		return UpgradeStatusRecoveryRequired
	}
	if observed.unprovable || observed.legacyAbsent && j.State != JournalPreflighted {
		return UpgradeStatusUnknown
	}
	if terminal(j.State) {
		if marker != UpgradeMarkerAbsent || !terminalPointersMatch(j, observed.state) {
			return UpgradeStatusRecoveryRequired
		}
		return UpgradeStatusTerminal
	}
	if observed.legacyAbsent {
		if j.State != JournalPreflighted || marker == UpgradeMarkerForeign {
			return UpgradeStatusRecoveryRequired
		}
	} else if !coherentStatusActivation(observed) {
		return UpgradeStatusUnknown
	}
	if marker == UpgradeMarkerSame {
		// A marker alone cannot distinguish a live owner from a crashed owner.
		// Status never probes or acquires the engine flock to guess.
		return UpgradeStatusUnknown
	}
	if marker == UpgradeMarkerForeign {
		return UpgradeStatusRecoveryRequired
	}
	return UpgradeStatusRecoveryRequired
}

func coherentStatusActivation(observed upgradeStatusObservation) bool {
	if !validID(observed.state.ActiveID) || !validSHA(observed.state.ActiveActivationJSONSHA256) || observed.activeTarget != "activations/"+observed.state.ActiveID {
		return false
	}
	if observed.state.PreviousID == "" && observed.state.PreviousJSONSHA256 == "" {
		return observed.previousTarget == ""
	}
	return validID(observed.state.PreviousID) && validSHA(observed.state.PreviousJSONSHA256) && observed.previousTarget == "activations/"+observed.state.PreviousID
}

func terminalPointersMatch(j UpgradeJournalV1, state UpgradeActivationState) bool {
	switch j.State {
	case JournalCommitted:
		return state.ActiveID == j.CandidateActivationID && state.ActiveActivationJSONSHA256 == j.CandidateActivationJSONSHA256 && state.PreviousID == j.OldActivationID && state.PreviousJSONSHA256 == j.OldActivationJSONSHA256
	case JournalAbortedPreSwitch:
		return state.ActiveID == j.OldActivationID && state.ActiveActivationJSONSHA256 == j.OldActivationJSONSHA256 && state.PreviousID == j.PreUpgradePreviousActivationID && state.PreviousJSONSHA256 == j.PreUpgradePreviousActivationJSONSHA256
	case JournalRolledBack:
		return state.ActiveID == j.OldActivationID && state.ActiveActivationJSONSHA256 == j.OldActivationJSONSHA256 && state.PreviousID == j.CandidateActivationID && state.PreviousJSONSHA256 == j.CandidateActivationJSONSHA256
	default:
		return false
	}
}

func sameUpgradeStatusSample(left, right upgradeStatusSample) bool {
	return left.status == right.status && bytes.Equal(left.journalBytes, right.journalBytes) && bytes.Equal(left.markerBytes, right.markerBytes) && left.observation == right.observation
}
