package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type BootstrapStore struct{ upgrade *UpgradeStore }

type bootstrapPointerStateV1 struct {
	ActiveActivationID         string `json:"active_activation_id"`
	ActiveActivationJSONSHA256 string `json:"active_activation_json_sha256"`
	CurrentTarget              string `json:"current_target"`
	PreviousAbsent             bool   `json:"previous_absent"`
}

func ProductionBootstrapStore() (*BootstrapStore, error) {
	s, e := ProductionUpgradeStore()
	if e != nil {
		return nil, e
	}
	return &BootstrapStore{s}, nil
}
func TaskBootstrapStore(root string, uid, gid int) (*BootstrapStore, error) {
	s, e := TaskUpgradeStore(root, uid, gid)
	if e != nil {
		return nil, e
	}
	return &BootstrapStore{s}, nil
}
func (s *BootstrapStore) Acquire(ctx context.Context, tx string) (UpgradeLock, error) {
	if s == nil || s.upgrade == nil {
		return nil, ErrUpgradeJournalConflict
	}
	return s.upgrade.Acquire(ctx, tx)
}
func (s *BootstrapStore) EnsureMarker(ctx context.Context, tx string) error {
	if s == nil || s.upgrade == nil || !s.upgrade.ownsLock() || s.upgrade.lock.tx != tx {
		return ErrUpgradeJournalConflict
	}
	return s.upgrade.EnsureMarker(ctx, tx)
}
func (s *BootstrapStore) Marker(ctx context.Context, set bool) error {
	if s == nil || s.upgrade == nil || !s.upgrade.ownsLock() {
		return ErrUpgradeJournalConflict
	}
	return s.upgrade.Marker(ctx, set)
}
func (s *BootstrapStore) path(tx string) string {
	return filepath.ToSlash(filepath.Join("bootstrap-transactions", tx+".json"))
}
func (s *BootstrapStore) Load(ctx context.Context, tx string) (BootstrapJournalV1, error) {
	if s == nil || s.upgrade == nil || !validID(tx) {
		return BootstrapJournalV1{}, ErrUpgradeJournalConflict
	}
	raw, e := s.upgrade.dataWriter.ReadMetadata(s.path(tx))
	if e != nil {
		return BootstrapJournalV1{}, e
	}
	return ParseBootstrapJournalV1(raw)
}
func (s *BootstrapStore) Create(ctx context.Context, j BootstrapJournalV1) error {
	if s == nil || s.upgrade == nil || !s.upgrade.ownsLock() || s.upgrade.lock.tx != j.TransactionID || j.Validate() != nil || !canonicalInitialBootstrapJournal(j) {
		return ErrUpgradeJournalConflict
	}
	raw, e := MarshalBootstrapJournalV1(j)
	if e != nil {
		return e
	}
	e = s.upgrade.dataWriter.CreateMetadata(s.path(j.TransactionID), raw)
	if errors.Is(e, os.ErrExist) {
		return ErrUpgradeJournalConflict
	}
	if e != nil && errors.Is(e, ErrDurableCommitUnknown) {
		observed, readErr := s.upgrade.dataWriter.ReadMetadata(s.path(j.TransactionID))
		if readErr == nil && bytes.Equal(observed, raw) {
			return nil
		}
	}
	return e
}

func canonicalInitialBootstrapJournal(j BootstrapJournalV1) bool {
	return j.State == BootstrapPrepared && j.Revision == 1 && len(j.History) == 1 && j.History[0].Revision == 1 && j.History[0].From == "" && j.History[0].To == BootstrapPrepared && j.CandidateDatabaseSchemaSHA256 == "" && j.ActivationJSONSHA256 == "" && j.PointerStateSHA256 == "" && j.InternalHealthSHA256 == "" && j.EdgeHealthSHA256 == "" && j.ServiceSnapshot == nil && j.Failure == nil
}
func (s *BootstrapStore) Save(ctx context.Context, j BootstrapJournalV1) error {
	if s == nil || s.upgrade == nil || !s.upgrade.ownsLock() || s.upgrade.lock.tx != j.TransactionID || j.Validate() != nil {
		return ErrUpgradeJournalConflict
	}
	old, e := s.Load(ctx, j.TransactionID)
	if e != nil || j.Revision != old.Revision+1 || len(j.History) != len(old.History)+1 || j.History[len(old.History)].Revision != j.Revision || j.History[len(old.History)].From != old.State || !sameBootstrapIdentity(old, j) || !preservesBootstrapEvidence(old, j) {
		return ErrUpgradeJournalConflict
	}
	for i := range old.History {
		if old.History[i] != j.History[i] {
			return ErrUpgradeJournalConflict
		}
	}
	raw, e := MarshalBootstrapJournalV1(j)
	if e != nil {
		return e
	}
	e = s.upgrade.dataWriter.WriteMetadata(s.path(j.TransactionID), raw)
	if e != nil && errors.Is(e, ErrDurableCommitUnknown) {
		observed, readErr := s.upgrade.dataWriter.ReadMetadata(s.path(j.TransactionID))
		if readErr == nil && bytes.Equal(observed, raw) {
			return nil
		}
	}
	return e
}

func sameBootstrapIdentity(old, next BootstrapJournalV1) bool {
	return old.SchemaVersion == next.SchemaVersion && old.TransactionID == next.TransactionID && old.CreatedAt.Equal(next.CreatedAt) && old.InstallationIDSHA256 == next.InstallationIDSHA256 && old.Release == next.Release && old.CandidateActivationID == next.CandidateActivationID && old.CandidateDatabaseName == next.CandidateDatabaseName && old.MarkerTransactionID == next.MarkerTransactionID
}

func preservesBootstrapEvidence(old, next BootstrapJournalV1) bool {
	if (old.CandidateDatabaseSchemaSHA256 != "" && old.CandidateDatabaseSchemaSHA256 != next.CandidateDatabaseSchemaSHA256) || (old.ActivationJSONSHA256 != "" && old.ActivationJSONSHA256 != next.ActivationJSONSHA256) || (old.PointerStateSHA256 != "" && old.PointerStateSHA256 != next.PointerStateSHA256) || (old.InternalHealthSHA256 != "" && old.InternalHealthSHA256 != next.InternalHealthSHA256) || (old.EdgeHealthSHA256 != "" && old.EdgeHealthSHA256 != next.EdgeHealthSHA256) {
		return false
	}
	if old.ServiceSnapshot != nil && (next.ServiceSnapshot == nil || *old.ServiceSnapshot != *next.ServiceSnapshot) {
		return false
	}
	return true
}

func validBootstrapActivationBinding(j BootstrapJournalV1, a ActivationV1) bool {
	return a.Origin == "native" && a.CreatedByTransactionID == j.TransactionID && a.ActivationID == j.CandidateActivationID && a.Release == j.Release && a.Database.Name == j.CandidateDatabaseName && a.Database.Migration == CurrentMigrationVersion && a.Database.SchemaMigrationsSHA256 == j.CandidateDatabaseSchemaSHA256 && a.LegacyProjection == nil && a.RestoreSource == nil
}

func (s *BootstrapStore) exactDurableBootstrapJournal(ctx context.Context, j BootstrapJournalV1) bool {
	if s == nil || s.upgrade == nil || !s.upgrade.ownsLock() || s.upgrade.lock.tx != j.TransactionID || j.Validate() != nil {
		return false
	}
	persisted, err := s.Load(ctx, j.TransactionID)
	return err == nil && sameBootstrapJournal(persisted, j)
}

// WriteInitialActivation publishes only the immutable native activation slot.
// It is the postcondition used to advance MIGRATED to ACTIVATION_WRITTEN;
// active/current/previous must remain absent throughout this operation.
func (s *BootstrapStore) WriteInitialActivation(ctx context.Context, j BootstrapJournalV1, a ActivationV1, env []byte) (string, error) {
	if j.State != BootstrapMigrated0024 || !validBootstrapActivationBinding(j, a) || !s.exactDurableBootstrapJournal(ctx, j) {
		return "", ErrUpgradeJournalConflict
	}
	raw, e := MarshalActivationV1(a)
	sum := sha256.Sum256(raw)
	if e != nil {
		return "", ErrUpgradeJournalConflict
	}
	digest := hex.EncodeToString(sum[:])
	marker, e := s.upgrade.markerTransaction()
	if e != nil || marker != j.TransactionID {
		return "", ErrUpgradeJournalConflict
	}
	activeID, currentPresent, e := s.bootstrapPointers()
	if e != nil || activeID != "" || currentPresent {
		return "", ErrUpgradeJournalConflict
	}
	written, e := s.upgrade.WriteCandidateActivation(ctx, a, env)
	if e != nil || written != digest || !s.exactActivationSlot(a.ActivationID, digest) {
		return "", ErrUpgradeJournalConflict
	}
	activeID, currentPresent, e = s.bootstrapPointers()
	if e != nil || activeID != "" || currentPresent {
		return "", ErrUpgradeJournalConflict
	}
	return digest, nil
}

// PublishInitialPointers consumes an already-durable ACTIVATION_WRITTEN
// journal and publishes only active/current. It accepts an exact active-only
// crash prefix, rejects every foreign partial state, and never creates a slot.
func (s *BootstrapStore) PublishInitialPointers(ctx context.Context, j BootstrapJournalV1, a ActivationV1) (string, error) {
	if j.State != BootstrapActivationWritten || !validBootstrapActivationBinding(j, a) || !s.exactDurableBootstrapJournal(ctx, j) {
		return "", ErrUpgradeJournalConflict
	}
	raw, e := MarshalActivationV1(a)
	sum := sha256.Sum256(raw)
	if e != nil || hex.EncodeToString(sum[:]) != j.ActivationJSONSHA256 || !s.exactActivationSlot(a.ActivationID, j.ActivationJSONSHA256) {
		return "", ErrUpgradeJournalConflict
	}
	marker, e := s.upgrade.markerTransaction()
	if e != nil || marker != j.TransactionID {
		return "", ErrUpgradeJournalConflict
	}
	activeID, currentPresent, e := s.bootstrapPointers()
	if e != nil {
		return "", ErrUpgradeJournalConflict
	}
	if (activeID != "" && activeID != a.ActivationID) || (activeID == "" && currentPresent) {
		return "", ErrUpgradeJournalConflict
	}
	if activeID != "" && !s.exactActive(a.ActivationID, j.ActivationJSONSHA256) {
		return "", ErrUpgradeJournalConflict
	}
	if activeID == "" {
		if e = s.upgrade.activationWriter.SwapActivationLink(ActivationLinkActive, a.ActivationID, ""); e != nil && !s.exactActive(a.ActivationID, j.ActivationJSONSHA256) {
			return "", e
		}
	}
	if !currentPresent {
		if e = s.upgrade.activationWriter.SwapActivationLink(ActivationLinkCurrent, "", ""); e != nil && !s.exactCurrent() {
			return "", e
		}
	} else if !s.exactCurrent() {
		return "", ErrUpgradeJournalConflict
	}
	return s.pointerState(a.ActivationID, j.ActivationJSONSHA256)
}

func (s *BootstrapStore) exactActivationSlot(id, digest string) bool {
	_, got, e := s.upgrade.readActivation(id)
	return e == nil && got == digest
}

func sameBootstrapJournal(left, right BootstrapJournalV1) bool {
	l, lerr := MarshalBootstrapJournalV1(left)
	r, rerr := MarshalBootstrapJournalV1(right)
	return lerr == nil && rerr == nil && bytes.Equal(l, r)
}
func (s *BootstrapStore) exactActive(id, digest string) bool {
	if !s.exactActivationSlot(id, digest) {
		return false
	}
	target, e := s.upgrade.activationWriter.ReadActivationLink(ActivationLinkActive)
	return e == nil && target == "activations/"+id
}
func (s *BootstrapStore) exactCurrent() bool {
	target, e := s.upgrade.activationWriter.ReadActivationLink(ActivationLinkCurrent)
	return e == nil && target == "active/release"
}
func (s *BootstrapStore) pointerState(id, digest string) (string, error) {
	if !s.exactActive(id, digest) || !s.exactCurrent() {
		return "", ErrUpgradeJournalConflict
	}
	if _, e := s.upgrade.activationWriter.ReadActivationLink(ActivationLinkPreviousActive); !errors.Is(e, os.ErrNotExist) {
		return "", ErrUpgradeJournalConflict
	}
	raw, err := json.Marshal(bootstrapPointerStateV1{ActiveActivationID: id, ActiveActivationJSONSHA256: digest, CurrentTarget: "active/release", PreviousAbsent: true})
	if err != nil {
		return "", ErrUpgradeJournalConflict
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func (s *BootstrapStore) bootstrapPointers() (string, bool, error) {
	if _, e := s.upgrade.activationWriter.ReadActivationLink(ActivationLinkPreviousActive); !errors.Is(e, os.ErrNotExist) {
		return "", false, ErrUpgradeJournalConflict
	}
	active, e := s.upgrade.activationWriter.ReadActivationLink(ActivationLinkActive)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return "", false, ErrUpgradeJournalConflict
	}
	if active != "" && (!strings.HasPrefix(active, "activations/") || !validID(strings.TrimPrefix(active, "activations/"))) {
		return "", false, ErrUpgradeJournalConflict
	}
	current, e := s.upgrade.activationWriter.ReadActivationLink(ActivationLinkCurrent)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return "", false, ErrUpgradeJournalConflict
	}
	if current != "" && current != "active/release" {
		return "", false, ErrUpgradeJournalConflict
	}
	return strings.TrimPrefix(active, "activations/"), current != "", nil
}

func (s *BootstrapStore) Close() error {
	if s == nil || s.upgrade == nil {
		return nil
	}
	upgrade := s.upgrade
	s.upgrade = nil
	return upgrade.Close()
}
