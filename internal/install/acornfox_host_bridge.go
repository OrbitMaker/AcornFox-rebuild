package install

import (
	"context"
	"encoding/json"
	"errors"
)

// AcornFoxHostBootstrapReceiptV1 is the deliberately small public result of
// repository preparation. It contains durable identities only; paths, uid/gid,
// timestamps, and host configuration must never escape this boundary.
type AcornFoxHostBootstrapReceiptV1 struct {
	SchemaVersion          int    `json:"schema_version"`
	State                  string `json:"state"`
	BindingSHA256          string `json:"binding_sha256"`
	ReleaseID              string `json:"release_id"`
	SourceCommit           string `json:"source_commit"`
	LayoutSHA256           string `json:"layout_sha256"`
	SubstrateReceiptSHA256 string `json:"substrate_receipt_sha256"`
	FinalEvidenceSHA256    string `json:"final_evidence_sha256"`
}

func (r AcornFoxHostBootstrapReceiptV1) Validate() error {
	if r.SchemaVersion != 1 || r.State != string(AcornFoxRepoPreparedFinal) || !validSHA(r.BindingSHA256) || !validID(r.ReleaseID) || len(r.SourceCommit) != 40 || !validSHA(r.LayoutSHA256) || !validSHA(r.SubstrateReceiptSHA256) || !validSHA(r.FinalEvidenceSHA256) {
		return errors.New("AcornFox host bootstrap receipt is invalid")
	}
	return nil
}

func MarshalAcornFoxHostBootstrapReceiptV1(r AcornFoxHostBootstrapReceiptV1) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

func ParseAcornFoxHostBootstrapReceiptV1(raw []byte) (AcornFoxHostBootstrapReceiptV1, error) {
	var r AcornFoxHostBootstrapReceiptV1
	if err := strictCanonicalJSON(raw, &r, "AcornFox host bootstrap receipt"); err != nil {
		return r, err
	}
	return r, r.Validate()
}

// BootstrapAcornFoxHostV1 is intentionally the only production bootstrap
// entrypoint. It has no root, account, unit, service, database, or network
// configuration knobs. The fixed constructor is not called by tests.
func BootstrapAcornFoxHostV1(ctx context.Context, candidate AcornFoxCandidateSetRequestV1) (AcornFoxHostBootstrapReceiptV1, error) {
	layout, err := newProductionAcornFoxLayout()
	if err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, err
	}
	return newAcornFoxHostBridge(layout, newAcornFoxProductionSelfVerifier()).bootstrap(ctx, candidate)
}

// RecoverAcornFoxHostV1 resumes only durable AcornFox state. In particular it
// accepts no candidate directory: recovery must not silently exchange the
// bytes that were verified before the initial state transition.
func RecoverAcornFoxHostV1(ctx context.Context) (AcornFoxHostBootstrapReceiptV1, error) {
	layout, err := newProductionAcornFoxLayout()
	if err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, err
	}
	return newAcornFoxHostBridge(layout, newAcornFoxProductionSelfVerifier()).recover(ctx)
}

// acornFoxHostBridge is package-private so temporary production layouts can
// exercise the exact sequence without granting callers a configurable host
// installer. Tests supply an already validated layout and a fake ownership
// edge after construction.
type acornFoxHostBridge struct {
	layout    acornFoxInstallLayout
	self      acornFoxSelfVerifier
	ownership acornFoxOwnershipEdge
}

func newAcornFoxHostBridge(layout acornFoxInstallLayout, self acornFoxSelfVerifier) acornFoxHostBridge {
	return acornFoxHostBridge{layout: layout, self: self, ownership: newAcornFoxRealOwnershipEdge()}
}

func (b acornFoxHostBridge) bootstrap(ctx context.Context, request AcornFoxCandidateSetRequestV1) (AcornFoxHostBootstrapReceiptV1, error) {
	// Candidate and self verification precede every state-root constructor.
	set, err := loadAcornFoxCandidateSet(request, nil, b.self)
	if err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, err
	}
	defer set.Close()
	return b.finish(ctx, set)
}

func (b acornFoxHostBridge) recover(ctx context.Context) (AcornFoxHostBootstrapReceiptV1, error) {
	if ctx == nil || ctx.Err() != nil || b.layout.validate() != nil {
		return AcornFoxHostBootstrapReceiptV1{}, ErrAcornFoxRepoRecoveryUnknown
	}
	publisher, err := newAcornFoxSubstratePublisherForLayout(b.layout)
	if err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, ErrAcornFoxRepoRecoveryUnknown
	}
	defer publisher.Close()
	store, err := newAcornFoxRepoStoreForLayout(b.layout)
	if err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, ErrAcornFoxRepoRecoveryUnknown
	}
	store.ownership = b.ownership
	defer store.Close()
	journal, err := store.Resume(ctx)
	if err != nil || journal.LayoutSHA256 != b.layout.evidence() || !validSHA(journal.BindingSHA256) {
		return AcornFoxHostBootstrapReceiptV1{}, ErrAcornFoxRepoRecoveryUnknown
	}
	if _, err = newAcornFoxBindingStore(store).Read(journal.BindingSHA256); err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, ErrAcornFoxRepoRecoveryUnknown
	}
	substrate, err := b.reopenSubstrate(ctx, publisher, journal.BindingSHA256)
	if err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, err
	}
	defer substrate.Close()
	return b.materializeAndPrepare(ctx, store, substrate, journal.BindingSHA256)
}

func (b acornFoxHostBridge) finish(ctx context.Context, set *acornFoxCandidateSet) (AcornFoxHostBootstrapReceiptV1, error) {
	if ctx == nil || ctx.Err() != nil || set == nil || !set.binding.valid() || b.layout.validate() != nil {
		return AcornFoxHostBootstrapReceiptV1{}, ErrAcornFoxRepoBootstrapConflict
	}
	stager, err := newAcornFoxStagerForLayout(b.layout)
	if err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, err
	}
	defer stager.Close()
	publisher, err := newAcornFoxSubstratePublisherForLayout(b.layout)
	if err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, err
	}
	defer publisher.Close()
	store, err := newAcornFoxRepoStoreForLayout(b.layout)
	if err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, err
	}
	store.ownership = b.ownership
	defer store.Close()

	inspection, err := publisher.Inspect(set.bindingSHA256)
	if err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, err
	}
	var substrate *PublishedAcornFoxSubstrateV1
	switch inspection.Outcome {
	case AcornFoxReconcileAbsent:
		input, inputErr := set.stageInput()
		if inputErr != nil {
			return AcornFoxHostBootstrapReceiptV1{}, inputErr
		}
		stage, _, stageErr := stager.Stage(input)
		if stageErr != nil {
			return AcornFoxHostBootstrapReceiptV1{}, stageErr
		}
		// A post-stage failure must close the handle rather than leaving an
		// ordinary error looking like an orphaned recovery capability.
		published := false
		defer func() {
			if !published {
				if closeErr := stage.Close(); closeErr != nil {
					_ = stage.retryCleanup()
				}
			}
		}()
		if err = newAcornFoxBindingStore(store).Put(set.bindingRaw); err != nil {
			return AcornFoxHostBootstrapReceiptV1{}, err
		}
		if _, err = publisher.Publish(ctx, &stage, set.bindingSHA256); err != nil {
			return AcornFoxHostBootstrapReceiptV1{}, err
		}
		published = true
	case AcornFoxReconcileResume:
		if err = newAcornFoxBindingStore(store).Put(set.bindingRaw); err != nil {
			return AcornFoxHostBootstrapReceiptV1{}, err
		}
		if _, err = publisher.Resume(ctx, set.bindingSHA256); err != nil {
			return AcornFoxHostBootstrapReceiptV1{}, err
		}
	case AcornFoxReconcileCompleted:
		if err = newAcornFoxBindingStore(store).Put(set.bindingRaw); err != nil {
			return AcornFoxHostBootstrapReceiptV1{}, err
		}
	default:
		return AcornFoxHostBootstrapReceiptV1{}, ErrAcornFoxRepoBootstrapConflict
	}
	substrate, err = publisher.Reopen(set.bindingSHA256)
	if err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, err
	}
	defer substrate.Close()
	if err = b.ensurePreparedJournal(ctx, store, substrate, set.bindingSHA256); err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, err
	}
	return b.materializeAndPrepare(ctx, store, substrate, set.bindingSHA256)
}

func (b acornFoxHostBridge) reopenSubstrate(ctx context.Context, publisher *TaskAcornFoxSubstratePublisher, binding string) (*PublishedAcornFoxSubstrateV1, error) {
	inspection, err := publisher.Inspect(binding)
	if err != nil || inspection.Outcome != AcornFoxReconcileCompleted {
		return nil, ErrAcornFoxRepoRecoveryUnknown
	}
	return publisher.Reopen(binding)
}

func (b acornFoxHostBridge) ensurePreparedJournal(ctx context.Context, store *TaskAcornFoxRepoStore, substrate *PublishedAcornFoxSubstrateV1, binding string) error {
	raw, err := MarshalInactiveSubstrateReceiptV1(substrate.receipt)
	if err != nil {
		return ErrAcornFoxRepoBootstrapConflict
	}
	want, err := newAcornFoxRepoJournalForLayout(b.layout, binding, sha256Hex(raw))
	if err != nil {
		return err
	}
	lock, err := store.Acquire(ctx)
	if err != nil {
		return err
	}
	defer lock.Release()
	got, readErr := store.Load(ctx)
	if readErr == nil {
		if got.BindingSHA256 != want.BindingSHA256 || got.LayoutSHA256 != want.LayoutSHA256 || got.SubstrateReceiptSHA256 != want.SubstrateReceiptSHA256 {
			return ErrAcornFoxRepoBootstrapConflict
		}
		return nil
	}
	return store.Create(ctx, want)
}

func (b acornFoxHostBridge) materializeAndPrepare(ctx context.Context, store *TaskAcornFoxRepoStore, substrate *PublishedAcornFoxSubstrateV1, binding string) (AcornFoxHostBootstrapReceiptV1, error) {
	if current, err := store.Resume(ctx); err == nil && current.Phase == AcornFoxRepoPreparedFinal {
		return b.receiptForJournal(current, substrate, binding)
	}
	if _, err := materializeAcornFoxLive(ctx, store, substrate, binding); err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, err
	}
	if err := prepareAcornFoxRepository(ctx, store, substrate, binding); err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, err
	}
	journal, err := store.Resume(ctx)
	if err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, ErrAcornFoxRepoBootstrapConflict
	}
	return b.receiptForJournal(journal, substrate, binding)
}

func (b acornFoxHostBridge) receiptForJournal(journal AcornFoxRepoJournalV1, substrate *PublishedAcornFoxSubstrateV1, binding string) (AcornFoxHostBootstrapReceiptV1, error) {
	if substrate == nil || journal.Phase != AcornFoxRepoPreparedFinal || journal.BindingSHA256 != binding || journal.LayoutSHA256 != b.layout.evidence() {
		return AcornFoxHostBootstrapReceiptV1{}, ErrAcornFoxRepoBootstrapConflict
	}
	final, err := AcornFoxRepoFinalEvidence(journal)
	if err != nil {
		return AcornFoxHostBootstrapReceiptV1{}, err
	}
	receipt := AcornFoxHostBootstrapReceiptV1{SchemaVersion: 1, State: string(AcornFoxRepoPreparedFinal), BindingSHA256: binding, ReleaseID: substrate.receipt.CandidateReceipt.ReleaseID, SourceCommit: substrate.receipt.CandidateReceipt.SourceCommit, LayoutSHA256: b.layout.evidence(), SubstrateReceiptSHA256: journal.SubstrateReceiptSHA256, FinalEvidenceSHA256: final}
	return receipt, receipt.Validate()
}
