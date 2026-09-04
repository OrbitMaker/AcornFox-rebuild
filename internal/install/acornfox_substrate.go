package install

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

var (
	ErrAcornFoxSubstrateRecoveryRequired = errors.New("AcornFox substrate recovery is required")
	ErrAcornFoxSubstrateConflict         = errors.New("AcornFox substrate conflicts with task state")
)

const (
	acornFoxSubstrateDir     = "substrate"
	acornFoxSubstrateRootfs  = "substrate/rootfs"
	acornFoxSubstrateIntent  = "substrate/intent.json"
	acornFoxSubstrateReceipt = "substrate/receipt.json"
	acornFoxSubstrateLock    = ".acornfox-substrate.lock"
)

// TaskAcornFoxSubstratePublisher is deliberately task-root-only. It has no
// production path, service, network, database, or activation capability.
type TaskAcornFoxSubstratePublisher struct {
	rootPath string
	rootInfo os.FileInfo
	root     *os.Root
	uid, gid int
	fs       acornFoxSubstrateFS
	// afterRootPathCheck is a package-private race seam. It must never affect
	// authority: the returned root is always derived from p.root.
	afterRootPathCheck func()
}

type AcornFoxSubstratePublishResult struct {
	Receipt InactiveSubstrateReceiptV1
	Outcome AcornFoxReconciliationOutcome
}

type AcornFoxSubstrateInspection struct {
	Outcome AcornFoxReconciliationOutcome
	Receipt InactiveSubstrateReceiptV1
}

type PublishedAcornFoxSubstrateV1 struct {
	root      *os.Root
	receipt   InactiveSubstrateReceiptV1
	uid, gid  int
	fs        acornFoxSubstrateFS
	publisher *TaskAcornFoxSubstratePublisher
}

func NewTaskAcornFoxSubstratePublisher(taskRoot string, uid, gid int) (*TaskAcornFoxSubstratePublisher, error) {
	fs := newAcornFoxSubstrateFS()
	if uid < 0 || gid < 0 || !safeAbsoluteDurableRoot(taskRoot) || forbiddenAcornFoxStageRoot(taskRoot) {
		return nil, errors.New("AcornFox task substrate root is unsafe")
	}
	info, err := fs.lstatPath(taskRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || verifyOwner(info, uid, gid) != nil {
		return nil, errors.New("AcornFox task substrate root is unsafe")
	}
	root, err := fs.openRootPath(taskRoot)
	if err != nil {
		return nil, err
	}
	return &TaskAcornFoxSubstratePublisher{rootPath: taskRoot, rootInfo: info, root: root, uid: uid, gid: gid, fs: fs}, nil
}

func (p *TaskAcornFoxSubstratePublisher) openRoot() (*os.Root, error) {
	if p == nil || p.root == nil || p.rootInfo == nil {
		return nil, errors.New("AcornFox substrate publisher is not initialized")
	}
	info, err := p.fs.lstatPath(p.rootPath)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || !os.SameFile(info, p.rootInfo) || verifyOwner(info, p.uid, p.gid) != nil {
		return nil, errors.New("AcornFox task substrate root identity changed")
	}
	if p.afterRootPathCheck != nil {
		p.afterRootPathCheck()
	}
	return p.fs.openRoot(p.root, ".")
}

// Close releases the constructor-held task-root descriptor. It is idempotent;
// every later operation fails rather than reopening rootPath by name.
func (p *TaskAcornFoxSubstratePublisher) Close() error {
	if p == nil || p.root == nil {
		return nil
	}
	root := p.root
	p.root = nil
	return root.Close()
}

// Publish creates an inactive substrate only from an absent task-root state.
func (p *TaskAcornFoxSubstratePublisher) Publish(ctx context.Context, stage *StagedAcornFoxCandidateV1, expectedBindingSHA256 string) (AcornFoxSubstratePublishResult, error) {
	lock, err := p.lock()
	if err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	defer lock.Close()
	if err := p.reconcileOwnedTempsLocked(expectedBindingSHA256); err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	return p.publishLocked(ctx, stage, expectedBindingSHA256, AcornFoxReconcileAbsent)
}

func (p *TaskAcornFoxSubstratePublisher) publishLocked(ctx context.Context, stage *StagedAcornFoxCandidateV1, expectedBindingSHA256 string, permitted AcornFoxReconciliationOutcome) (AcornFoxSubstratePublishResult, error) {
	if p == nil || stage == nil || !digestPattern.MatchString(expectedBindingSHA256) {
		return AcornFoxSubstratePublishResult{}, errors.New("AcornFox substrate publish input is invalid")
	}
	inspection, err := p.inspectLocked(expectedBindingSHA256)
	if err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	if inspection.Outcome == AcornFoxReconcileCompleted {
		return AcornFoxSubstratePublishResult{Receipt: inspection.Receipt, Outcome: AcornFoxReconcileCompleted}, nil
	}
	if inspection.Outcome == AcornFoxReconcileCleanupUnknown {
		return AcornFoxSubstratePublishResult{Receipt: inspection.Receipt, Outcome: inspection.Outcome}, ErrAcornFoxStageCleanupUnknown
	}
	if inspection.Outcome != permitted {
		return AcornFoxSubstratePublishResult{}, acornFoxSubstrateOutcomeError(inspection.Outcome)
	}
	lease, err := stage.claimForPublish()
	if err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	committed := false
	defer func() {
		if !committed {
			lease.releaseFailure()
		}
	}()
	candidate, ok := lease.receipt()
	if !ok || candidate.BindingSHA256 != expectedBindingSHA256 {
		return AcornFoxSubstratePublishResult{}, errors.New("AcornFox staged binding is invalid")
	}
	if !p.ownsStageParent(stage) {
		return AcornFoxSubstratePublishResult{}, errors.New("AcornFox staged parent is not this task root")
	}
	source, err := lease.openSourceRoot()
	if err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	defer source.Close()
	manifest, err := acornFoxSubstrateManifest(source, candidate)
	if err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	entries, err := acornFoxSubstrateEntries(source, candidate, manifest)
	if err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	installed, err := ComputeAcornFoxSubstrateTreeSHA256(entries)
	if err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	intent := AcornFoxInactiveSubstrateIntentV1{SchemaVersion: InactiveSubstrateReceiptV1Schema, LayoutVersion: AcornFoxSubstrateLayoutV1, CandidateReceipt: candidate, ExpectedEntryEnvelopeSHA256: installed}
	root, err := p.openRoot()
	if err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	defer root.Close()
	if err := acornFoxSubstrateWriteIntent(p.fs, root, intent, p.uid, p.gid); err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	if err := acornFoxSubstrateCreateDirs(p.fs, root, entries, p.uid, p.gid); err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	if err := acornFoxSubstrateCopyFiles(p.fs, ctx, root, source, entries, candidate, p.uid, p.gid); err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	installed, err = ComputeAcornFoxSubstrateTreeSHA256(entries)
	if err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	receipt := InactiveSubstrateReceiptV1{SchemaVersion: InactiveSubstrateReceiptV1Schema, State: "inactive_complete", LayoutVersion: AcornFoxSubstrateLayoutV1, CandidateReceipt: candidate, ReleaseTreeSHA256: candidate.TreeSHA256, InstalledTreeSHA256: installed, UpgradeHelperSHA256: substrateEntryAt(entries, AcornFoxUpgradeHelperPath).SHA256, HealthHelperSHA256: substrateEntryAt(entries, AcornFoxHealthcheckHelperPath(candidate)).SHA256, Entries: entries}
	if err := receipt.Validate(); err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	if err := acornFoxSubstrateWriteReleaseControl(p.fs, root, receipt, p.uid, p.gid); err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	if err := acornFoxSubstrateWriteReceipt(p.fs, root, receipt, p.uid, p.gid); err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	if err := lease.consume(); err != nil {
		return AcornFoxSubstratePublishResult{Receipt: receipt, Outcome: AcornFoxReconcileCleanupUnknown}, ErrAcornFoxStageCleanupUnknown
	}
	committed = true
	return AcornFoxSubstratePublishResult{Receipt: receipt, Outcome: AcornFoxReconcileCompleted}, nil
}

func (p *TaskAcornFoxSubstratePublisher) ownsStageParent(stage *StagedAcornFoxCandidateV1) bool {
	if p == nil || p.root == nil || stage == nil || stage.state == nil || stage.state.parent == nil {
		return false
	}
	stageDir, err := stage.state.parent.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	stageInfo, stageErr := stageDir.Stat()
	closeStageErr := stageDir.Close()
	rootDir, rootErr := p.root.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if rootErr != nil {
		return false
	}
	rootInfo, rootStatErr := rootDir.Stat()
	closeRootErr := rootDir.Close()
	return stageErr == nil && closeStageErr == nil && rootStatErr == nil && closeRootErr == nil && os.SameFile(stageInfo, rootInfo) && verifyOwner(stageInfo, p.uid, p.gid) == nil
}

// Resume reacquires the only matching sealed task stage after a process exit.
// It never accepts a caller-supplied stage path.
func (p *TaskAcornFoxSubstratePublisher) Resume(ctx context.Context, expectedBindingSHA256 string) (AcornFoxSubstratePublishResult, error) {
	lock, err := p.lock()
	if err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	defer lock.Close()
	if err := p.reconcileOwnedTempsLocked(expectedBindingSHA256); err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	inspection, err := p.inspectLocked(expectedBindingSHA256)
	if err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	if inspection.Outcome != AcornFoxReconcileResume {
		return AcornFoxSubstratePublishResult{}, acornFoxSubstrateOutcomeError(inspection.Outcome)
	}
	stage, err := p.reopenStage(expectedBindingSHA256)
	if err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	defer stage.Close()
	return p.publishLocked(ctx, stage, expectedBindingSHA256, AcornFoxReconcileResume)
}

func (p *TaskAcornFoxSubstratePublisher) reconcileOwnedTempsLocked(expectedBindingSHA256 string) error {
	root, err := p.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	raw, err := acornFoxSubstrateReadControl(p.fs, root, acornFoxSubstrateReceipt, p.uid, p.gid)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrAcornFoxSubstrateConflict
	}
	receipt, err := ParseInactiveSubstrateReceiptV1(raw)
	if err != nil || receipt.CandidateReceipt.BindingSHA256 != expectedBindingSHA256 {
		return ErrAcornFoxSubstrateConflict
	}
	return acornFoxSubstrateRemoveOwnedTemps(p.fs, root, receipt.Entries, p.uid, p.gid)
}

func acornFoxSubstrateOutcomeError(outcome AcornFoxReconciliationOutcome) error {
	if outcome == AcornFoxReconcileConflict {
		return ErrAcornFoxSubstrateConflict
	}
	return ErrAcornFoxSubstrateRecoveryRequired
}

// Inspect classifies only pinned task-root durable state. It does not mint a
// stage capability or mutate rootfs.
func (p *TaskAcornFoxSubstratePublisher) Inspect(expectedBindingSHA256 string) (AcornFoxSubstrateInspection, error) {
	if p == nil || !digestPattern.MatchString(expectedBindingSHA256) {
		return AcornFoxSubstrateInspection{}, errors.New("AcornFox substrate inspect input is invalid")
	}
	lock, err := p.lock()
	if err != nil {
		return AcornFoxSubstrateInspection{}, err
	}
	defer lock.Close()
	return p.inspectLocked(expectedBindingSHA256)
}

func (p *TaskAcornFoxSubstratePublisher) inspectLocked(expectedBindingSHA256 string) (AcornFoxSubstrateInspection, error) {
	root, err := p.openRoot()
	if err != nil {
		return AcornFoxSubstrateInspection{}, err
	}
	defer root.Close()
	raw, receiptErr := acornFoxSubstrateReadControl(p.fs, root, acornFoxSubstrateReceipt, p.uid, p.gid)
	if receiptErr == nil {
		receipt, parseErr := ParseInactiveSubstrateReceiptV1(raw)
		if parseErr != nil || receipt.CandidateReceipt.BindingSHA256 != expectedBindingSHA256 {
			return AcornFoxSubstrateInspection{Outcome: AcornFoxReconcileConflict}, nil
		}
		handle := &PublishedAcornFoxSubstrateV1{root: root, receipt: receipt, uid: p.uid, gid: p.gid, fs: p.fs}
		if verifyErr := handle.Verify(); verifyErr != nil {
			handle.root = nil
			return AcornFoxSubstrateInspection{Outcome: acornFoxSubstrateVerificationOutcome(verifyErr)}, nil
		}
		handle.root = nil
		switch p.stageDisposition(expectedBindingSHA256) {
		case AcornFoxReconcileRecoveryRequired:
			return AcornFoxSubstrateInspection{Outcome: AcornFoxReconcileCompleted, Receipt: receipt}, nil
		case AcornFoxReconcileConflict:
			return AcornFoxSubstrateInspection{Outcome: AcornFoxReconcileConflict, Receipt: receipt}, nil
		default:
			return AcornFoxSubstrateInspection{Outcome: AcornFoxReconcileCleanupUnknown, Receipt: receipt}, nil
		}
	}
	if !errors.Is(receiptErr, os.ErrNotExist) {
		return AcornFoxSubstrateInspection{Outcome: AcornFoxReconcileConflict}, nil
	}
	intentRaw, intentErr := acornFoxSubstrateReadControl(p.fs, root, acornFoxSubstrateIntent, p.uid, p.gid)
	if errors.Is(intentErr, os.ErrNotExist) {
		return AcornFoxSubstrateInspection{Outcome: AcornFoxReconcileAbsent}, nil
	}
	if intentErr != nil {
		return AcornFoxSubstrateInspection{Outcome: AcornFoxReconcileConflict}, nil
	}
	intent, parseErr := ParseAcornFoxInactiveSubstrateIntentV1(intentRaw)
	if parseErr != nil || intent.CandidateReceipt.BindingSHA256 != expectedBindingSHA256 {
		return AcornFoxSubstrateInspection{Outcome: AcornFoxReconcileConflict}, nil
	}
	return AcornFoxSubstrateInspection{Outcome: p.stageDisposition(expectedBindingSHA256)}, nil
}

// Validation errors are deterministic drift and therefore conflict evidence.
// OS I/O failures leave the durable state unreadable, so they are the narrow
// CommitUnknown case rather than permission to overwrite a terminal receipt.
func acornFoxSubstrateVerificationOutcome(err error) AcornFoxReconciliationOutcome {
	if errors.Is(err, ErrAcornFoxSubstrateConflict) {
		return AcornFoxReconcileConflict
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return AcornFoxReconcileCommitUnknown
	}
	return AcornFoxReconcileConflict
}

func (p *TaskAcornFoxSubstratePublisher) Reopen(expectedBindingSHA256 string) (*PublishedAcornFoxSubstrateV1, error) {
	if p == nil || !digestPattern.MatchString(expectedBindingSHA256) {
		return nil, errors.New("AcornFox substrate reopen input is invalid")
	}
	lock, err := p.lock()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	return p.reopenLocked(expectedBindingSHA256)
}

func (p *TaskAcornFoxSubstratePublisher) reopenLocked(expectedBindingSHA256 string) (*PublishedAcornFoxSubstrateV1, error) {
	if p == nil || !digestPattern.MatchString(expectedBindingSHA256) {
		return nil, errors.New("AcornFox substrate reopen input is invalid")
	}
	root, err := p.openRoot()
	if err != nil {
		return nil, err
	}
	raw, err := acornFoxSubstrateReadControl(p.fs, root, acornFoxSubstrateReceipt, p.uid, p.gid)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			root.Close()
			return nil, err
		}
		intentRaw, intentErr := acornFoxSubstrateReadControl(p.fs, root, acornFoxSubstrateIntent, p.uid, p.gid)
		root.Close()
		if errors.Is(intentErr, os.ErrNotExist) {
			return nil, ErrAcornFoxSubstrateRecoveryRequired
		}
		intent, parseErr := ParseAcornFoxInactiveSubstrateIntentV1(intentRaw)
		if parseErr != nil || intent.CandidateReceipt.BindingSHA256 != expectedBindingSHA256 {
			return nil, ErrAcornFoxSubstrateConflict
		}
		if !p.hasReopenableStage(expectedBindingSHA256) {
			return nil, ErrAcornFoxSubstrateRecoveryRequired
		}
		return nil, ErrAcornFoxSubstrateRecoveryRequired
	}
	receipt, err := ParseInactiveSubstrateReceiptV1(raw)
	if err != nil || receipt.CandidateReceipt.BindingSHA256 != expectedBindingSHA256 {
		root.Close()
		return nil, ErrAcornFoxSubstrateConflict
	}
	handle := &PublishedAcornFoxSubstrateV1{root: root, receipt: receipt, uid: p.uid, gid: p.gid, fs: p.fs, publisher: p}
	if err := handle.Verify(); err != nil {
		root.Close()
		return nil, err
	}
	return handle, nil
}

func (p *TaskAcornFoxSubstratePublisher) hasReopenableStage(expectedBindingSHA256 string) bool {
	return p.stageDisposition(expectedBindingSHA256) == AcornFoxReconcileResume
}

func acornFoxStageReceiptCanonical(raw []byte, receipt AcornFoxStageReceiptV1) bool {
	canonical, err := json.Marshal(receipt)
	return err == nil && string(raw) == string(canonical)
}

// stageDisposition makes the resumability decision from one complete scan:
// no candidate is recoverable, exactly one matching candidate is resumable,
// while a mismatching or ambiguous stage set is conflict evidence.
func (p *TaskAcornFoxSubstratePublisher) stageDisposition(expectedBindingSHA256 string) AcornFoxReconciliationOutcome {
	parent, err := p.openRoot()
	if err != nil {
		return AcornFoxReconcileCommitUnknown
	}
	defer parent.Close()
	directory, err := p.fs.openFile(parent, ".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return AcornFoxReconcileCommitUnknown
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return AcornFoxReconcileCommitUnknown
	}
	matches := 0
	mismatch := false
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), ".acornfox-stage-") {
			continue
		}
		stageRoot, openErr := p.fs.openRoot(parent, entry.Name())
		if openErr != nil {
			return AcornFoxReconcileCommitUnknown
		}
		raw, readErr := acornFoxSubstrateReadControl(p.fs, stageRoot, ".acornfox-stage-complete.json", p.uid, p.gid)
		var receipt AcornFoxStageReceiptV1
		closeStageErr := stageRoot.Close()
		if readErr != nil || closeStageErr != nil {
			return AcornFoxReconcileCommitUnknown
		}
		valid := json.Unmarshal(raw, &receipt) == nil && acornFoxStageReceiptCanonical(raw, receipt) && receipt.Validate() == nil
		if valid && receipt.BindingSHA256 == expectedBindingSHA256 {
			matches++
		} else {
			mismatch = true
		}
	}
	if mismatch || matches > 1 {
		return AcornFoxReconcileConflict
	}
	if matches == 1 {
		return AcornFoxReconcileResume
	}
	return AcornFoxReconcileRecoveryRequired
}

func (p *TaskAcornFoxSubstratePublisher) reopenStage(expectedBindingSHA256 string) (*StagedAcornFoxCandidateV1, error) {
	if p == nil || !digestPattern.MatchString(expectedBindingSHA256) {
		return nil, errors.New("AcornFox substrate stage reopen input is invalid")
	}
	parent, err := p.openRoot()
	if err != nil {
		return nil, err
	}
	directory, err := p.fs.openFile(parent, ".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		parent.Close()
		return nil, err
	}
	entries, err := directory.ReadDir(-1)
	directory.Close()
	if err != nil {
		parent.Close()
		return nil, err
	}
	var matches []struct {
		name    string
		root    *os.Root
		receipt AcornFoxStageReceiptV1
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), ".acornfox-stage-") {
			continue
		}
		stageRoot, openErr := p.fs.openRoot(parent, entry.Name())
		if openErr != nil {
			continue
		}
		raw, readErr := acornFoxSubstrateReadControl(p.fs, stageRoot, ".acornfox-stage-complete.json", p.uid, p.gid)
		var receipt AcornFoxStageReceiptV1
		if readErr != nil || json.Unmarshal(raw, &receipt) != nil || !acornFoxStageReceiptCanonical(raw, receipt) || receipt.BindingSHA256 != expectedBindingSHA256 || receipt.Validate() != nil {
			stageRoot.Close()
			continue
		}
		matches = append(matches, struct {
			name    string
			root    *os.Root
			receipt AcornFoxStageReceiptV1
		}{entry.Name(), stageRoot, receipt})
	}
	if len(matches) != 1 {
		for _, match := range matches {
			match.root.Close()
		}
		parent.Close()
		if len(matches) > 1 {
			return nil, ErrAcornFoxSubstrateConflict
		}
		return nil, ErrAcornFoxSubstrateRecoveryRequired
	}
	match := matches[0]
	state := &acornFoxStageState{phase: acornFoxStageLive, root: match.root, parent: parent, stageName: match.name, receipt: match.receipt, uid: p.uid, gid: p.gid, seal: &acornFoxStageSeal{}}
	return &StagedAcornFoxCandidateV1{state: state}, nil
}

func (h *PublishedAcornFoxSubstrateV1) Verify() error {
	if h == nil || h.root == nil {
		return errors.New("AcornFox substrate handle is invalid")
	}
	if err := h.receipt.Validate(); err != nil {
		return err
	}
	if err := h.verifyControlFiles(); err != nil {
		return err
	}
	actual, err := h.walkRootfs()
	if err != nil {
		return err
	}
	control := "var/lib/acornfox/install/releases/" + h.receipt.CandidateReceipt.ReleaseID + ".json"
	if _, ok := actual[control]; !ok {
		return errors.New("AcornFox substrate release control is missing")
	}
	delete(actual, control)
	if len(actual) != len(h.receipt.Entries) {
		return errors.New("AcornFox substrate rootfs set is not exact")
	}
	observed := append([]SubstrateEntry(nil), h.receipt.Entries...)
	for index := range observed {
		entry := &observed[index]
		if _, ok := actual[entry.Path]; !ok {
			return errors.New("AcornFox substrate rootfs misses receipt entry")
		}
		path := acornFoxSubstrateTarget(entry.Path)
		file, err := h.fs.openFile(h.root, path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		info, statErr := file.Stat()
		if statErr == nil && ((!info.Mode().IsRegular() && entry.Kind == SubstrateEntryFile) || (!info.IsDir() && entry.Kind == SubstrateEntryDirectory) || info.Mode().Perm() != os.FileMode(entry.Mode) || verifyOwner(info, h.uid, h.gid) != nil) {
			statErr = errors.New("AcornFox substrate disk entry is invalid")
		}
		if statErr == nil && entry.Kind == SubstrateEntryFile {
			entry.Size, entry.SHA256 = info.Size(), sha256SubstrateOpenFile(file)
			if entry.Size != h.receipt.Entries[index].Size || entry.SHA256 != h.receipt.Entries[index].SHA256 {
				statErr = errors.New("AcornFox substrate file digest is invalid")
			}
		}
		closeErr := file.Close()
		if statErr == nil {
			statErr = closeErr
		}
		if statErr != nil {
			return statErr
		}
	}
	installed, err := ComputeAcornFoxSubstrateTreeSHA256(observed)
	if err != nil || installed != h.receipt.InstalledTreeSHA256 {
		return errors.New("AcornFox substrate installed tree digest is invalid")
	}
	release, err := ComputeAcornFoxReleaseTreeSHA256(h.receipt.CandidateReceipt, observed)
	if err != nil || release != h.receipt.ReleaseTreeSHA256 {
		return errors.New("AcornFox substrate release tree digest is invalid")
	}
	return nil
}

func (h *PublishedAcornFoxSubstrateV1) verifyControlFiles() error {
	for _, path := range []string{acornFoxSubstrateDir, acornFoxSubstrateRootfs} {
		file, err := h.fs.openFile(h.root, path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		info, statErr := file.Stat()
		closeErr := file.Close()
		if statErr != nil || closeErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || verifyOwner(info, h.uid, h.gid) != nil {
			return errors.New("AcornFox substrate control directory is invalid")
		}
	}
	dir, err := h.fs.openFile(h.root, acornFoxSubstrateDir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	children, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil || closeErr != nil || len(children) != 3 {
		return errors.New("AcornFox substrate control set is not exact")
	}
	want := map[string]bool{"intent.json": true, "receipt.json": true, "rootfs": true}
	for _, child := range children {
		if !want[child.Name()] {
			return errors.New("AcornFox substrate control set has an extra entry")
		}
	}
	intentRaw, err := acornFoxSubstrateReadControl(h.fs, h.root, acornFoxSubstrateIntent, h.uid, h.gid)
	if err != nil {
		return err
	}
	intent, err := ParseAcornFoxInactiveSubstrateIntentV1(intentRaw)
	if err != nil || intent.CandidateReceipt.BindingSHA256 != h.receipt.CandidateReceipt.BindingSHA256 || intent.ExpectedEntryEnvelopeSHA256 != h.receipt.InstalledTreeSHA256 {
		return errors.New("AcornFox substrate intent binding is invalid")
	}
	raw, err := acornFoxSubstrateReadControl(h.fs, h.root, acornFoxSubstrateReceipt, h.uid, h.gid)
	if err != nil {
		return err
	}
	canonical, err := MarshalInactiveSubstrateReceiptV1(h.receipt)
	if err != nil || string(raw) != string(canonical) {
		return errors.New("AcornFox substrate receipt canonical evidence is invalid")
	}
	releaseControl := acornFoxSubstrateTarget("var/lib/acornfox/install/releases/" + h.receipt.CandidateReceipt.ReleaseID + ".json")
	releaseRaw, err := acornFoxSubstrateReadControl(h.fs, h.root, releaseControl, h.uid, h.gid)
	if err != nil || string(releaseRaw) != string(canonical) {
		return errors.New("AcornFox substrate release control evidence is invalid")
	}
	return nil
}

func (h *PublishedAcornFoxSubstrateV1) walkRootfs() (map[string]os.FileInfo, error) {
	actual := map[string]os.FileInfo{}
	var walk func(string) error
	walk = func(directory string) error {
		dir, err := h.fs.openFile(h.root, directory, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		children, readErr := dir.ReadDir(-1)
		closeErr := dir.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		for _, child := range children {
			path := filepath.ToSlash(filepath.Join(directory, child.Name()))
			info, err := h.fs.lstat(h.root, path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
				return errors.New("AcornFox substrate rootfs contains an unsafe entry")
			}
			relative := strings.TrimPrefix(path, acornFoxSubstrateRootfs+"/")
			actual[relative] = info
			if info.IsDir() {
				if err := walk(path); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(acornFoxSubstrateRootfs); err != nil {
		return nil, err
	}
	return actual, nil
}
func (h *PublishedAcornFoxSubstrateV1) Close() error {
	if h == nil || h.root == nil {
		return nil
	}
	root := h.root
	h.root = nil
	return root.Close()
}
func (h *PublishedAcornFoxSubstrateV1) Discard() error {
	if h == nil || h.root == nil {
		return errors.New("AcornFox substrate handle is invalid")
	}
	if h.publisher == nil {
		return errors.New("AcornFox substrate publisher is unavailable")
	}
	lock, err := h.publisher.lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	// The lock remains outside substrate. Reopen from the pinned publisher after
	// acquiring it so a stale handle cannot delete replacement task state.
	fresh, err := h.publisher.reopenLocked(h.receipt.CandidateReceipt.BindingSHA256)
	if err != nil {
		return err
	}
	defer fresh.Close()
	if err := fresh.Verify(); err != nil {
		return err
	}
	if err := h.fs.removeAll(fresh.root, acornFoxSubstrateDir); err != nil {
		return ErrAcornFoxStageCleanupUnknown
	}
	if err := h.fs.syncRoot(fresh.root); err != nil {
		return ErrAcornFoxStageCleanupUnknown
	}
	return nil
}

func acornFoxSubstrateTarget(path string) string {
	return filepath.ToSlash(filepath.Join(acornFoxSubstrateRootfs, path))
}

func acornFoxSubstrateManifest(source *os.Root, candidate AcornFoxStageReceiptV1) (Manifest, error) {
	raw, err := source.ReadFile("manifest.json")
	if err != nil || sha256Hex(raw) != candidate.ManifestSHA256 {
		return Manifest{}, errors.New("AcornFox substrate source manifest is invalid")
	}
	var manifest Manifest
	if err := strictCanonicalJSON(raw, &manifest, "AcornFox substrate manifest"); err != nil || manifest.Product != AcornFoxV1Product || manifest.Version != candidate.Version || manifest.ReleaseID != candidate.ReleaseID || manifest.SourceCommit != candidate.SourceCommit || len(manifest.Files) != candidate.FileCount {
		return Manifest{}, errors.New("AcornFox substrate source manifest is invalid")
	}
	return manifest, nil
}

func acornFoxSubstrateEntries(source *os.Root, candidate AcornFoxStageReceiptV1, manifest Manifest) ([]SubstrateEntry, error) {
	entries := []SubstrateEntry{}
	prefix := "opt/acornfox/releases/" + candidate.ReleaseID + "/"
	add := func(path string, mode uint32, digest string, size int64) {
		entries = append(entries, SubstrateEntry{Path: path, Kind: SubstrateEntryFile, Mode: mode, Role: OwnerRoleRoot, Group: GroupRoleRoot, Size: size, SHA256: digest})
	}
	if size, err := acornFoxSubstrateSourceEvidence(source, "manifest.json", 0o644, candidate.ManifestSHA256); err != nil {
		return nil, err
	} else {
		add(prefix+"manifest.json", 0o644, candidate.ManifestSHA256, size)
	}
	for _, file := range manifest.Files {
		size, err := acornFoxSubstrateSourceEvidence(source, file.Path, file.Mode, file.SHA256)
		if err != nil {
			return nil, err
		}
		add(prefix+file.Path, file.Mode, file.SHA256, size)
	}
	for path, entry := range acornFoxFixedSubstrateEntries(candidate) {
		entries = append(entries, entry)
		if entry.Kind == SubstrateEntryFile {
			sourcePath := acornFoxInstalledSource(candidate, path)
			sourceEntry := substrateEntryAt(entries, prefix+sourcePath)
			if sourceEntry != nil {
				entries[len(entries)-1].SHA256, entries[len(entries)-1].Size = sourceEntry.SHA256, sourceEntry.Size
			}
		}
	}
	for _, file := range append([]SubstrateEntry(nil), entries...) {
		if file.Kind != SubstrateEntryFile || !strings.HasPrefix(file.Path, prefix) {
			continue
		}
		for parent := parentDirectory(file.Path); strings.HasPrefix(parent, strings.TrimSuffix(prefix, "/")); parent = parentDirectory(parent) {
			entries = append(entries, SubstrateEntry{Path: parent, Kind: SubstrateEntryDirectory, Mode: 0o755, Role: OwnerRoleRoot, Group: GroupRoleRoot})
			if parent == strings.TrimSuffix(prefix, "/") {
				break
			}
		}
	}
	unique := map[string]SubstrateEntry{}
	for _, entry := range entries {
		unique[entry.Path] = entry
	}
	entries = entries[:0]
	for _, entry := range unique {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	if err := validateAcornFoxV1SubstrateInventory(candidate, entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func acornFoxSubstrateSourceEvidence(root *os.Root, path string, mode uint32, digest string) (int64, error) {
	file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	info, statErr := file.Stat()
	actual := sha256SubstrateOpenFile(file)
	closeErr := file.Close()
	if statErr != nil || closeErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != os.FileMode(mode) || actual != digest {
		return 0, errors.New("AcornFox substrate source evidence is invalid")
	}
	return info.Size(), nil
}
