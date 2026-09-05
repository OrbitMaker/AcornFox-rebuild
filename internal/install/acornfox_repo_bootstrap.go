package install

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var (
	ErrAcornFoxRepoBootstrapConflict = errors.New("AcornFox repository preparation conflicts with task state")
	ErrAcornFoxRepoRecoveryUnknown   = errors.New("AcornFox repository preparation recovery is unknown")
)

const AcornFoxRepoActivationV1Schema = 1

// AcornFoxRepoActivationV1 records only task-model evidence. It deliberately
// excludes any host, database, service, network, or health authority.
type AcornFoxRepoActivationV1 struct {
	SchemaVersion          int    `json:"schema_version"`
	Mode                   string `json:"mode"`
	TransactionID          string `json:"transaction_id"`
	ActivationID           string `json:"activation_id"`
	BindingSHA256          string `json:"binding_sha256"`
	SubstrateReceiptSHA256 string `json:"substrate_receipt_sha256"`
	LiveTreeSHA256         string `json:"live_tree_sha256"`
	StaticSetSHA256        string `json:"static_set_sha256"`
	OwnershipPlanSHA256    string `json:"ownership_plan_sha256"`
	LayoutSHA256           string `json:"layout_sha256,omitempty"`
	ReleaseID              string `json:"release_id"`
	ReleaseTreeSHA256      string `json:"release_tree_sha256"`
}

func (a AcornFoxRepoActivationV1) Validate() error {
	id, err := AcornFoxRepoActivationID(a.BindingSHA256)
	if err != nil || a.SchemaVersion != 1 || (a.Mode != "task_model" && a.Mode != "production_host") || !validID(a.TransactionID) || a.ActivationID != id || !validSHA(a.SubstrateReceiptSHA256) || !validSHA(a.LiveTreeSHA256) || !validSHA(a.StaticSetSHA256) || !validSHA(a.OwnershipPlanSHA256) || !validID(a.ReleaseID) || !validSHA(a.ReleaseTreeSHA256) || (a.LayoutSHA256 != "" && !validSHA(a.LayoutSHA256)) || (a.Mode == "task_model" && a.LayoutSHA256 != "") || (a.Mode == "production_host" && a.LayoutSHA256 == "") {
		return ErrAcornFoxRepoBootstrapConflict
	}
	return nil
}
func MarshalAcornFoxRepoActivationV1(a AcornFoxRepoActivationV1) ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(a)
}
func ParseAcornFoxRepoActivationV1(raw []byte) (AcornFoxRepoActivationV1, error) {
	var a AcornFoxRepoActivationV1
	if err := strictCanonicalJSON(raw, &a, "AcornFox repository activation"); err != nil {
		return a, err
	}
	return a, a.Validate()
}

var acornFoxRepoBootstrapFaultStep = func(string) error { return nil }

func acornFoxRepoBootstrapStep(s string) error { return acornFoxRepoBootstrapFaultStep(s) }

func prepareAcornFoxRepository(ctx context.Context, store *TaskAcornFoxRepoStore, substrate *PublishedAcornFoxSubstrateV1, binding string) (err error) {
	lease, err := store.mintLiveVerifiedLease(ctx, substrate, binding)
	if err != nil {
		return err
	}
	defer func() {
		if release := lease.Release(); release != nil && err == nil {
			err = ErrAcornFoxRepoBootstrapConflict
		}
	}()
	l := lease.prepared
	root, err := l.store.openHostRoot()
	if err != nil {
		return ErrAcornFoxRepoBootstrapConflict
	}
	defer root.Close()
	a, raw, err := acornFoxRepoActivationForLayout(l.store.layout, l.journal, lease.receipt, l.substrate)
	if err != nil {
		return err
	}
	digest := sha256Hex(raw)
	effect := false
	mark := func() { effect = true }
	defer func() {
		if err != nil && effect && !l.journal.NeedsRecovery {
			failed := acornFoxRepoFailure(l.journal, digest)
			if l.store.Save(context.Background(), failed) == nil {
				l.journal = failed
				return
			}
			observed, loadErr := l.store.Resume(context.Background())
			if loadErr == nil && sameAcornFoxRepoJournal(observed, failed) {
				l.journal = observed
				return
			}
			err = ErrAcornFoxRepoRecoveryUnknown
		}
	}()
	wasRecovery := l.journal.NeedsRecovery
	if l.journal.NeedsRecovery {
		if !acornFoxRepoPrefixForLayout(root, l.store, l.store.layout, l.journal, lease.receipt, l.substrate, a, raw) {
			return ErrAcornFoxRepoBootstrapConflict
		}
		if err = acornFoxRepoRecoverPointerTempsForLayout(root, l.store, l.store.layout, l.journal.TransactionID, a, mark); err != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		if !acornFoxRepoPrefixForLayout(root, l.store, l.store.layout, l.journal, lease.receipt, l.substrate, a, raw) {
			return ErrAcornFoxRepoBootstrapConflict
		}
		next := acornFoxRepoRecovered(l.journal, digest)
		if l.store.Save(ctx, next) != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		l.journal = next
	}
	if !wasRecovery && !acornFoxRepoPrefixForLayout(root, l.store, l.store.layout, l.journal, lease.receipt, l.substrate, a, raw) {
		return ErrAcornFoxRepoBootstrapConflict
	}
	if l.journal.Phase == AcornFoxRepoStaticVerified {
		if err = acornFoxRepoEnsureActivationForLayout(root, l.store, l.store.layout, l.journal.TransactionID, a, raw, mark); err != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		if acornFoxRepoBootstrapStep("journal-activation") != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		l.journal, err = acornFoxRepoAdvance(l.store, ctx, l.journal, AcornFoxRepoActivationWritten, digest)
		if err != nil {
			return err
		}
	}
	if l.journal.Phase == AcornFoxRepoActivationWritten {
		if err = acornFoxRepoEnsurePointerForLayout(root, l.store, l.store.layout, l.journal.TransactionID, l.store.layout.activePath(), "activations/"+a.ActivationID, mark); err != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		if acornFoxRepoBootstrapStep("journal-active") != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		l.journal, err = acornFoxRepoAdvance(l.store, ctx, l.journal, AcornFoxRepoActivePublished, digest)
		if err != nil {
			return err
		}
	}
	if l.journal.Phase == AcornFoxRepoActivePublished {
		if err = acornFoxRepoEnsurePointerForLayout(root, l.store, l.store.layout, l.journal.TransactionID, l.store.layout.currentPath(), "active/release", mark); err != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		if acornFoxRepoBootstrapStep("journal-current") != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		l.journal, err = acornFoxRepoAdvance(l.store, ctx, l.journal, AcornFoxRepoCurrentPublished, digest)
		if err != nil {
			return err
		}
	}
	if l.journal.Phase == AcornFoxRepoCurrentPublished {
		if !acornFoxRepoFinalForLayout(root, l.store, l.store.layout, l.journal, lease.receipt, l.substrate, a, raw) {
			return ErrAcornFoxRepoBootstrapConflict
		}
		l.journal, err = acornFoxRepoAdvance(l.store, ctx, l.journal, AcornFoxRepoPreparedFinal, digest)
		if err != nil {
			return err
		}
	}
	if l.journal.Phase != AcornFoxRepoPreparedFinal || !acornFoxRepoFinalForLayout(root, l.store, l.store.layout, l.journal, lease.receipt, l.substrate, a, raw) {
		return ErrAcornFoxRepoBootstrapConflict
	}
	return nil
}

func acornFoxRepoActivation(j AcornFoxRepoJournalV1, r AcornFoxLiveReceiptV1, s *PublishedAcornFoxSubstrateV1) (AcornFoxRepoActivationV1, []byte, error) {
	return acornFoxRepoActivationForLayout(acornFoxInstallLayout{mode: acornFoxInstallLayoutTask}, j, r, s)
}

func acornFoxRepoActivationForLayout(layout acornFoxInstallLayout, j AcornFoxRepoJournalV1, r AcornFoxLiveReceiptV1, s *PublishedAcornFoxSubstrateV1) (AcornFoxRepoActivationV1, []byte, error) {
	id, e := AcornFoxRepoActivationID(j.BindingSHA256)
	if e != nil {
		return AcornFoxRepoActivationV1{}, nil, e
	}
	mode := "task_model"
	if layout.mode == acornFoxInstallLayoutProduction {
		mode = "production_host"
	}
	a := AcornFoxRepoActivationV1{SchemaVersion: 1, Mode: mode, TransactionID: j.TransactionID, ActivationID: id, BindingSHA256: j.BindingSHA256, SubstrateReceiptSHA256: j.SubstrateReceiptSHA256, LiveTreeSHA256: r.LiveTreeSHA256, StaticSetSHA256: r.StaticSetSHA256, OwnershipPlanSHA256: r.OwnershipPlanSHA256, LayoutSHA256: layout.evidence(), ReleaseID: s.receipt.CandidateReceipt.ReleaseID, ReleaseTreeSHA256: s.receipt.ReleaseTreeSHA256}
	raw, e := MarshalAcornFoxRepoActivationV1(a)
	return a, raw, e
}
func acornFoxRepoActivationDir(id string) string {
	return acornFoxLiveDir + "/opt/acornfox/activations/" + id
}
func acornFoxRepoActivationPath(id string) string {
	return acornFoxRepoActivationDir(id) + "/repo-activation.json"
}
func acornFoxRepoReleasePath(id string) string { return acornFoxRepoActivationDir(id) + "/release" }
func acornFoxRepoActivePath() string           { return acornFoxLiveDir + "/opt/acornfox/active" }
func acornFoxRepoCurrentPath() string          { return acornFoxLiveDir + "/opt/acornfox/current" }
func acornFoxRepoEnsureActivation(root *os.Root, s *TaskAcornFoxRepoStore, tx string, a AcornFoxRepoActivationV1, raw []byte, mark func()) error {
	if s == nil {
		return ErrAcornFoxRepoBootstrapConflict
	}
	return acornFoxRepoEnsureActivationForLayout(root, s, s.layout, tx, a, raw, mark)
}

func acornFoxRepoEnsureActivationForLayout(root *os.Root, s *TaskAcornFoxRepoStore, layout acornFoxInstallLayout, tx string, a AcornFoxRepoActivationV1, raw []byte, mark func()) error {
	if layout.validate() != nil {
		return ErrAcornFoxRepoBootstrapConflict
	}
	for _, p := range []string{layout.livePath("opt/acornfox/activations"), layout.activationDir(a.ActivationID)} {
		if err := acornFoxRepoDirForLayout(root, s, layout, p, mark); err != nil {
			return err
		}
	}
	rootPrincipal, ok := layout.owner(AcornFoxLiveRootRole)
	if !ok || acornFoxLiveWriteFileOwned(root, s, tx, layout.activationReceiptPath(a.ActivationID), raw, durableFileMode, rootPrincipal, mark) != nil {
		return ErrAcornFoxRepoBootstrapConflict
	}
	return acornFoxRepoEnsurePointerForLayout(root, s, layout, tx, layout.activationReleasePath(a.ActivationID), "../../releases/"+a.ReleaseID, mark)
}
func acornFoxRepoDir(root *os.Root, s *TaskAcornFoxRepoStore, p string, mark func()) error {
	return acornFoxRepoDirForLayout(root, s, s.layout, p, mark)
}
func acornFoxRepoDirForLayout(root *os.Root, s *TaskAcornFoxRepoStore, layout acornFoxInstallLayout, p string, mark func()) error {
	info, e := root.Lstat(p)
	if errors.Is(e, os.ErrNotExist) {
		if acornFoxRepoBootstrapStep("mkdir") != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		if e = root.Mkdir(p, durableDirMode); e != nil {
			return e
		}
		mark()
		file, openErr := root.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return openErr
		}
		rootPrincipal, ownerOK := layout.owner(AcornFoxLiveRootRole)
		ownerErr := ErrAcornFoxRepoBootstrapConflict
		if ownerOK {
			ownerErr = acornFoxLiveApplyOwner(s, file, rootPrincipal)
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if ownerErr != nil || syncErr != nil || closeErr != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		if acornFoxLiveSyncDir(root, parentDirectory(p)) != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		info, e = root.Lstat(p)
	}
	principal, ok := layout.owner(AcornFoxLiveRootRole)
	if e != nil || !ok || !info.IsDir() || info.Mode().Perm() != durableDirMode || !acornFoxLiveObservedOwner(s, info, principal) {
		return ErrAcornFoxRepoBootstrapConflict
	}
	return nil
}
func acornFoxRepoTemp(tx, p string) string {
	return filepath.ToSlash(filepath.Join(parentDirectory(p), ".acornfox-repo-link-"+sha256Hex([]byte(tx+"\x00"+p))))
}
func acornFoxRepoPointer(root *os.Root, s *TaskAcornFoxRepoStore, p, target string, two bool) bool {
	return acornFoxRepoPointerForLayout(root, s, s.layout, p, target, two)
}
func acornFoxRepoPointerForLayout(root *os.Root, s *TaskAcornFoxRepoStore, layout acornFoxInstallLayout, p, target string, two bool) bool {
	info, e := root.Lstat(p)
	principal, ok := layout.owner(AcornFoxLiveRootRole)
	if e != nil || !ok || info.Mode()&os.ModeSymlink == 0 || !acornFoxLiveObservedOwner(s, info, principal) || (!two && acornFoxRepoNlink(info) != 1) || (two && acornFoxRepoNlink(info) != 1 && acornFoxRepoNlink(info) != 2) {
		return false
	}
	got, e := root.Readlink(p)
	return e == nil && got == target
}
func acornFoxRepoEnsurePointer(root *os.Root, s *TaskAcornFoxRepoStore, tx, p, target string, mark func()) error {
	return acornFoxRepoEnsurePointerForLayout(root, s, s.layout, tx, p, target, mark)
}
func acornFoxRepoEnsurePointerForLayout(root *os.Root, s *TaskAcornFoxRepoStore, layout acornFoxInstallLayout, tx, p, target string, mark func()) error {
	tmp := acornFoxRepoTemp(tx, p)
	if info, e := root.Lstat(tmp); e == nil {
		if !acornFoxRepoPointerForLayout(root, s, layout, tmp, target, true) {
			return ErrAcornFoxRepoBootstrapConflict
		}
		if acornFoxRepoNlink(info) == 2 {
			final, finalErr := root.Lstat(p)
			if finalErr != nil || !os.SameFile(info, final) || !acornFoxRepoPointerForLayout(root, s, layout, p, target, true) {
				return ErrAcornFoxRepoBootstrapConflict
			}
			if acornFoxRepoBootstrapStep("pointer-temp-remove") != nil || root.Remove(tmp) != nil {
				return ErrAcornFoxRepoBootstrapConflict
			}
			mark()
			if acornFoxRepoBootstrapStep("pointer-post-remove-sync") != nil || acornFoxLiveSyncDir(root, parentDirectory(p)) != nil || !acornFoxRepoPointerForLayout(root, s, layout, p, target, false) {
				return ErrAcornFoxRepoBootstrapConflict
			}
			return nil
		}
		if acornFoxRepoNlink(info) != 1 {
			return ErrAcornFoxRepoBootstrapConflict
		}
		if acornFoxRepoBootstrapStep("pointer-temp-remove") != nil || root.Remove(tmp) != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		mark()
		if acornFoxRepoBootstrapStep("pointer-post-remove-sync") != nil || acornFoxLiveSyncDir(root, parentDirectory(p)) != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if _, e := root.Lstat(p); e == nil {
		if acornFoxRepoPointerForLayout(root, s, layout, p, target, false) {
			return nil
		}
		return ErrAcornFoxRepoBootstrapConflict
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if acornFoxRepoBootstrapStep("pointer-temp") != nil {
		return ErrAcornFoxRepoBootstrapConflict
	}
	if e := root.Symlink(target, tmp); e != nil {
		return e
	}
	mark()
	principal, ok := layout.owner(AcornFoxLiveRootRole)
	if !ok || s.ownership.lchown == nil || s.ownership.lchown(root, tmp, principal.uid, principal.gid) != nil {
		return ErrAcornFoxRepoBootstrapConflict
	}
	if !acornFoxRepoPointerForLayout(root, s, layout, tmp, target, false) {
		return ErrAcornFoxRepoBootstrapConflict
	}
	if acornFoxRepoBootstrapStep("pointer-link") != nil {
		return ErrAcornFoxRepoBootstrapConflict
	}
	if e := root.Link(tmp, p); e != nil {
		return e
	}
	mark()
	if acornFoxRepoBootstrapStep("pointer-post-link") != nil || acornFoxRepoBootstrapStep("pointer-parent-sync") != nil || acornFoxLiveSyncDir(root, parentDirectory(p)) != nil || !acornFoxRepoPointerForLayout(root, s, layout, p, target, true) {
		return ErrAcornFoxRepoBootstrapConflict
	}
	if acornFoxRepoBootstrapStep("pointer-readback") != nil {
		return ErrAcornFoxRepoBootstrapConflict
	}
	if acornFoxRepoBootstrapStep("pointer-temp-remove") != nil || root.Remove(tmp) != nil {
		return ErrAcornFoxRepoBootstrapConflict
	}
	mark()
	if acornFoxRepoBootstrapStep("pointer-post-remove-sync") != nil || acornFoxLiveSyncDir(root, parentDirectory(p)) != nil || !acornFoxRepoPointerForLayout(root, s, layout, p, target, false) {
		return ErrAcornFoxRepoBootstrapConflict
	}
	return nil
}

// Recover only an authenticated no-replace symlink temporary. Any other
// topology remains on disk for diagnosis and blocks progress.
func acornFoxRepoRecoverPointerTemps(root *os.Root, s *TaskAcornFoxRepoStore, tx string, a AcornFoxRepoActivationV1, mark func()) error {
	return acornFoxRepoRecoverPointerTempsForLayout(root, s, s.layout, tx, a, mark)
}
func acornFoxRepoRecoverPointerTempsForLayout(root *os.Root, s *TaskAcornFoxRepoStore, layout acornFoxInstallLayout, tx string, a AcornFoxRepoActivationV1, mark func()) error {
	for _, v := range []struct{ path, target string }{{layout.activationReleasePath(a.ActivationID), "../../releases/" + a.ReleaseID}, {layout.activePath(), "activations/" + a.ActivationID}, {layout.currentPath(), "active/release"}} {
		tmp := acornFoxRepoTemp(tx, v.path)
		info, err := root.Lstat(tmp)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !acornFoxRepoPointerForLayout(root, s, layout, tmp, v.target, true) {
			return ErrAcornFoxRepoBootstrapConflict
		}
		if acornFoxRepoNlink(info) == 2 {
			final, finalErr := root.Lstat(v.path)
			if finalErr != nil || !os.SameFile(info, final) || !acornFoxRepoPointerForLayout(root, s, layout, v.path, v.target, true) {
				return ErrAcornFoxRepoBootstrapConflict
			}
		} else if acornFoxRepoNlink(info) != 1 {
			return ErrAcornFoxRepoBootstrapConflict
		}
		if acornFoxRepoBootstrapStep("pointer-temp-remove") != nil || root.Remove(tmp) != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		mark()
		if acornFoxRepoBootstrapStep("pointer-post-remove-sync") != nil || acornFoxLiveSyncDir(root, parentDirectory(v.path)) != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		if _, finalErr := root.Lstat(v.path); finalErr == nil && !acornFoxRepoPointerForLayout(root, s, layout, v.path, v.target, false) {
			return ErrAcornFoxRepoBootstrapConflict
		}
	}
	return nil
}
func acornFoxRepoAdvance(s *TaskAcornFoxRepoStore, ctx context.Context, old AcornFoxRepoJournalV1, phase AcornFoxRepoPhase, activation string) (AcornFoxRepoJournalV1, error) {
	n := old
	n.Revision++
	n.Phase = phase
	switch phase {
	case AcornFoxRepoActivationWritten:
		n.ActivationSHA256 = activation
	case AcornFoxRepoActivePublished:
		n.ActivePointerSHA256 = acornFoxRepoEvidence("acornfox-repo-active-v1\x00", old.BindingSHA256, activation)
	case AcornFoxRepoCurrentPublished:
		n.CurrentPointerSHA256 = acornFoxRepoEvidence("acornfox-repo-current-v1\x00", old.BindingSHA256, activation)
	case AcornFoxRepoPreparedFinal:
	default:
		return old, ErrAcornFoxRepoBootstrapConflict
	}
	n.History = append(n.History, AcornFoxRepoHistoryV1{n.Revision, AcornFoxRepoHistoryAdvance, old.Phase, phase, acornFoxRepoPhaseEvidence(n, phase)})
	if n.Validate() != nil || s.Save(ctx, n) != nil {
		return old, ErrAcornFoxRepoBootstrapConflict
	}
	return n, nil
}
func acornFoxRepoFailure(o AcornFoxRepoJournalV1, d string) AcornFoxRepoJournalV1 {
	n := o
	n.Revision++
	n.NeedsRecovery = true
	n.Failure = &AcornFoxRepoFailureV1{"repo_bootstrap_effect_failure", acornFoxRepoEvidence("acornfox-repo-bootstrap-failure-v1\x00", o.BindingSHA256, string(o.Phase), d)}
	n.History = append(n.History, AcornFoxRepoHistoryV1{n.Revision, AcornFoxRepoHistoryFailure, o.Phase, o.Phase, n.Failure.Digest})
	return n
}
func acornFoxRepoRecovered(o AcornFoxRepoJournalV1, d string) AcornFoxRepoJournalV1 {
	n := o
	n.Revision++
	n.NeedsRecovery = false
	n.Failure = nil
	evidence := ""
	if o.Failure != nil {
		evidence, _ = AcornFoxRepoRecoveredEvidence(o, o.Phase, o.Failure.Digest)
	}
	n.History = append(n.History, AcornFoxRepoHistoryV1{n.Revision, AcornFoxRepoHistoryRecovered, o.Phase, o.Phase, evidence})
	return n
}

type acornFoxRepoPrefixState int

const (
	acornFoxRepoPrefixStatic acornFoxRepoPrefixState = iota
	acornFoxRepoPrefixActivations
	acornFoxRepoPrefixActivationDir
	acornFoxRepoPrefixActivationJSON
	acornFoxRepoPrefixReleaseTemp
	acornFoxRepoPrefixRelease
	acornFoxRepoPrefixActiveTemp
	acornFoxRepoPrefixActive
	acornFoxRepoPrefixCurrentTemp
	acornFoxRepoPrefixCurrent
)

func acornFoxRepoPrefix(root *os.Root, s *TaskAcornFoxRepoStore, j AcornFoxRepoJournalV1, r AcornFoxLiveReceiptV1, sub *PublishedAcornFoxSubstrateV1, a AcornFoxRepoActivationV1, raw []byte) bool {
	return acornFoxRepoPrefixForLayout(root, s, s.layout, j, r, sub, a, raw)
}
func acornFoxRepoPrefixForLayout(root *os.Root, s *TaskAcornFoxRepoStore, layout acornFoxInstallLayout, j AcornFoxRepoJournalV1, r AcornFoxLiveReceiptV1, sub *PublishedAcornFoxSubstrateV1, a AcornFoxRepoActivationV1, raw []byte) bool {
	if layout.validate() != nil || a.LayoutSHA256 != layout.evidence() || r.LayoutSHA256 != layout.evidence() || j.LayoutSHA256 != layout.evidence() {
		return false
	}
	if layout.mode == acornFoxInstallLayoutProduction {
		return acornFoxRepoProductionPrefix(root, s, layout, j, r, sub, a, raw)
	}
	entries, e := acornFoxLiveExpectedEntries(sub)
	if e != nil || !acornFoxRepoVerifyPinnedLive(root, s, entries, r) {
		return false
	}
	state, ok := acornFoxRepoClassifyPrefix(root, s, a, raw)
	if !ok || !acornFoxRepoExactInventory(root, s, entries, a, raw, state) {
		return false
	}
	min, max := acornFoxRepoPrefixBounds(j.Phase, j.NeedsRecovery)
	return state >= min && state <= max
}

func acornFoxRepoProductionPrefix(root *os.Root, s *TaskAcornFoxRepoStore, layout acornFoxInstallLayout, j AcornFoxRepoJournalV1, r AcornFoxLiveReceiptV1, sub *PublishedAcornFoxSubstrateV1, a AcornFoxRepoActivationV1, raw []byte) bool {
	entries, err := acornFoxLiveExpectedEntriesForLayout(layout, sub)
	if err != nil || !acornFoxRepoVerifyPinnedLiveForLayout(root, s, layout, entries, r) {
		return false
	}
	state, ok := acornFoxRepoClassifyPrefixForLayout(root, s, layout, a, raw)
	if !ok {
		return false
	}
	min, max := acornFoxRepoPrefixBounds(j.Phase, j.NeedsRecovery)
	if state < min || state > max {
		return false
	}
	// Audit the complete owned scope at every activation boundary. The narrow
	// validator adds only journal-bound activation paths; it never broadens
	// into a host-root walk.
	if acornFoxValidateProductionManagedScopePrefix(root, s, entries, a, raw, state) != nil {
		return false
	}
	return true
}
func acornFoxRepoPrefixBounds(phase AcornFoxRepoPhase, recovery bool) (acornFoxRepoPrefixState, acornFoxRepoPrefixState) {
	_ = recovery // Clean and failed journals admit the same exact next boundary.
	switch phase {
	case AcornFoxRepoStaticVerified:
		return acornFoxRepoPrefixStatic, acornFoxRepoPrefixRelease
	case AcornFoxRepoActivationWritten:
		return acornFoxRepoPrefixRelease, acornFoxRepoPrefixActive
	case AcornFoxRepoActivePublished:
		return acornFoxRepoPrefixActive, acornFoxRepoPrefixCurrent
	default:
		return acornFoxRepoPrefixCurrent, acornFoxRepoPrefixCurrent
	}
}
func acornFoxRepoClassifyPrefix(root *os.Root, s *TaskAcornFoxRepoStore, a AcornFoxRepoActivationV1, raw []byte) (acornFoxRepoPrefixState, bool) {
	return acornFoxRepoClassifyPrefixForLayout(root, s, s.layout, a, raw)
}
func acornFoxRepoClassifyPrefixForLayout(root *os.Root, s *TaskAcornFoxRepoStore, layout acornFoxInstallLayout, a AcornFoxRepoActivationV1, raw []byte) (acornFoxRepoPrefixState, bool) {
	exists := func(path string) bool { _, err := root.Lstat(path); return err == nil }
	parent, dir, jsonPath, release := layout.livePath("opt/acornfox/activations"), layout.activationDir(a.ActivationID), layout.activationReceiptPath(a.ActivationID), layout.activationReleasePath(a.ActivationID)
	if !exists(parent) {
		return acornFoxRepoPrefixStatic, true
	}
	if !exists(dir) {
		return acornFoxRepoPrefixActivations, true
	}
	if !exists(jsonPath) {
		return acornFoxRepoPrefixActivationDir, true
	}
	rootPrincipal, rootOK := layout.owner(AcornFoxLiveRootRole)
	if !rootOK || !acornFoxLiveExactFileOwned(root, s, jsonPath, raw, durableFileMode, rootPrincipal, false) {
		return 0, false
	}
	if state, ok := acornFoxRepoPointerPrefixForLayout(root, s, layout, a.TransactionID, release, "../../releases/"+a.ReleaseID, acornFoxRepoPrefixActivationJSON, acornFoxRepoPrefixReleaseTemp, acornFoxRepoPrefixRelease); !ok || state != acornFoxRepoPrefixRelease {
		return state, ok
	}
	if state, ok := acornFoxRepoPointerPrefixForLayout(root, s, layout, a.TransactionID, layout.activePath(), "activations/"+a.ActivationID, acornFoxRepoPrefixRelease, acornFoxRepoPrefixActiveTemp, acornFoxRepoPrefixActive); !ok || state != acornFoxRepoPrefixActive {
		return state, ok
	}
	if state, ok := acornFoxRepoPointerPrefixForLayout(root, s, layout, a.TransactionID, layout.currentPath(), "active/release", acornFoxRepoPrefixActive, acornFoxRepoPrefixCurrentTemp, acornFoxRepoPrefixCurrent); !ok || state != acornFoxRepoPrefixCurrent {
		return state, ok
	}
	return acornFoxRepoPrefixCurrent, true
}
func acornFoxRepoPointerPrefix(root *os.Root, s *TaskAcornFoxRepoStore, tx, path, target string, before, tempState, finalState acornFoxRepoPrefixState) (acornFoxRepoPrefixState, bool) {
	return acornFoxRepoPointerPrefixForLayout(root, s, s.layout, tx, path, target, before, tempState, finalState)
}
func acornFoxRepoPointerPrefixForLayout(root *os.Root, s *TaskAcornFoxRepoStore, layout acornFoxInstallLayout, tx, path, target string, before, tempState, finalState acornFoxRepoPrefixState) (acornFoxRepoPrefixState, bool) {
	temp := acornFoxRepoTemp(tx, path)
	tempInfo, tempErr := root.Lstat(temp)
	finalInfo, finalErr := root.Lstat(path)
	if tempErr == nil {
		if !acornFoxRepoPointerForLayout(root, s, layout, temp, target, true) {
			return 0, false
		}
		if finalErr == nil {
			if !os.SameFile(tempInfo, finalInfo) || !acornFoxRepoPointerForLayout(root, s, layout, path, target, true) {
				return 0, false
			}
		} else if !errors.Is(finalErr, os.ErrNotExist) {
			return 0, false
		}
		return tempState, true
	}
	if !errors.Is(tempErr, os.ErrNotExist) {
		return 0, false
	}
	if errors.Is(finalErr, os.ErrNotExist) {
		return before, true
	}
	if finalErr != nil || !acornFoxRepoPointerForLayout(root, s, layout, path, target, false) {
		return 0, false
	}
	return finalState, true
}
func acornFoxRepoExactInventory(root *os.Root, s *TaskAcornFoxRepoStore, entries []SubstrateEntry, a AcornFoxRepoActivationV1, raw []byte, state acornFoxRepoPrefixState) bool {
	type expectedNode struct {
		directory     bool
		mode          os.FileMode
		pointerTarget string
		allowTwo      bool
	}
	want := map[string]expectedNode{"receipt.json": {mode: durableFileMode}}
	for _, entry := range entries {
		want[entry.Path] = expectedNode{directory: entry.Kind == SubstrateEntryDirectory, mode: os.FileMode(entry.Mode)}
	}
	if state >= acornFoxRepoPrefixActivations {
		want["opt/acornfox/activations"] = expectedNode{directory: true, mode: durableDirMode}
	}
	if state >= acornFoxRepoPrefixActivationDir {
		want["opt/acornfox/activations/"+a.ActivationID] = expectedNode{directory: true, mode: durableDirMode}
	}
	if state >= acornFoxRepoPrefixActivationJSON {
		want["opt/acornfox/activations/"+a.ActivationID+"/repo-activation.json"] = expectedNode{mode: durableFileMode}
	}
	if state == acornFoxRepoPrefixReleaseTemp {
		want["opt/acornfox/activations/"+a.ActivationID+"/"+filepath.Base(acornFoxRepoTemp(a.TransactionID, acornFoxRepoReleasePath(a.ActivationID)))] = expectedNode{pointerTarget: "../../releases/" + a.ReleaseID, allowTwo: true}
	}
	_, releaseExists := root.Lstat(acornFoxRepoReleasePath(a.ActivationID))
	if state >= acornFoxRepoPrefixRelease || (state == acornFoxRepoPrefixReleaseTemp && releaseExists == nil) {
		want["opt/acornfox/activations/"+a.ActivationID+"/release"] = expectedNode{pointerTarget: "../../releases/" + a.ReleaseID, allowTwo: state == acornFoxRepoPrefixReleaseTemp}
	}
	if state == acornFoxRepoPrefixActiveTemp {
		want["opt/acornfox/"+filepath.Base(acornFoxRepoTemp(a.TransactionID, acornFoxRepoActivePath()))] = expectedNode{pointerTarget: "activations/" + a.ActivationID, allowTwo: true}
	}
	_, activeExists := root.Lstat(acornFoxRepoActivePath())
	if state >= acornFoxRepoPrefixActive || (state == acornFoxRepoPrefixActiveTemp && activeExists == nil) {
		want["opt/acornfox/active"] = expectedNode{pointerTarget: "activations/" + a.ActivationID, allowTwo: state == acornFoxRepoPrefixActiveTemp}
	}
	if state == acornFoxRepoPrefixCurrentTemp {
		want["opt/acornfox/"+filepath.Base(acornFoxRepoTemp(a.TransactionID, acornFoxRepoCurrentPath()))] = expectedNode{pointerTarget: "active/release", allowTwo: true}
	}
	_, currentExists := root.Lstat(acornFoxRepoCurrentPath())
	if state >= acornFoxRepoPrefixCurrent || (state == acornFoxRepoPrefixCurrentTemp && currentExists == nil) {
		want["opt/acornfox/current"] = expectedNode{pointerTarget: "active/release", allowTwo: state == acornFoxRepoPrefixCurrentTemp}
	}
	var walk func(string) bool
	walk = func(dir string) bool {
		f, err := root.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return false
		}
		children, readErr := f.ReadDir(-1)
		closeErr := f.Close()
		if readErr != nil || closeErr != nil {
			return false
		}
		for _, child := range children {
			path := filepath.ToSlash(filepath.Join(dir, child.Name()))
			relative := path[len(acornFoxLiveDir)+1:]
			expected, ok := want[relative]
			if !ok {
				return false
			}
			info, statErr := root.Lstat(path)
			if statErr != nil {
				return false
			}
			if info.Mode()&os.ModeSymlink != 0 {
				if expected.pointerTarget == "" || !acornFoxRepoPointer(root, s, path, expected.pointerTarget, expected.allowTwo) {
					return false
				}
				continue
			}
			if expected.pointerTarget != "" || verifyOwner(info, s.uid, s.gid) != nil || info.Mode().Perm() != expected.mode {
				return false
			}
			if expected.directory {
				if !info.IsDir() || !walk(path) {
					return false
				}
			} else if !info.Mode().IsRegular() || acornFoxRepoNlink(info) != 1 {
				return false
			}
		}
		return true
	}
	if !walk(acornFoxLiveDir) {
		return false
	}
	if state >= acornFoxRepoPrefixActivationJSON && !acornFoxLiveExactFile(root, s, acornFoxRepoActivationPath(a.ActivationID), raw, durableFileMode, false) {
		return false
	}
	return true
}
func acornFoxRepoVerifyLeaseInventory(root *os.Root, s *TaskAcornFoxRepoStore, j AcornFoxRepoJournalV1, r AcornFoxLiveReceiptV1, sub *PublishedAcornFoxSubstrateV1) bool {
	a, raw, err := acornFoxRepoActivationForLayout(s.layout, j, r, sub)
	if err != nil {
		return false
	}
	entries, err := acornFoxLiveExpectedEntriesForLayout(s.layout, sub)
	if err != nil || !acornFoxRepoVerifyPinnedLiveForLayout(root, s, s.layout, entries, r) {
		return false
	}
	state, ok := acornFoxRepoClassifyPrefixForLayout(root, s, s.layout, a, raw)
	if s.layout.mode == acornFoxInstallLayoutProduction {
		min, max := acornFoxRepoPrefixBounds(j.Phase, j.NeedsRecovery)
		return ok && state >= min && state <= max
	}
	min, max := acornFoxRepoPrefixBounds(j.Phase, j.NeedsRecovery)
	return ok && state >= min && state <= max && acornFoxRepoExactInventory(root, s, entries, a, raw, state)
}
func acornFoxRepoVerifyPinnedLive(root *os.Root, s *TaskAcornFoxRepoStore, entries []SubstrateEntry, r AcornFoxLiveReceiptV1) bool {
	return acornFoxRepoVerifyPinnedLiveForLayout(root, s, s.layout, entries, r)
}
func acornFoxRepoVerifyPinnedLiveForLayout(root *os.Root, s *TaskAcornFoxRepoStore, layout acornFoxInstallLayout, entries []SubstrateEntry, r AcornFoxLiveReceiptV1) bool {
	if layout.validate() != nil || r.LayoutSHA256 != layout.evidence() {
		return false
	}
	for _, e := range entries {
		p := layout.livePath(e.Path)
		info, x := root.Lstat(p)
		principal := acornFoxLivePrincipalForEntry(layout, e)
		if x != nil || info.Mode()&os.ModeSymlink != 0 || !acornFoxLiveObservedOwner(s, info, principal) || info.Mode().Perm() != os.FileMode(e.Mode) {
			return false
		}
		if e.Kind == SubstrateEntryDirectory {
			if !info.IsDir() {
				return false
			}
			continue
		}
		f, x := root.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if x != nil {
			return false
		}
		raw, re := io.ReadAll(io.LimitReader(f, e.Size+1))
		stat, se := f.Stat()
		ce := f.Close()
		if re != nil || se != nil || ce != nil || !os.SameFile(info, stat) || info.Size() != e.Size || sha256Hex(raw) != e.SHA256 || acornFoxRepoNlink(info) != 1 {
			return false
		}
	}
	raw, e := MarshalAcornFoxLiveReceiptV1(r)
	rootPrincipal, ok := layout.owner(AcornFoxLiveRootRole)
	return e == nil && ok && acornFoxLiveExactFileOwned(root, s, layout.receiptPath(), raw, durableFileMode, rootPrincipal, false)
}
func acornFoxRepoFinal(root *os.Root, s *TaskAcornFoxRepoStore, j AcornFoxRepoJournalV1, r AcornFoxLiveReceiptV1, sub *PublishedAcornFoxSubstrateV1, a AcornFoxRepoActivationV1, raw []byte) bool {
	return acornFoxRepoFinalForLayout(root, s, s.layout, j, r, sub, a, raw)
}
func acornFoxRepoFinalForLayout(root *os.Root, s *TaskAcornFoxRepoStore, layout acornFoxInstallLayout, j AcornFoxRepoJournalV1, r AcornFoxLiveReceiptV1, sub *PublishedAcornFoxSubstrateV1, a AcornFoxRepoActivationV1, raw []byte) bool {
	if !acornFoxRepoPrefixForLayout(root, s, layout, j, r, sub, a, raw) {
		return false
	}
	for _, role := range []string{"upgrade", "healthcheck"} {
		i := AcornFoxBuildIdentityV1{AcornFoxHelperContractV1Schema, AcornFoxV1Product, AcornFoxSubstrateLayoutV1, role, sub.receipt.CandidateReceipt.Version, sub.receipt.CandidateReceipt.ReleaseID, sub.receipt.CandidateReceipt.SourceCommit}
		if !verifyPublishedAcornFoxHelperContract(i, sub).OK {
			return false
		}
	}
	return true
}
