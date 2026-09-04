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
	ReleaseID              string `json:"release_id"`
	ReleaseTreeSHA256      string `json:"release_tree_sha256"`
}

func (a AcornFoxRepoActivationV1) Validate() error {
	id, err := AcornFoxRepoActivationID(a.BindingSHA256)
	if err != nil || a.SchemaVersion != 1 || a.Mode != "task_model" || !validID(a.TransactionID) || a.ActivationID != id || !validSHA(a.SubstrateReceiptSHA256) || !validSHA(a.LiveTreeSHA256) || !validSHA(a.StaticSetSHA256) || !validSHA(a.OwnershipPlanSHA256) || !validID(a.ReleaseID) || !validSHA(a.ReleaseTreeSHA256) {
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
	root, err := l.store.openRoot()
	if err != nil {
		return ErrAcornFoxRepoBootstrapConflict
	}
	defer root.Close()
	a, raw, err := acornFoxRepoActivation(l.journal, lease.receipt, l.substrate)
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
	if err = acornFoxRepoRecoverPointerTemps(root, l.store, l.journal.TransactionID, a, mark); err != nil {
		return ErrAcornFoxRepoBootstrapConflict
	}
	if l.journal.NeedsRecovery {
		if !acornFoxRepoPrefix(root, l.store, l.journal, lease.receipt, l.substrate, a, raw) {
			return ErrAcornFoxRepoBootstrapConflict
		}
		next := acornFoxRepoRecovered(l.journal, digest)
		if l.store.Save(ctx, next) != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		l.journal = next
	}
	if !acornFoxRepoPrefix(root, l.store, l.journal, lease.receipt, l.substrate, a, raw) {
		return ErrAcornFoxRepoBootstrapConflict
	}
	if l.journal.Phase == AcornFoxRepoStaticVerified {
		if err = acornFoxRepoEnsureActivation(root, l.store, l.journal.TransactionID, a, raw, mark); err != nil {
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
		if err = acornFoxRepoEnsurePointer(root, l.store, l.journal.TransactionID, acornFoxRepoActivePath(), "activations/"+a.ActivationID, mark); err != nil {
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
		if err = acornFoxRepoEnsurePointer(root, l.store, l.journal.TransactionID, acornFoxRepoCurrentPath(), "active/release", mark); err != nil {
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
		if !acornFoxRepoFinal(root, l.store, l.journal, lease.receipt, l.substrate, a, raw) {
			return ErrAcornFoxRepoBootstrapConflict
		}
		l.journal, err = acornFoxRepoAdvance(l.store, ctx, l.journal, AcornFoxRepoPreparedFinal, digest)
		if err != nil {
			return err
		}
	}
	if l.journal.Phase != AcornFoxRepoPreparedFinal || !acornFoxRepoFinal(root, l.store, l.journal, lease.receipt, l.substrate, a, raw) {
		return ErrAcornFoxRepoBootstrapConflict
	}
	return nil
}

func acornFoxRepoActivation(j AcornFoxRepoJournalV1, r AcornFoxLiveReceiptV1, s *PublishedAcornFoxSubstrateV1) (AcornFoxRepoActivationV1, []byte, error) {
	id, e := AcornFoxRepoActivationID(j.BindingSHA256)
	if e != nil {
		return AcornFoxRepoActivationV1{}, nil, e
	}
	a := AcornFoxRepoActivationV1{1, "task_model", j.TransactionID, id, j.BindingSHA256, j.SubstrateReceiptSHA256, r.LiveTreeSHA256, r.StaticSetSHA256, r.OwnershipPlanSHA256, s.receipt.CandidateReceipt.ReleaseID, s.receipt.ReleaseTreeSHA256}
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
	for _, p := range []string{acornFoxLiveDir + "/opt/acornfox/activations", acornFoxRepoActivationDir(a.ActivationID)} {
		if err := acornFoxRepoDir(root, s, p, mark); err != nil {
			return err
		}
	}
	if err := acornFoxLiveWriteFile(root, s, tx, acornFoxRepoActivationPath(a.ActivationID), raw, durableFileMode, mark); err != nil {
		return err
	}
	return acornFoxRepoEnsurePointer(root, s, tx, acornFoxRepoReleasePath(a.ActivationID), "../../releases/"+a.ReleaseID, mark)
}
func acornFoxRepoDir(root *os.Root, s *TaskAcornFoxRepoStore, p string, mark func()) error {
	info, e := root.Lstat(p)
	if errors.Is(e, os.ErrNotExist) {
		if acornFoxRepoBootstrapStep("mkdir") != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		if e = root.Mkdir(p, durableDirMode); e != nil {
			return e
		}
		mark()
		if acornFoxLiveSyncDir(root, parentDirectory(p)) != nil {
			return ErrAcornFoxRepoBootstrapConflict
		}
		info, e = root.Lstat(p)
	}
	if e != nil || !safeAcornFoxRepoDir(info, s.uid, s.gid) {
		return ErrAcornFoxRepoBootstrapConflict
	}
	return nil
}
func acornFoxRepoTemp(tx, p string) string {
	return filepath.ToSlash(filepath.Join(parentDirectory(p), ".acornfox-repo-link-"+sha256Hex([]byte(tx+"\x00"+p))))
}
func acornFoxRepoPointer(root *os.Root, s *TaskAcornFoxRepoStore, p, target string, two bool) bool {
	info, e := root.Lstat(p)
	if e != nil || info.Mode()&os.ModeSymlink == 0 || verifyOwner(info, s.uid, s.gid) != nil || (!two && acornFoxRepoNlink(info) != 1) || (two && acornFoxRepoNlink(info) != 1 && acornFoxRepoNlink(info) != 2) {
		return false
	}
	got, e := root.Readlink(p)
	return e == nil && got == target
}
func acornFoxRepoEnsurePointer(root *os.Root, s *TaskAcornFoxRepoStore, tx, p, target string, mark func()) error {
	tmp := acornFoxRepoTemp(tx, p)
	if info, e := root.Lstat(tmp); e == nil {
		if !acornFoxRepoPointer(root, s, tmp, target, true) {
			return ErrAcornFoxRepoBootstrapConflict
		}
		if acornFoxRepoNlink(info) == 2 {
			final, finalErr := root.Lstat(p)
			if finalErr != nil || !os.SameFile(info, final) || !acornFoxRepoPointer(root, s, p, target, true) {
				return ErrAcornFoxRepoBootstrapConflict
			}
			if acornFoxRepoBootstrapStep("pointer-temp-remove") != nil || root.Remove(tmp) != nil {
				return ErrAcornFoxRepoBootstrapConflict
			}
			mark()
			if acornFoxRepoBootstrapStep("pointer-post-remove-sync") != nil || acornFoxLiveSyncDir(root, parentDirectory(p)) != nil || !acornFoxRepoPointer(root, s, p, target, false) {
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
		if acornFoxRepoPointer(root, s, p, target, false) {
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
	if acornFoxRepoBootstrapStep("pointer-link") != nil {
		return ErrAcornFoxRepoBootstrapConflict
	}
	if e := root.Link(tmp, p); e != nil {
		return e
	}
	mark()
	if acornFoxRepoBootstrapStep("pointer-post-link") != nil || acornFoxRepoBootstrapStep("pointer-parent-sync") != nil || acornFoxLiveSyncDir(root, parentDirectory(p)) != nil || !acornFoxRepoPointer(root, s, p, target, true) {
		return ErrAcornFoxRepoBootstrapConflict
	}
	if acornFoxRepoBootstrapStep("pointer-readback") != nil {
		return ErrAcornFoxRepoBootstrapConflict
	}
	if acornFoxRepoBootstrapStep("pointer-temp-remove") != nil || root.Remove(tmp) != nil {
		return ErrAcornFoxRepoBootstrapConflict
	}
	mark()
	if acornFoxRepoBootstrapStep("pointer-post-remove-sync") != nil || acornFoxLiveSyncDir(root, parentDirectory(p)) != nil || !acornFoxRepoPointer(root, s, p, target, false) {
		return ErrAcornFoxRepoBootstrapConflict
	}
	return nil
}

// Recover only an authenticated no-replace symlink temporary. Any other
// topology remains on disk for diagnosis and blocks progress.
func acornFoxRepoRecoverPointerTemps(root *os.Root, s *TaskAcornFoxRepoStore, tx string, a AcornFoxRepoActivationV1, mark func()) error {
	for _, v := range []struct{ path, target string }{{acornFoxRepoReleasePath(a.ActivationID), "../../releases/" + a.ReleaseID}, {acornFoxRepoActivePath(), "activations/" + a.ActivationID}, {acornFoxRepoCurrentPath(), "active/release"}} {
		tmp := acornFoxRepoTemp(tx, v.path)
		info, err := root.Lstat(tmp)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !acornFoxRepoPointer(root, s, tmp, v.target, true) {
			return ErrAcornFoxRepoBootstrapConflict
		}
		if acornFoxRepoNlink(info) == 2 {
			final, finalErr := root.Lstat(v.path)
			if finalErr != nil || !os.SameFile(info, final) || !acornFoxRepoPointer(root, s, v.path, v.target, true) {
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
		if _, finalErr := root.Lstat(v.path); finalErr == nil && !acornFoxRepoPointer(root, s, v.path, v.target, false) {
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
	n.History = append(n.History, AcornFoxRepoHistoryV1{n.Revision, AcornFoxRepoHistoryRecovered, o.Phase, o.Phase, acornFoxRepoEvidence("acornfox-repo-bootstrap-recovered-v1\x00", o.BindingSHA256, string(o.Phase), d)})
	return n
}
func acornFoxRepoPrefix(root *os.Root, s *TaskAcornFoxRepoStore, j AcornFoxRepoJournalV1, r AcornFoxLiveReceiptV1, sub *PublishedAcornFoxSubstrateV1, a AcornFoxRepoActivationV1, raw []byte) bool {
	entries, e := acornFoxLiveExpectedEntries(sub)
	if e != nil || !acornFoxRepoVerifyPinnedLive(root, s, entries, r) {
		return false
	}
	stage := AcornFoxRepoStaticVerified
	if acornFoxLiveExactFile(root, s, acornFoxRepoActivationPath(a.ActivationID), raw, durableFileMode, false) && acornFoxRepoPointer(root, s, acornFoxRepoReleasePath(a.ActivationID), "../../releases/"+a.ReleaseID, false) {
		stage = AcornFoxRepoActivationWritten
	}
	if acornFoxRepoPointer(root, s, acornFoxRepoActivePath(), "activations/"+a.ActivationID, false) {
		if stage != AcornFoxRepoActivationWritten {
			return false
		}
		stage = AcornFoxRepoActivePublished
	}
	if acornFoxRepoPointer(root, s, acornFoxRepoCurrentPath(), "active/release", false) {
		if stage != AcornFoxRepoActivePublished {
			return false
		}
		stage = AcornFoxRepoCurrentPublished
	}
	if !acornFoxRepoExactInventory(root, s, entries, r, a, raw, stage) {
		return false
	}
	minimum := acornFoxRepoRank(j.Phase)
	if j.Phase == AcornFoxRepoPreparedFinal {
		minimum = acornFoxRepoRank(AcornFoxRepoCurrentPublished)
	}
	return acornFoxRepoRank(stage) >= minimum && (j.Phase == AcornFoxRepoPreparedFinal || acornFoxRepoRank(stage) <= acornFoxRepoRank(j.Phase)+1)
}
func acornFoxRepoExactInventory(root *os.Root, s *TaskAcornFoxRepoStore, entries []SubstrateEntry, r AcornFoxLiveReceiptV1, a AcornFoxRepoActivationV1, raw []byte, phase AcornFoxRepoPhase) bool {
	type expectedNode struct {
		directory     bool
		mode          os.FileMode
		pointerTarget string
	}
	want := map[string]expectedNode{"receipt.json": {mode: durableFileMode}}
	for _, entry := range entries {
		want[entry.Path] = expectedNode{directory: entry.Kind == SubstrateEntryDirectory, mode: os.FileMode(entry.Mode)}
	}
	if acornFoxRepoRank(phase) >= acornFoxRepoRank(AcornFoxRepoActivationWritten) {
		want["opt/acornfox/activations"] = expectedNode{directory: true, mode: durableDirMode}
		want["opt/acornfox/activations/"+a.ActivationID] = expectedNode{directory: true, mode: durableDirMode}
		want["opt/acornfox/activations/"+a.ActivationID+"/repo-activation.json"] = expectedNode{mode: durableFileMode}
		want["opt/acornfox/activations/"+a.ActivationID+"/release"] = expectedNode{pointerTarget: "../../releases/" + a.ReleaseID}
	}
	if acornFoxRepoRank(phase) >= acornFoxRepoRank(AcornFoxRepoActivePublished) {
		want["opt/acornfox/active"] = expectedNode{pointerTarget: "activations/" + a.ActivationID}
	}
	if acornFoxRepoRank(phase) >= acornFoxRepoRank(AcornFoxRepoCurrentPublished) {
		want["opt/acornfox/current"] = expectedNode{pointerTarget: "active/release"}
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
				if expected.pointerTarget == "" || !acornFoxRepoPointer(root, s, path, expected.pointerTarget, false) {
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
	if acornFoxRepoRank(phase) >= acornFoxRepoRank(AcornFoxRepoActivationWritten) && !acornFoxLiveExactFile(root, s, acornFoxRepoActivationPath(a.ActivationID), raw, durableFileMode, false) {
		return false
	}
	return true
}
func acornFoxRepoVerifyLeaseInventory(root *os.Root, s *TaskAcornFoxRepoStore, j AcornFoxRepoJournalV1, r AcornFoxLiveReceiptV1, sub *PublishedAcornFoxSubstrateV1) bool {
	a, raw, err := acornFoxRepoActivation(j, r, sub)
	if err != nil {
		return false
	}
	entries, err := acornFoxLiveExpectedEntries(sub)
	if err != nil || !acornFoxRepoVerifyPinnedLive(root, s, entries, r) {
		return false
	}
	return acornFoxRepoExactInventory(root, s, entries, r, a, raw, j.Phase)
}
func acornFoxRepoVerifyPinnedLive(root *os.Root, s *TaskAcornFoxRepoStore, entries []SubstrateEntry, r AcornFoxLiveReceiptV1) bool {
	for _, e := range entries {
		p := acornFoxLivePath(e.Path)
		info, x := root.Lstat(p)
		if x != nil || info.Mode()&os.ModeSymlink != 0 || verifyOwner(info, s.uid, s.gid) != nil || info.Mode().Perm() != os.FileMode(e.Mode) {
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
	return e == nil && acornFoxLiveExactFile(root, s, acornFoxLiveReceipt, raw, durableFileMode, false)
}
func acornFoxRepoFinal(root *os.Root, s *TaskAcornFoxRepoStore, j AcornFoxRepoJournalV1, r AcornFoxLiveReceiptV1, sub *PublishedAcornFoxSubstrateV1, a AcornFoxRepoActivationV1, raw []byte) bool {
	if !acornFoxRepoPrefix(root, s, j, r, sub, a, raw) {
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
