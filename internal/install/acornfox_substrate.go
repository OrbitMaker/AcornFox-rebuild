package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const (
	acornFoxSubstrateDir     = "substrate"
	acornFoxSubstrateRootfs  = "substrate/rootfs"
	acornFoxSubstrateIntent  = "substrate/intent.json"
	acornFoxSubstrateReceipt = "substrate/receipt.json"
)

// TaskAcornFoxSubstratePublisher is deliberately task-root-only. It has no
// production path, service, network, database, or activation capability.
type TaskAcornFoxSubstratePublisher struct {
	rootPath string
	uid, gid int
}

type AcornFoxSubstratePublishResult struct {
	Receipt InactiveSubstrateReceiptV1
	Outcome AcornFoxReconciliationOutcome
}

type PublishedAcornFoxSubstrateV1 struct {
	root     *os.Root
	receipt  InactiveSubstrateReceiptV1
	uid, gid int
}

func NewTaskAcornFoxSubstratePublisher(taskRoot string, uid, gid int) (*TaskAcornFoxSubstratePublisher, error) {
	if uid < 0 || gid < 0 || !safeAbsoluteDurableRoot(taskRoot) || forbiddenAcornFoxStageRoot(taskRoot) {
		return nil, errors.New("AcornFox task substrate root is unsafe")
	}
	info, err := os.Lstat(taskRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || verifyOwner(info, uid, gid) != nil {
		return nil, errors.New("AcornFox task substrate root is unsafe")
	}
	return &TaskAcornFoxSubstratePublisher{rootPath: taskRoot, uid: uid, gid: gid}, nil
}

func (p *TaskAcornFoxSubstratePublisher) Publish(ctx context.Context, stage *StagedAcornFoxCandidateV1, expectedBindingSHA256 string) (AcornFoxSubstratePublishResult, error) {
	if p == nil || stage == nil || !digestPattern.MatchString(expectedBindingSHA256) {
		return AcornFoxSubstratePublishResult{}, errors.New("AcornFox substrate publish input is invalid")
	}
	if existing, err := p.Reopen(expectedBindingSHA256); err == nil {
		defer existing.Close()
		return AcornFoxSubstratePublishResult{Receipt: existing.receipt, Outcome: AcornFoxReconcileCompleted}, nil
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
	root, err := os.OpenRoot(p.rootPath)
	if err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	defer root.Close()
	if err := acornFoxSubstrateWriteIntent(root, intent, p.uid, p.gid); err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	if err := acornFoxSubstrateCreateDirs(root, entries, p.uid, p.gid); err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	if err := acornFoxSubstrateCopyFiles(ctx, root, source, entries, candidate, p.uid, p.gid); err != nil {
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
	if err := acornFoxSubstrateWriteReceipt(root, receipt, p.uid, p.gid); err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	if err := lease.consume(); err != nil {
		return AcornFoxSubstratePublishResult{}, err
	}
	committed = true
	return AcornFoxSubstratePublishResult{Receipt: receipt, Outcome: AcornFoxReconcileCompleted}, nil
}

func (p *TaskAcornFoxSubstratePublisher) Reopen(expectedBindingSHA256 string) (*PublishedAcornFoxSubstrateV1, error) {
	if p == nil || !digestPattern.MatchString(expectedBindingSHA256) {
		return nil, errors.New("AcornFox substrate reopen input is invalid")
	}
	root, err := os.OpenRoot(p.rootPath)
	if err != nil {
		return nil, err
	}
	raw, err := root.ReadFile(acornFoxSubstrateReceipt)
	if err != nil {
		root.Close()
		return nil, err
	}
	receipt, err := ParseInactiveSubstrateReceiptV1(raw)
	if err != nil || receipt.CandidateReceipt.BindingSHA256 != expectedBindingSHA256 {
		root.Close()
		return nil, errors.New("AcornFox substrate receipt is invalid")
	}
	handle := &PublishedAcornFoxSubstrateV1{root: root, receipt: receipt, uid: p.uid, gid: p.gid}
	if err := handle.Verify(); err != nil {
		root.Close()
		return nil, err
	}
	return handle, nil
}

func (h *PublishedAcornFoxSubstrateV1) Verify() error {
	if h == nil || h.root == nil {
		return errors.New("AcornFox substrate handle is invalid")
	}
	if err := h.receipt.Validate(); err != nil {
		return err
	}
	for _, entry := range h.receipt.Entries {
		path := acornFoxSubstrateTarget(entry.Path)
		file, err := h.root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		info, statErr := file.Stat()
		if statErr == nil && (!info.Mode().IsRegular() && entry.Kind == SubstrateEntryFile || !info.IsDir() && entry.Kind == SubstrateEntryDirectory || info.Mode().Perm() != os.FileMode(entry.Mode) || verifyOwner(info, h.uid, h.gid) != nil || (entry.Kind == SubstrateEntryFile && (info.Size() != entry.Size || sha256SubstrateOpenFile(file) != entry.SHA256))) {
			statErr = errors.New("AcornFox substrate disk entry is invalid")
		}
		closeErr := file.Close()
		if statErr == nil {
			statErr = closeErr
		}
		if statErr != nil {
			return statErr
		}
	}
	return nil
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
	if err := h.Verify(); err != nil {
		return err
	}
	if err := h.root.RemoveAll(acornFoxSubstrateDir); err != nil {
		return ErrAcornFoxStageCleanupUnknown
	}
	if err := syncAcornFoxRoot(h.root); err != nil {
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
	add(prefix+"manifest.json", 0o644, candidate.ManifestSHA256, 0)
	for _, file := range manifest.Files {
		add(prefix+file.Path, file.Mode, file.SHA256, 0)
	}
	for path, entry := range acornFoxFixedSubstrateEntries(candidate) {
		entries = append(entries, entry)
		if entry.Kind == SubstrateEntryFile {
			sourcePath := acornFoxInstalledSource(candidate, path)
			sourceEntry := substrateEntryAt(entries, prefix+sourcePath)
			if sourceEntry != nil {
				entries[len(entries)-1].SHA256 = sourceEntry.SHA256
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
