package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
)

func (u *acornFoxUpgrade) capture(ctx context.Context, s *TaskAcornFoxRepoStore, binding []byte) (acornFoxUpgradeImage, error) {
	var image acornFoxUpgradeImage
	a, _, e := acornFoxRuntimeAuthority(ctx, s, s.hostRoot)
	if e != nil {
		return image, e
	}
	j, e := s.Load(ctx)
	if e != nil {
		return image, e
	}
	pub, e := newAcornFoxSubstratePublisherForLayout(u.layout)
	if e != nil {
		return image, e
	}
	defer pub.Close()
	sub, e := pub.Reopen(j.BindingSHA256)
	if e != nil {
		return image, e
	}
	defer sub.Close()
	raw, e := u.read(s.root, "live-receipt.json", 0600, acornFoxUpgradeMaxJournal)
	if e != nil {
		return image, e
	}
	live, e := ParseAcornFoxLiveReceiptV1(raw)
	if e != nil {
		return image, e
	}
	entries, e := acornFoxLiveExpectedEntriesForLayout(u.layout, sub)
	if e != nil {
		return image, e
	}
	if e = acornFoxValidateProductionManagedScopePrefix(s.hostRoot, s, entries, a, acornFoxUpgradeJSON(a), acornFoxRepoPrefixCurrent); e != nil {
		return image, e
	}
	raw, e = u.read(s.root, acornFoxControlPlaneReceipt, 0600, acornFoxUpgradeMaxJournal)
	if e != nil {
		return image, e
	}
	cp, e := ParseAcornFoxControlPlaneMigrationReceiptV1(raw)
	if e != nil {
		return image, e
	}
	raw, e = u.read(s.root, acornFoxRuntimeIntentName, 0600, acornFoxRuntimeMaxIntent)
	if e != nil {
		return image, e
	}
	runtime, e := parseAcornFoxRuntimeIntent(raw)
	if e != nil {
		return image, e
	}
	raw, e = u.read(s.root, acornFoxRuntimeReceiptName, 0600, acornFoxRuntimeMaxIntent)
	if e != nil {
		return image, e
	}
	receipt, e := ParseAcornFoxRuntimeConfigReceiptV1(raw)
	if e != nil || receipt != runtime.receipt(acornFoxUpgradeJSON(runtime)) {
		return image, ErrAcornFoxUpgradeConflict
	}
	image = acornFoxUpgradeImage{Binding: append([]byte(nil), binding...), Substrate: sub.receipt, Repo: j, Live: live, Activation: a, ControlPlane: cp, Runtime: runtime}
	return image, image.validate(u.layout)
}
func (u *acornFoxUpgrade) nextImage(old acornFoxUpgradeImage, set *acornFoxCandidateSet, sub *PublishedAcornFoxSubstrateV1) (acornFoxUpgradeImage, error) {
	var i acornFoxUpgradeImage
	j, e := newAcornFoxRepoJournalForLayout(u.layout, set.bindingSHA256, sha256Hex(acornFoxUpgradeJSON(sub.receipt)))
	if e != nil {
		return i, e
	}
	entries, e := acornFoxLiveExpectedEntriesForLayout(u.layout, sub)
	if e != nil {
		return i, e
	}
	live, e := acornFoxLiveMakeReceiptForLayout(u.layout, j, sub, entries)
	if e != nil {
		return i, e
	}
	for _, phase := range []AcornFoxRepoPhase{AcornFoxRepoLiveMaterialized, AcornFoxRepoStaticVerified} {
		j, e = acornFoxLiveAdvance(j, phase, live)
		if e != nil {
			return i, e
		}
	}
	a, raw, e := acornFoxRepoActivationForLayout(u.layout, j, live, sub)
	if e != nil {
		return i, e
	}
	digest := sha256Hex(raw)
	// This is an intended receipt in the private snapshot. It is published only
	// under the upgrade marker and observed against actual production ownership
	// before the transaction can claim success.
	for _, phase := range []AcornFoxRepoPhase{AcornFoxRepoActivationWritten, AcornFoxRepoActivePublished, AcornFoxRepoCurrentPublished, AcornFoxRepoPreparedFinal} {
		prior := j.Phase
		j.Revision++
		j.Phase = phase
		switch phase {
		case AcornFoxRepoActivationWritten:
			j.ActivationSHA256 = digest
		case AcornFoxRepoActivePublished:
			j.ActivePointerSHA256 = acornFoxRepoEvidence("acornfox-repo-active-v1\x00", j.BindingSHA256, digest)
		case AcornFoxRepoCurrentPublished:
			j.CurrentPointerSHA256 = acornFoxRepoEvidence("acornfox-repo-current-v1\x00", j.BindingSHA256, digest)
		}
		j.History = append(j.History, AcornFoxRepoHistoryV1{j.Revision, AcornFoxRepoHistoryAdvance, prior, phase, acornFoxRepoPhaseEvidence(j, phase)})
		if j.Validate() != nil {
			return i, ErrAcornFoxUpgradeConflict
		}
	}
	cp := old.ControlPlane
	cp.BindingSHA256, cp.ReleaseID, cp.SourceCommit = set.bindingSHA256, set.binding.binding.ReleaseID, set.binding.binding.SourceCommit
	runtime, e := acornFoxUpgradeRebind(old.Runtime, set.binding.binding, set.bindingSHA256)
	if e != nil {
		return i, e
	}
	i = acornFoxUpgradeImage{Binding: append([]byte(nil), set.bindingRaw...), Substrate: sub.receipt, Repo: j, Live: live, Activation: a, ControlPlane: cp, Runtime: runtime}
	return i, i.validate(u.layout)
}
func (u *acornFoxUpgrade) phase(s *TaskAcornFoxRepoStore, j *acornFoxUpgradeJournal, phase string) error {
	j.Phase = phase
	if e := u.save(s, *j, false); e != nil {
		return e
	}
	return u.fault(strings.ToLower(phase))
}
func (u *acornFoxUpgrade) stop(ctx context.Context) error {
	for _, unit := range []string{"acornfox-edge.service", "acornfox-agent.service", "acornfox-server.service", "acornfox-caddy.service", "acornfox-buildkit.service", "acornfox-build-network.service"} {
		if e := u.services.Run(ctx, "stop", unit); e != nil {
			return e
		}
	}
	return nil
}
func (u *acornFoxUpgrade) start(ctx context.Context) error {
	if e := u.services.Run(ctx, "daemon-reload", ""); e != nil {
		return e
	}
	for _, unit := range []string{"acornfox-build-network.service", "acornfox-buildkit.service", "acornfox-caddy.service", "acornfox-server.service", "acornfox-agent.service"} {
		if e := u.services.Run(ctx, "start", unit); e != nil {
			return e
		}
	}
	return nil
}
func (u *acornFoxUpgrade) unblock(ctx context.Context, s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal) error {
	// systemd ConditionPathExists on edge requires removing the marker first.
	// Any failure reinstates it and stops edge before rollback is attempted.
	if e := u.marker(s, j, false); e != nil {
		return e
	}
	if e := u.fault("marker-cleared"); e != nil {
		return e
	}
	if e := u.services.Run(ctx, "start", "acornfox-edge.service"); e != nil {
		return e
	}
	return u.services.EdgeHealthy(ctx)
}
func (u *acornFoxUpgrade) forward(ctx context.Context, s *TaskAcornFoxRepoStore, j *acornFoxUpgradeJournal) error {
	if e := u.marker(s, *j, true); e != nil {
		return e
	}
	if e := u.phase(s, j, "BLOCKED"); e != nil {
		return e
	}
	if e := u.stop(ctx); e != nil {
		return e
	}
	if e := u.fault("services-stopped"); e != nil {
		return e
	}
	if e := u.copyNextSubstrate(s, *j); e != nil {
		return e
	}
	if e := u.applyImage(s, *j, true); e != nil {
		return e
	}
	if e := u.phase(s, j, "PUBLISHED"); e != nil {
		return e
	}
	if e := u.switchSubstrate(s, *j, true); e != nil {
		return e
	}
	if e := u.pointer(s, u.layout.activePath(), "activations/"+j.Old.Activation.ActivationID, "activations/"+j.Next.Activation.ActivationID); e != nil {
		return e
	}
	if e := u.phase(s, j, "SWITCHED"); e != nil {
		return e
	}
	if e := u.verifyImage(s, *j, true); e != nil {
		return e
	}
	if e := u.start(ctx); e != nil {
		return e
	}
	if e := u.services.Healthy(ctx, j.Next); e != nil {
		return e
	}
	if e := u.fault("healthy"); e != nil {
		return e
	}
	if e := u.unblock(ctx, s, *j); e != nil {
		return e
	}
	return u.phase(s, j, "UPGRADED")
}
func (u *acornFoxUpgrade) restore(ctx context.Context, s *TaskAcornFoxRepoStore, j *acornFoxUpgradeJournal) (err error) {
	defer func() {
		if err != nil {
			_ = u.marker(s, *j, true)
			_ = u.services.Run(context.WithoutCancel(ctx), "stop", "acornfox-edge.service")
		}
	}()
	if err = u.marker(s, *j, true); err != nil {
		return err
	}
	if err = u.phase(s, j, "ROLLING_BACK"); err != nil {
		return err
	}
	if err = u.stop(ctx); err != nil {
		return err
	}
	if err = u.copyNextSubstrate(s, *j); err != nil {
		return err
	}
	if err = u.applyImage(s, *j, false); err != nil {
		return err
	}
	if err = u.switchSubstrate(s, *j, false); err != nil {
		return err
	}
	if err = u.pointer(s, u.layout.activePath(), "activations/"+j.Next.Activation.ActivationID, "activations/"+j.Old.Activation.ActivationID); err != nil {
		return err
	}
	return u.verifyImage(s, *j, false)
}
func (u *acornFoxUpgrade) rollback(ctx context.Context, s *TaskAcornFoxRepoStore, j *acornFoxUpgradeJournal) (err error) {
	defer func() {
		if err != nil {
			_ = u.marker(s, *j, true)
			_ = u.services.Run(context.WithoutCancel(ctx), "stop", "acornfox-edge.service")
		}
	}()
	if err = u.restore(ctx, s, j); err != nil {
		return err
	}
	if err = u.start(ctx); err != nil {
		return err
	}
	if err = u.services.Healthy(ctx, j.Old); err != nil {
		return err
	}
	if err = u.unblock(ctx, s, *j); err != nil {
		return err
	}
	return u.phase(s, j, "ROLLED_BACK")
}

func (u *acornFoxUpgrade) verifyImage(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, next bool) error {
	image := j.Old
	if next {
		image = j.Next
	}
	raw, e := u.read(s.root, acornFoxRepoInstallJournal, 0600, acornFoxRepoMaxJournalSize)
	if e != nil || !bytes.Equal(raw, acornFoxUpgradeJSON(image.Repo)) {
		return ErrAcornFoxUpgradeConflict
	}
	files, modes, e := u.imageFiles(s, j, image)
	if e != nil {
		return e
	}
	principals := map[string]acornFoxInstallPrincipal{}
	for _, entry := range image.Substrate.Entries {
		if entry.Kind == SubstrateEntryFile {
			principals[entry.Path] = acornFoxLivePrincipalForEntry(u.layout, entry)
		}
	}
	for path, want := range files {
		got, e := u.readPrincipal(s.hostRoot, path, modes[path], acornFoxArchiveMaxBytes, principals[path])
		if e != nil || !bytes.Equal(got, want) {
			return ErrAcornFoxUpgradeConflict
		}
	}
	for path, target := range map[string]string{u.layout.activePath(): "activations/" + image.Activation.ActivationID, u.layout.currentPath(): "active/release"} {
		if !acornFoxRepoPointerForLayout(s.hostRoot, s, u.layout, path, target, false) {
			return ErrAcornFoxUpgradeConflict
		}
	}
	root, e := s.root.OpenRoot(".")
	if e != nil {
		return e
	}
	sub, e := u.openSubstrate(root, image)
	if e != nil {
		return e
	}
	defer sub.Close()
	// Observe every role and file at its real production path; the task artifact
	// is never accepted as a substitute for host materialization.
	entries, e := acornFoxLiveExpectedEntriesForLayout(u.layout, sub)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if acornFoxProductionSharedParent(entry.Path) {
			continue
		}
		if !acornFoxProductionEntryMatches(s.hostRoot, s, entry.Path, entry) {
			return ErrAcornFoxUpgradeConflict
		}
	}
	return u.verifyRetainedScope(s, j, image)
}

// acornFoxUpgradeRetainedScope is the Current-scope integration point. It
// recognizes exactly the journal-bound pair and verifies both retained
// releases/activations plus the selected host state. It never permits an
// arbitrary release directory or generic descendants under an upgrade prefix.
// Caller must already own the fixed repository lock.
func acornFoxUpgradeRetainedScope(root *os.Root, s *TaskAcornFoxRepoStore, activation AcornFoxRepoActivationV1) (bool, error) {
	if root == nil || s == nil || !s.ownsLock() {
		return false, ErrAcornFoxUpgradeConflict
	}
	host, e := root.Stat(".")
	if e != nil || !os.SameFile(host, s.layout.hostRootInfo) {
		return false, ErrAcornFoxUpgradeConflict
	}
	u := newAcornFoxUpgrade(s.layout)
	u.ownership = s.ownership
	j, e := u.load(s)
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	if e != nil {
		return true, e
	}
	image := j.Old
	if activation == j.Next.Activation {
		image = j.Next
	} else if activation != j.Old.Activation {
		return true, ErrAcornFoxUpgradeConflict
	}
	if j.Phase == "UPGRADED" && image.Repo.BindingSHA256 != j.Next.Repo.BindingSHA256 || j.Phase == "ROLLED_BACK" && image.Repo.BindingSHA256 != j.Old.Repo.BindingSHA256 {
		return true, ErrAcornFoxUpgradeConflict
	}
	return true, u.verifyImage(s, j, image.Repo.BindingSHA256 == j.Next.Repo.BindingSHA256)
}
func (u *acornFoxUpgrade) verifyRetainedScope(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, current acornFoxUpgradeImage) error {
	entries := map[string]SubstrateEntry{}
	files := map[string][]byte{}
	modes := map[string]os.FileMode{}
	pointers := map[string]string{}
	// Shared paths use the selected image. Only versioned immutable material from
	// the other image extends the inventory.
	for _, image := range []acornFoxUpgradeImage{j.Old, j.Next} {
		prefix := "opt/acornfox/releases/" + image.Activation.ReleaseID
		for _, entry := range image.Substrate.Entries {
			if entry.Path == prefix || strings.HasPrefix(entry.Path, prefix+"/") || image.Repo.BindingSHA256 == current.Repo.BindingSHA256 {
				if entry.Path == "var/lib/acornfox/install" && entry.Kind == SubstrateEntryDirectory {
					entry.Mode = 0700
				}
				entries[entry.Path] = entry
			}
		}
		dir := u.layout.activationDir(image.Activation.ActivationID)
		entries["opt/acornfox/activations"] = SubstrateEntry{Path: "opt/acornfox/activations", Kind: SubstrateEntryDirectory, Mode: uint32(u.layout.activationDirectoryMode()), Role: OwnerRoleRoot, Group: GroupRoleRoot}
		entries[dir] = SubstrateEntry{Path: dir, Kind: SubstrateEntryDirectory, Mode: uint32(u.layout.activationDirectoryMode()), Role: OwnerRoleRoot, Group: GroupRoleRoot}
		path := u.layout.activationReceiptPath(image.Activation.ActivationID)
		files[path] = acornFoxUpgradeJSON(image.Activation)
		modes[path] = 0600
		env, e := u.read(s.root, acornFoxControlPlaneStateEnv, 0600, 16384)
		if e != nil || sha256Hex(env) != image.ControlPlane.DatabaseEnvSHA256 {
			return ErrAcornFoxUpgradeConflict
		}
		files[dir+"/database.env"] = env
		modes[dir+"/database.env"] = 0600
		pointers[u.layout.activationReleasePath(image.Activation.ActivationID)] = "../../releases/" + image.Activation.ReleaseID
	}
	pointers[u.layout.activePath()] = "activations/" + current.Activation.ActivationID
	pointers[u.layout.currentPath()] = "active/release"
	entries[acornFoxRuntimeTarget] = SubstrateEntry{Path: acornFoxRuntimeTarget, Kind: SubstrateEntryDirectory, Mode: 0755, Role: OwnerRoleRoot, Group: GroupRoleRoot}
	for _, f := range current.Runtime.Files {
		path := strings.TrimPrefix(f.Path, "/")
		files[path] = f.Data
		modes[path] = os.FileMode(f.Mode)
	}
	marker, me := u.read(s.hostRoot, acornFoxUpgradeMarkerPath, 0600, 256)
	if me == nil {
		if !bytes.Equal(marker, []byte(j.Old.Repo.BindingSHA256+"\n"+j.Next.Repo.BindingSHA256+"\n")) {
			return ErrAcornFoxUpgradeConflict
		}
		files[acornFoxUpgradeMarkerPath] = marker
		modes[acornFoxUpgradeMarkerPath] = 0600
	} else if !errors.Is(me, os.ErrNotExist) {
		return ErrAcornFoxUpgradeConflict
	}
	seen := map[string]bool{}
	var walk func(string) error
	walk = func(path string) error {
		if target, ok := pointers[path]; ok {
			if !acornFoxRepoPointerForLayout(s.hostRoot, s, u.layout, path, target, false) {
				return ErrAcornFoxUpgradeConflict
			}
			seen[path] = true
			return nil
		}
		if want, ok := files[path]; ok {
			raw, e := u.read(s.hostRoot, path, modes[path], acornFoxArchiveMaxBytes)
			if e != nil || !bytes.Equal(raw, want) {
				return ErrAcornFoxUpgradeConflict
			}
			seen[path] = true
			return nil
		}
		entry, ok := entries[path]
		if !ok || !acornFoxProductionEntryMatches(s.hostRoot, s, path, entry) {
			return ErrAcornFoxUpgradeConflict
		}
		seen[path] = true
		if entry.Kind == SubstrateEntryFile || path == "var/lib/acornfox/install" {
			return nil
		}
		if acornFoxServiceDataRoot(path) {
			for child := range entries {
				if parentDirectory(child) == path {
					if e := walk(child); e != nil {
						return e
					}
				}
			}
			return nil
		}
		d, e := s.hostRoot.OpenFile(path, os.O_RDONLY, 0)
		if e != nil {
			return e
		}
		children, e := d.ReadDir(-1)
		d.Close()
		if e != nil {
			return e
		}
		for _, child := range children {
			if e = walk(path + "/" + child.Name()); e != nil {
				return e
			}
		}
		return nil
	}
	for _, path := range acornFoxProductionManagedRoots() {
		if e := walk(path); e != nil {
			return e
		}
	}
	unitEntries := map[string]SubstrateEntry{}
	for p, e := range entries {
		unitEntries[p] = e
	}
	if e := acornFoxValidateProductionSystemdWithBootLinks(s.hostRoot, s, unitEntries, seen, true); e != nil {
		return e
	}
	for path := range entries {
		if acornFoxProductionStateChild(path) || acornFoxProductionSharedParent(path) {
			continue
		}
		if !seen[path] {
			return ErrAcornFoxUpgradeConflict
		}
	}
	for path := range files {
		if !seen[path] {
			return ErrAcornFoxUpgradeConflict
		}
	}
	for path := range pointers {
		if !seen[path] {
			return ErrAcornFoxUpgradeConflict
		}
	}
	return u.verifyPrivateStore(s, j, current)
}
func (u *acornFoxUpgrade) verifyPrivateStore(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal, current acornFoxUpgradeImage) error {
	info, e := s.root.Lstat(acornFoxUpgradeDirectory)
	if e != nil || !safeAcornFoxRepoDir(info, s.uid, s.gid) {
		return ErrAcornFoxUpgradeConflict
	}
	dir, e := s.root.OpenFile(acornFoxUpgradeDirectory, os.O_RDONLY, 0)
	if e != nil {
		return e
	}
	children, e := dir.ReadDir(-1)
	dir.Close()
	if e != nil {
		return e
	}
	if len(children) != 3 {
		return ErrAcornFoxUpgradeConflict
	}
	for _, child := range children {
		if child.Name() != "journal.json" && child.Name() != "old-state" && child.Name() != "new-state" {
			return ErrAcornFoxUpgradeConflict
		}
	}
	for _, item := range []struct {
		path  string
		image acornFoxUpgradeImage
	}{{"upgrade/old-state", j.Old}, {"upgrade/new-state", j.Next}} {
		info, e := s.root.Lstat(item.path)
		if e != nil || !safeAcornFoxRepoDir(info, s.uid, s.gid) {
			return ErrAcornFoxUpgradeConflict
		}
		d, e := s.root.OpenFile(item.path, os.O_RDONLY, 0)
		if e != nil {
			return e
		}
		list, e := d.ReadDir(-1)
		d.Close()
		if e != nil {
			return e
		}
		if current.Repo.BindingSHA256 == item.image.Repo.BindingSHA256 {
			if len(list) != 0 {
				return ErrAcornFoxUpgradeConflict
			}
			continue
		}
		if len(list) != 1 || list[0].Name() != "substrate" {
			return ErrAcornFoxUpgradeConflict
		}
		root, e := s.root.OpenRoot(item.path)
		if e != nil {
			return e
		}
		h, e := u.openSubstrate(root, item.image)
		if e != nil {
			return e
		}
		h.Close()
	}
	return nil
}
