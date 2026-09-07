package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const acornFoxRetired0039StashName = "retired-0039"
const acornFoxRetired0039Stash = "upgrade/" + acornFoxRetired0039StashName

// The exact completed journal is retained in the successor's atomic journal
// write. No deletion, mutable history pointer, or unbounded upgrade chain is
// authorized. Its old substrate is subsequently renamed within the same root.
type acornFoxRetired0039 struct {
	JournalSHA256 string          `json:"journal_sha256"`
	Journal       json.RawMessage `json:"journal"`
}

func (acornFoxRetired0039) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "retired 0039 journal [redacted]")
}

func validateAcornFoxCompleted0039(j acornFoxUpgradeJournal, layout acornFoxInstallLayout, env []byte) error {
	if j.SchemaVersion != 1 || j.Phase != "UPGRADED" || j.CrossSchema != nil || j.Retired0039 != nil || j.LayoutSHA256 != layout.evidence() {
		return ErrAcornFoxUpgradeConflict
	}
	for _, image := range []acornFoxUpgradeImage{j.Old, j.Next} {
		// The old same-schema writer omitted the unchanged environment from both
		// snapshots. Normalize in memory only, against each recorded environment SHA.
		if len(image.DatabaseEnv) == 0 {
			image.DatabaseEnv = bytes.Clone(env)
		}
		if validateAcornFoxRecent0039UpgradeImage(image, layout) != nil {
			return ErrAcornFoxUpgradeConflict
		}
	}
	old, err := verifiedAcornFoxUpgradePredecessor(j.Old.Binding, j.Old.Repo.BindingSHA256)
	if err != nil {
		return ErrAcornFoxUpgradeConflict
	}
	next, err := verifiedAcornFoxUpgradePredecessor(j.Next.Binding, j.Next.Repo.BindingSHA256)
	if err != nil || old.binding.SourceRepository != next.binding.SourceRepository || !acornFoxUpgradeVersionAfter(next.binding.Version, old.binding.Version) {
		return ErrAcornFoxUpgradeConflict
	}
	n := next.binding.NMinusOne
	if n == nil || n.MigrationVersion != acornFoxRecentPredecessorMigration || n.BindingSHA256 != old.digest || verifyAcornFoxPredecessor(j.Old.Binding, next.binding, &NMinusOne{Version: n.Version, MigrationVersion: n.MigrationVersion, SourceCommit: n.SourceCommit, ReleaseManifestSHA256: n.ReleaseManifestSHA256, ArchiveSHA256: n.ArchiveSHA256, BundleManifestSHA256: n.BundleManifestSHA256}) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	if j.Old.ControlPlane.MigrationRowsSHA256 != j.Next.ControlPlane.MigrationRowsSHA256 || j.Old.ControlPlane.DatabaseEnvSHA256 != j.Next.ControlPlane.DatabaseEnvSHA256 {
		return ErrAcornFoxUpgradeConflict
	}
	rebound, err := acornFoxUpgradeRebind(j.Old.Runtime, next.binding, next.digest, j.Next.Runtime.SetupToken)
	if err != nil || !bytes.Equal(acornFoxUpgradeJSON(rebound), acornFoxUpgradeJSON(j.Next.Runtime)) {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

func (h acornFoxRetired0039) decode(j acornFoxUpgradeJournal, layout acornFoxInstallLayout) (acornFoxUpgradeJournal, error) {
	var old acornFoxUpgradeJournal
	if !validSHA(h.JournalSHA256) || sha256Hex(h.Journal) != h.JournalSHA256 || len(h.Journal) > acornFoxUpgradeMaxJournal || strictCanonicalJSON(h.Journal, &old, "retired 0039 journal") != nil || validateAcornFoxCompleted0039(old, layout, j.Old.DatabaseEnv) != nil {
		return old, ErrAcornFoxUpgradeConflict
	}
	if j.CrossSchema == nil || j.CrossSchema.OldMigrationVersion != acornFoxRecentPredecessorMigration || j.CrossSchema.NextMigrationVersion != "0040" || j.Old.Repo.BindingSHA256 != old.Next.Repo.BindingSHA256 {
		return old, ErrAcornFoxUpgradeConflict
	}
	normalized := old.Next
	if len(normalized.DatabaseEnv) == 0 {
		normalized.DatabaseEnv = bytes.Clone(j.Old.DatabaseEnv)
	}
	if !bytes.Equal(acornFoxUpgradeJSON(normalized), acornFoxUpgradeJSON(j.Old)) {
		return old, ErrAcornFoxUpgradeConflict
	}
	return old, nil
}
func (h acornFoxRetired0039) validate(j acornFoxUpgradeJournal, layout acornFoxInstallLayout) error {
	_, err := h.decode(j, layout)
	return err
}

func (u *acornFoxUpgrade) verifyRecent0039CapturedScope(s *TaskAcornFoxRepoStore, image acornFoxUpgradeImage) error {
	j, err := u.load(s)
	if errors.Is(err, os.ErrNotExist) {
		return u.verifyRecent0039HostScope(s, image)
	}
	if err != nil || validateAcornFoxCompleted0039(j, u.layout, image.DatabaseEnv) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	next := j.Next
	if len(next.DatabaseEnv) == 0 {
		next.DatabaseEnv = bytes.Clone(image.DatabaseEnv)
	}
	if !bytes.Equal(acornFoxUpgradeJSON(next), acornFoxUpgradeJSON(image)) {
		return ErrAcornFoxUpgradeConflict
	}
	return u.verifyImage(s, j, true)
}

func (u *acornFoxUpgrade) retired0039SubstrateAt(s *TaskAcornFoxRepoStore, path string, image acornFoxUpgradeImage) error {
	info, err := s.root.Lstat(path)
	if err != nil || !safeAcornFoxRepoDir(info, s.uid, s.gid) {
		return ErrAcornFoxUpgradeConflict
	}
	root, err := s.root.OpenRoot(path)
	if err != nil {
		return ErrAcornFoxUpgradeConflict
	}
	sub, err := u.openSubstrate(root, image)
	if err != nil {
		return err
	}
	defer sub.Close()
	// Read every descendant against the closed retained substrate inventory;
	// reject foreign files, symlinks, hard links, ownership and mode changes.
	expected := map[string]SubstrateEntry{
		"substrate":        {Path: "substrate", Kind: SubstrateEntryDirectory, Mode: 0700},
		"substrate/rootfs": {Path: "substrate/rootfs", Kind: SubstrateEntryDirectory, Mode: 0700},
	}
	for _, entry := range image.Substrate.Entries {
		entry.Path = acornFoxSubstrateRootfs + "/" + entry.Path
		expected[entry.Path] = entry
	}
	for _, name := range []string{acornFoxSubstrateIntent, acornFoxSubstrateReceipt} {
		raw, err := u.read(sub.root, name, 0600, acornFoxUpgradeMaxJournal)
		if err != nil {
			return err
		}
		if name == acornFoxSubstrateReceipt && !bytes.Equal(raw, acornFoxUpgradeJSON(image.Substrate)) {
			return ErrAcornFoxUpgradeConflict
		}
		if name == acornFoxSubstrateIntent {
			want := AcornFoxInactiveSubstrateIntentV1{SchemaVersion: InactiveSubstrateReceiptV1Schema, LayoutVersion: AcornFoxSubstrateLayoutV1, CandidateReceipt: image.Substrate.CandidateReceipt, ExpectedEntryEnvelopeSHA256: image.Substrate.InstalledTreeSHA256}
			if !bytes.Equal(raw, acornFoxUpgradeJSON(want)) {
				return ErrAcornFoxUpgradeConflict
			}
		}
		expected[name] = SubstrateEntry{Path: name, Kind: SubstrateEntryFile, Mode: 0600, Size: int64(len(raw)), SHA256: sha256Hex(raw)}
	}
	receiptPath := acornFoxSubstrateRootfs + "/var/lib/acornfox/install/releases/" + image.Activation.ReleaseID + ".json"
	raw := acornFoxUpgradeJSON(image.Substrate)
	expected[receiptPath] = SubstrateEntry{Path: receiptPath, Kind: SubstrateEntryFile, Mode: 0600, Size: int64(len(raw)), SHA256: sha256Hex(raw)}
	seen := map[string]bool{}
	var walk func(string) error
	walk = func(path string) error {
		f, err := sub.root.OpenFile(path, os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		children, err := f.ReadDir(-1)
		f.Close()
		if err != nil {
			return err
		}
		for _, child := range children {
			name := filepath.Join(path, child.Name())
			entry, ok := expected[name]
			if !ok {
				return ErrAcornFoxUpgradeConflict
			}
			info, err := sub.root.Lstat(name)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || uint32(info.Mode().Perm()) != entry.Mode || verifyOwner(info, s.uid, s.gid) != nil {
				return ErrAcornFoxUpgradeConflict
			}
			seen[name] = true
			if entry.Kind == SubstrateEntryDirectory {
				if !info.IsDir() {
					return ErrAcornFoxUpgradeConflict
				}
				if err := walk(name); err != nil {
					return err
				}
			} else {
				value, err := u.read(sub.root, name, os.FileMode(entry.Mode), acornFoxArchiveMaxBytes)
				if err != nil || int64(len(value)) != entry.Size || sha256Hex(value) != entry.SHA256 {
					return ErrAcornFoxUpgradeConflict
				}
			}
		}
		return nil
	}
	if err := walk("."); err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

func (u *acornFoxUpgrade) verifyRetired0039Stash(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal) error {
	if j.Retired0039 == nil {
		return nil
	}
	history, err := j.Retired0039.decode(j, u.layout)
	if err != nil {
		return err
	}
	return u.retired0039SubstrateAt(s, acornFoxRetired0039Stash, history.Old)
}

func (u *acornFoxUpgrade) retire0039Stash(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal) error {
	if j.Retired0039 == nil {
		return nil
	}
	if !s.ownsLock() || j.validate(u.layout) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	history, err := j.Retired0039.decode(j, u.layout)
	if err != nil {
		return err
	}
	if _, err := s.root.Lstat(acornFoxRetired0039Stash); err == nil {
		return u.verifyRetired0039Stash(s, j)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrAcornFoxUpgradeConflict
	}
	if err := u.retired0039SubstrateAt(s, "upgrade/old-state", history.Old); err != nil {
		return err
	}
	// Journal already binds all archived bytes. Rename is atomic; on interruption
	// either source or destination remains, and this operation can safely repeat.
	if err := s.root.Rename("upgrade/old-state", acornFoxRetired0039Stash); err != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	if err := acornFoxLiveSyncDir(s.root, acornFoxUpgradeDirectory); err != nil {
		return err
	}
	return u.fault("legacy-0039-stash-retired")
}

func (u *acornFoxUpgrade) verifyCompleted0039Manifests(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal) error {
	var migrations map[string]FileDigest
	for _, image := range []acornFoxUpgradeImage{j.Old, j.Next} {
		raw, err := u.imageManifest(s, j, image)
		if err != nil {
			return err
		}
		var manifest Manifest
		binding, err := verifiedAcornFoxUpgradePredecessor(image.Binding, image.Repo.BindingSHA256)
		if err != nil || strictCanonicalJSON(raw, &manifest, "completed 0039 manifest") != nil || validateAcornFoxRecent0039Manifest(manifest, binding.binding) != nil {
			return ErrAcornFoxUpgradeConflict
		}
		got := map[string]FileDigest{}
		for _, file := range manifest.Files {
			if strings.HasPrefix(file.Path, "migrations/") {
				got[file.Path] = file
			}
		}
		if migrations != nil && !bytes.Equal(acornFoxUpgradeJSON(got), acornFoxUpgradeJSON(migrations)) {
			return ErrAcornFoxUpgradeConflict
		}
		migrations = got
	}
	return nil
}
