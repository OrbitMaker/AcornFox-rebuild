package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// These services model actual systemd filesystem effects. In particular a
// removed unit cannot be stopped, and enabled state is a symlink, not a file.
type retirementServices struct {
	*acornFoxUpgradePIServiceFake
	p      acornFoxProductionPreparedFixture
	data   map[string][]byte
	inodes map[string]os.FileInfo
}

func (f *retirementServices) PILegacyAbsent(context.Context) (bool, error) {
	_, err := os.Lstat(filepath.Join(f.p.host, "etc/systemd/system/acornfox-pi-worker.service"))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	return false, err
}

func (f *retirementServices) Run(ctx context.Context, verb, unit string) error {
	if unit == "acornfox-pi-worker.service" {
		path := filepath.Join(f.p.host, "etc/systemd/system", unit)
		if _, err := os.Lstat(path); err != nil {
			return err
		}
		wants := filepath.Join(f.p.host, "etc/systemd/system/multi-user.target.wants", unit)
		switch verb {
		case "disable":
			if err := os.Remove(wants); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			f.enabled = false
		case "enable":
			if err := os.MkdirAll(filepath.Dir(wants), 0755); err != nil {
				return err
			}
			parentInfo, err := os.Lstat(filepath.Dir(wants))
			if err != nil {
				return err
			}
			f.p.owners.set(parentInfo, acornFoxInstallPrincipal{})
			if err := os.Symlink("../"+unit, wants); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			info, err := os.Lstat(wants)
			if err != nil {
				return err
			}
			f.p.owners.set(info, acornFoxInstallPrincipal{})
			f.enabled = true
		}
	}
	return f.acornFoxUpgradeServiceFake.Run(ctx, verb, unit)
}

func historicalSubstrateForTest(t *testing.T, fixture acornFoxFixture) (InactiveSubstrateReceiptV1, map[string][]byte) {
	t.Helper()
	files, contents := fixtureManifestAndContents(t, fixture)
	contents["manifest.json"] = fixture.manifestRaw
	b := fixture.binding
	candidate := AcornFoxStageReceiptV1{SchemaVersion: 1, Product: b.Product, Version: b.Version, ReleaseID: b.ReleaseID,
		ManifestSHA256: b.ManifestSHA256, ArchiveSHA256: b.ArchiveSHA256, BindingSHA256: fixture.bindingSHA,
		BundleManifestSHA256: b.BundleManifestSHA256, SourceCommit: b.SourceCommit, Architecture: b.Architecture,
		MigrationVersion: b.MigrationVersion, FileCount: len(files), TreeSHA256: strings.Repeat("a", 64)}
	if b.NMinusOne != nil {
		candidate.PredecessorBindingSHA256 = b.NMinusOne.BindingSHA256
	}
	prefix := "opt/acornfox/releases/" + b.ReleaseID + "/"
	entries := map[string]SubstrateEntry{}
	add := func(path string, mode uint32, raw []byte) {
		entries[path] = SubstrateEntry{Path: path, Kind: SubstrateEntryFile, Mode: mode, Role: OwnerRoleRoot, Group: GroupRoleRoot, Size: int64(len(raw)), SHA256: sha256Hex(raw)}
	}
	add(prefix+"manifest.json", 0644, fixture.manifestRaw)
	for _, file := range files {
		add(prefix+file.Path, file.Mode, contents[file.Path])
	}
	for path, fixed := range acornFoxFrozen0040FixedSubstrateEntries(candidate) {
		if fixed.Kind == SubstrateEntryFile {
			raw, ok := contents[acornFoxInstalledSource(candidate, path)]
			if !ok {
				t.Fatalf("missing frozen fixed source %s", path)
			}
			fixed.Size, fixed.SHA256 = int64(len(raw)), sha256Hex(raw)
		}
		entries[path] = fixed
	}
	for path := range contents {
		for parent := parentDirectory(prefix + path); strings.HasPrefix(parent, strings.TrimSuffix(prefix, "/")); parent = parentDirectory(parent) {
			entries[parent] = SubstrateEntry{Path: parent, Kind: SubstrateEntryDirectory, Mode: 0755, Role: OwnerRoleRoot, Group: GroupRoleRoot}
			if parent == strings.TrimSuffix(prefix, "/") {
				break
			}
		}
	}
	list := make([]SubstrateEntry, 0, len(entries))
	for _, entry := range entries {
		list = append(list, entry)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Path < list[j].Path })
	var err error
	candidate.TreeSHA256, err = ComputeAcornFoxReleaseTreeSHA256(candidate, list)
	if err != nil {
		t.Fatal(err)
	}
	receipt := InactiveSubstrateReceiptV1{SchemaVersion: 1, State: "inactive_complete", LayoutVersion: 1, CandidateReceipt: candidate, Entries: list, ReleaseTreeSHA256: candidate.TreeSHA256,
		UpgradeHelperSHA256: substrateEntryAt(list, AcornFoxUpgradeHelperPath).SHA256, HealthHelperSHA256: substrateEntryAt(list, AcornFoxHealthcheckHelperPath(candidate)).SHA256}
	receipt.InstalledTreeSHA256, err = ComputeAcornFoxSubstrateTreeSHA256(list)
	if err != nil {
		t.Fatal(err)
	}
	if b.MigrationVersion == "0039" {
		err = validateAcornFoxRecent0039SubstrateReceipt(receipt, b, fixture.bindingSHA)
	} else {
		err = validateAcornFoxFrozen0040SubstrateReceipt(receipt, b, fixture.bindingSHA)
	}
	if err != nil {
		t.Fatal("historical substrate", err)
	}
	return receipt, contents
}

func setupFrozen0040HostForTest(t *testing.T, u *acornFoxUpgrade, p acornFoxProductionPreparedFixture, enabled bool) (AcornFoxUpgradeRequestV1, *retirementServices) {
	t.Helper()
	s, err := u.openStore()
	if err != nil {
		t.Fatal(err)
	}
	lock, err := s.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := newAcornFoxBindingStore(s).Read(p.binding)
	if err != nil {
		t.Fatal(err)
	}
	image, err := u.capture(context.Background(), s, raw)
	if err != nil {
		t.Fatal("template capture", err)
	}
	original := image
	b, err := verifiedAcornFoxInstalled0040Binding(raw, p.binding)
	if err != nil {
		t.Fatal(err)
	}
	fixture := acornFoxFixtureForPolicy(t, b.binding.Version, nil, AcornFoxCandidateBindingV1Schema, acornFoxFrozen0040RequiredFiles())
	image.Binding = bytes.Clone(fixture.bindingRaw)
	substrate, contents := historicalSubstrateForTest(t, fixture)
	image.Substrate = substrate
	source, err := acornFoxFrozen0040ExpectedEntries(p.layout, substrate)
	if err != nil {
		t.Fatal(err)
	}
	image.Repo.BindingSHA256 = fixture.bindingSHA
	image.Repo.SubstrateReceiptSHA256 = sha256Hex(acornFoxUpgradeJSON(substrate))
	image.Live, err = acornFoxLiveMakeReceiptForLayout(p.layout, image.Repo, &PublishedAcornFoxSubstrateV1{receipt: substrate}, source)
	if err != nil {
		t.Fatal(err)
	}
	image.Repo.LiveTreeSHA256 = image.Live.LiveTreeSHA256
	image.Repo.StaticSetSHA256 = image.Live.StaticSetSHA256
	image.Repo.OwnershipPlanSHA256 = image.Live.OwnershipPlanSHA256
	image.Repo.TransactionID = "acornfox-layout-" + fixture.bindingSHA[:12]
	image.Activation, _, err = acornFoxRepoActivationForLayout(p.layout, image.Repo, image.Live, &PublishedAcornFoxSubstrateV1{receipt: substrate})
	if err != nil {
		t.Fatal(err)
	}
	image.Repo.ActivationSHA256 = sha256Hex(acornFoxUpgradeJSON(image.Activation))
	image.Repo.ActivePointerSHA256 = acornFoxRepoEvidence("acornfox-repo-active-v1\x00", fixture.bindingSHA, image.Repo.ActivationSHA256)
	image.Repo.CurrentPointerSHA256 = acornFoxRepoEvidence("acornfox-repo-current-v1\x00", fixture.bindingSHA, image.Repo.ActivationSHA256)
	for i := range image.Repo.History {
		image.Repo.History[i].EvidenceSHA256 = acornFoxRepoPhaseEvidence(image.Repo, image.Repo.History[i].To)
	}
	image.ControlPlane.BindingSHA256 = fixture.bindingSHA
	image.Runtime, err = acornFoxUpgradeRebind(original.Runtime, fixture.binding, fixture.bindingSHA, original.Runtime.SetupToken)
	if err != nil {
		t.Fatal(err)
	}
	if err = image.validate(p.layout, false); err != nil {
		t.Fatal("frozen image", err)
	}

	write := func(path string, data []byte, mode os.FileMode, principal acornFoxInstallPrincipal) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		p.owners.set(info, principal)
	}
	runtimeFiles := map[string]bool{}
	for _, f := range image.Runtime.Files {
		runtimeFiles[f.Path] = true
	}
	for _, target := range []struct {
		root    string
		entries []SubstrateEntry
		host    bool
	}{{filepath.Join(p.state, acornFoxSubstrateRootfs), substrate.Entries, false}, {p.host, source, true}} {
		for _, entry := range target.entries {
			path := filepath.Join(target.root, entry.Path)
			principal := acornFoxInstallPrincipal{}
			if target.host {
				principal = acornFoxLivePrincipalForEntry(p.layout, entry)
			}
			if entry.Kind == SubstrateEntryDirectory {
				if err := os.MkdirAll(path, os.FileMode(entry.Mode)); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, os.FileMode(entry.Mode)); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				if target.host {
					p.owners.set(info, principal)
				}
				continue
			}
			if target.host && runtimeFiles[entry.Path] {
				continue
			}
			var body []byte
			prefix := "opt/acornfox/releases/" + fixture.binding.ReleaseID + "/"
			if strings.HasPrefix(entry.Path, prefix) {
				body = contents[strings.TrimPrefix(entry.Path, prefix)]
			} else if strings.HasPrefix(entry.Path, "var/lib/acornfox/install/releases/") {
				body = acornFoxUpgradeJSON(substrate)
			} else {
				body = contents[acornFoxInstalledSource(substrate.CandidateReceipt, entry.Path)]
			}
			if body == nil {
				t.Fatalf("no bytes for %s", entry.Path)
			}
			write(path, body, os.FileMode(entry.Mode), principal)
		}
	}
	intent := AcornFoxInactiveSubstrateIntentV1{SchemaVersion: 1, LayoutVersion: 1, CandidateReceipt: substrate.CandidateReceipt, ExpectedEntryEnvelopeSHA256: substrate.InstalledTreeSHA256}
	for path, data := range map[string][]byte{acornFoxSubstrateIntent: acornFoxUpgradeJSON(intent), acornFoxSubstrateReceipt: acornFoxUpgradeJSON(substrate),
		acornFoxRepoInstallJournal: acornFoxUpgradeJSON(image.Repo), "live-receipt.json": acornFoxUpgradeJSON(image.Live), acornFoxControlPlaneReceipt: acornFoxUpgradeJSON(image.ControlPlane),
		acornFoxRuntimeIntentName: acornFoxUpgradeJSON(image.Runtime), acornFoxRuntimeReceiptName: acornFoxUpgradeJSON(image.Runtime.receipt(acornFoxUpgradeJSON(image.Runtime))),
		"bindings/" + fixture.bindingSHA + ".json": fixture.bindingRaw} {
		write(filepath.Join(p.state, path), data, 0600, acornFoxInstallPrincipal{})
	}
	if err := os.Remove(filepath.Join(p.state, "bindings", p.binding+".json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(p.host, u.layout.activationDir(original.Activation.ActivationID)), filepath.Join(p.host, u.layout.activationDir(image.Activation.ActivationID))); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(p.host, u.layout.activationReceiptPath(image.Activation.ActivationID)), acornFoxUpgradeJSON(image.Activation), 0600, acornFoxInstallPrincipal{})
	active := filepath.Join(p.host, u.layout.activePath())
	if err := os.Remove(active); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("activations/"+image.Activation.ActivationID, active); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(active)
	if err != nil {
		t.Fatal(err)
	}
	p.owners.set(info, acornFoxInstallPrincipal{})
	if _, err := os.Stat(filepath.Join(p.state, acornFoxUpgradeJournalPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fixture is not a clean first upgrade", err)
	}
	if _, err := newAcornFoxBindingStore(s).Read(fixture.bindingSHA); err != nil {
		t.Fatal("installed binding read", err)
	}
	if got, err := u.capture(context.Background(), s, fixture.bindingRaw); err != nil || !bytes.Equal(acornFoxUpgradeJSON(got), acornFoxUpgradeJSON(image)) {
		t.Fatal("frozen capture", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	provisionUpgradeAssistantConfig(t, p)
	write(filepath.Join(p.host, "var/lib/acornfox/pi/sessions/session-001.json"), []byte(`{"messages":[{"role":"user","content":"hello"}]}`), 0600, acornFoxLivePrincipalForEntry(p.layout, SubstrateEntry{Role: OwnerRolePI, Group: GroupRolePI}))
	next := newAcornFoxFixture(t, "1.2.4-test.1", &fixture)
	candidate, self, selfSHA := writeAcornFoxBridgeCandidate(t, p.parent, next)
	u.self = acornFoxSelfVerifier{path: self, uid: os.Getuid(), gid: os.Getgid()}
	services := &retirementServices{acornFoxUpgradePIServiceFake: &acornFoxUpgradePIServiceFake{acornFoxUpgradeServiceFake: &acornFoxUpgradeServiceFake{old: fixture.bindingSHA}, enabled: enabled}, p: p}
	if enabled {
		if err := services.Run(context.Background(), "enable", "acornfox-pi-worker.service"); err != nil {
			t.Fatal(err)
		}
		services.calls = nil
	}
	services.data = map[string][]byte{}
	services.inodes = map[string]os.FileInfo{}
	for _, path := range []string{acornFoxAssistantKey, acornFoxAssistantConfig, "var/lib/acornfox/pi/sessions/session-001.json"} {
		raw, err := os.ReadFile(filepath.Join(p.host, path))
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(filepath.Join(p.host, path))
		if err != nil {
			t.Fatal(err)
		}
		services.data[path] = bytes.Clone(raw)
		services.inodes[path] = info
	}
	u.services = services
	if err := os.MkdirAll(filepath.Join(p.host, "var/tmp"), 0755); err != nil {
		t.Fatal(err)
	}
	return AcornFoxUpgradeRequestV1{candidate, next.bindingSHA, fixture.bindingSHA, selfSHA}, services
}

func (f *retirementServices) assertDataPreserved(t *testing.T) {
	t.Helper()
	for path, expected := range f.data {
		raw, err := os.ReadFile(filepath.Join(f.p.host, path))
		info, statErr := os.Lstat(filepath.Join(f.p.host, path))
		if err != nil || statErr != nil || !bytes.Equal(raw, expected) || !os.SameFile(info, f.inodes[path]) {
			t.Errorf("retirement changed historical data: %s", path)
		}
	}
}
