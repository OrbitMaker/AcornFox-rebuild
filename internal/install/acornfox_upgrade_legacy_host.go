package install

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

const (
	acornFoxLegacyHostJournalPath = "legacy-0034-host-provision.json"
	acornFoxLegacyHostJournalTemp = ".legacy-0034-host-provision.tmp"
	acornFoxLegacyHostJournalMax  = 64 * 1024
)

var acornFoxLegacyPIDataDirectories = []string{
	"var/lib/acornfox/pi",
	"var/lib/acornfox/pi/work",
	"var/lib/acornfox/pi/agent",
	"var/lib/acornfox/pi/sessions",
}

type acornFoxLegacy0034Identity struct {
	old       AcornFoxCandidateBindingV1
	oldSHA256 string
	candidate VerifiedAcornFoxBindingV1
}

func newAcornFoxLegacy0034Identity(oldRaw []byte, oldSHA256 string, candidate VerifiedAcornFoxBindingV1) (acornFoxLegacy0034Identity, error) {
	old, err := parseAcornFoxPredecessorBindingV1(oldRaw, oldSHA256)
	if err != nil || validateAcornFoxLegacyPredecessorBinding(old) != nil || !candidate.valid() {
		return acornFoxLegacy0034Identity{}, ErrAcornFoxUpgradeConflict
	}
	n := candidate.binding.NMinusOne
	if n == nil || !acornFoxUpgradeVersionAfter(candidate.binding.Version, old.Version) || n.Version != old.Version || n.MigrationVersion != AcornFoxLegacyPredecessorMigration || n.SourceCommit != old.SourceCommit || n.ReleaseManifestSHA256 != old.ManifestSHA256 || n.ArchiveSHA256 != old.ArchiveSHA256 || n.BundleManifestSHA256 != old.BundleManifestSHA256 || n.BindingSHA256 != oldSHA256 {
		return acornFoxLegacy0034Identity{}, ErrAcornFoxUpgradeConflict
	}
	return acornFoxLegacy0034Identity{old: old, oldSHA256: oldSHA256, candidate: candidate}, nil
}

type acornFoxLegacyHostJournal struct {
	SchemaVersion          int             `json:"schema_version"`
	Phase                  string          `json:"phase"`
	OldBindingSHA256       string          `json:"old_binding_sha256"`
	CandidateBindingSHA256 string          `json:"candidate_binding_sha256"`
	CandidateBinding       json.RawMessage `json:"candidate_binding"`
	OldLayoutSHA256        string          `json:"old_layout_sha256"`
	NewLayoutSHA256        string          `json:"new_layout_sha256,omitempty"`
	PIGID                  int             `json:"pi_gid,omitempty"`
	PIUID                  int             `json:"pi_uid,omitempty"`
	Directories            int             `json:"directories,omitempty"`
	EvidenceSHA256         string          `json:"evidence_sha256,omitempty"`
}

func (j acornFoxLegacyHostJournal) validate(identity acornFoxLegacy0034Identity, legacy acornFoxInstallLayout) error {
	bound, err := ParseAcornFoxCandidateBindingV1(j.CandidateBinding, j.CandidateBindingSHA256)
	if j.SchemaVersion != 1 || err != nil || bound.digest != identity.candidate.digest || j.OldBindingSHA256 != identity.oldSHA256 || j.CandidateBindingSHA256 != identity.candidate.digest || j.OldLayoutSHA256 != legacy.evidence() || j.Directories < 0 || j.Directories > len(acornFoxLegacyPIDataDirectories) {
		return ErrAcornFoxUpgradeConflict
	}
	switch j.Phase {
	case "PREPARED":
		if j.PIGID != 0 || j.PIUID != 0 || j.Directories != 0 || j.NewLayoutSHA256 != "" || j.EvidenceSHA256 != "" {
			return ErrAcornFoxUpgradeConflict
		}
	case "GROUP_CREATED":
		if j.PIGID <= 0 || j.PIUID != 0 || j.Directories != 0 || j.NewLayoutSHA256 != "" || j.EvidenceSHA256 != "" {
			return ErrAcornFoxUpgradeConflict
		}
	case "ACCOUNT_CREATED", "DIRECTORIES_CREATED":
		if j.PIGID <= 0 || j.PIUID <= 0 || j.NewLayoutSHA256 != "" || j.EvidenceSHA256 != "" || (j.Phase == "ACCOUNT_CREATED" && j.Directories != 0) || (j.Phase == "DIRECTORIES_CREATED" && j.Directories == 0) {
			return ErrAcornFoxUpgradeConflict
		}
	case "COMPLETE":
		if j.PIGID <= 0 || j.PIUID <= 0 || j.Directories != len(acornFoxLegacyPIDataDirectories) || !validSHA(j.NewLayoutSHA256) || !validSHA(j.EvidenceSHA256) {
			return ErrAcornFoxUpgradeConflict
		}
	default:
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

// acornFoxLegacyHostProvisionEvidence is safe to bind into the private main
// upgrade journal. It contains no path supplied by a caller and no credential.
type acornFoxLegacyHostProvisionEvidence struct {
	SchemaVersion          int    `json:"schema_version"`
	OldBindingSHA256       string `json:"old_binding_sha256"`
	CandidateBindingSHA256 string `json:"candidate_binding_sha256"`
	OldLayoutSHA256        string `json:"old_layout_sha256"`
	NewLayoutSHA256        string `json:"new_layout_sha256"`
	PIUID                  int    `json:"pi_uid"`
	PIGID                  int    `json:"pi_gid"`
	DirectorySetSHA256     string `json:"directory_set_sha256"`
}

func acornFoxLegacyPIDirectorySetSHA256() string {
	raw, _ := json.Marshal(struct {
		SchemaVersion int      `json:"schema_version"`
		Paths         []string `json:"paths"`
		Mode          uint32   `json:"mode"`
		Owner         string   `json:"owner"`
		Group         string   `json:"group"`
	}{1, acornFoxLegacyPIDataDirectories, 0o700, "acornfox-pi", "acornfox-pi"})
	return sha256Hex(raw)
}

func (e acornFoxLegacyHostProvisionEvidence) validate(identity acornFoxLegacy0034Identity, oldLayout, newLayout acornFoxInstallLayout) error {
	pi, ok := newLayout.owner(AcornFoxLivePIRole)
	if e.SchemaVersion != 1 || e.OldBindingSHA256 != identity.oldSHA256 || e.CandidateBindingSHA256 != identity.candidate.digest || e.OldLayoutSHA256 != oldLayout.evidence() || e.NewLayoutSHA256 != newLayout.evidence() || e.PIUID != pi.uid || e.PIGID != pi.gid || e.DirectorySetSHA256 != acornFoxLegacyPIDirectorySetSHA256() || !ok || oldLayout.validateLegacy0034() != nil || newLayout.validate() != nil {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

func (e acornFoxLegacyHostProvisionEvidence) digest(identity acornFoxLegacy0034Identity, oldLayout, newLayout acornFoxInstallLayout) (string, error) {
	if e.validate(identity, oldLayout, newLayout) != nil {
		return "", ErrAcornFoxUpgradeConflict
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return "", ErrAcornFoxUpgradeConflict
	}
	return sha256Hex(raw), nil
}

type acornFoxLegacyHostProvisioner struct {
	legacy      acornFoxInstallLayout
	lookupUser  func(string) (*user.User, error)
	lookupGroup func(string) (*user.Group, error)
	unitAbsent  func(context.Context) (bool, error)
	run         func(context.Context, string, ...string) error
	verifyHost  func(acornFoxLegacy0034Identity) error
	chown       func(*os.File, int, int) error
	observe     func(os.FileInfo) (acornFoxInstallPrincipal, bool)
	fault       func(string) error
}

// ensureAcornFoxLegacyUpgradeHost is the only production entry point. Inputs
// contain immutable identities, never host paths or account configuration.
func ensureAcornFoxLegacyUpgradeHost(ctx context.Context, oldRaw []byte, oldSHA256 string, candidate VerifiedAcornFoxBindingV1) (acornFoxInstallLayout, acornFoxLegacyHostProvisionEvidence, error) {
	identity, err := newAcornFoxLegacy0034Identity(oldRaw, oldSHA256, candidate)
	if err != nil {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, err
	}
	legacy, err := newProductionAcornFoxLegacy0034Layout()
	if err != nil {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, err
	}
	p := newAcornFoxLegacyHostProvisioner(legacy)
	return p.ensure(ctx, identity)
}

// recoverAcornFoxLegacyUpgradeHost resumes the fixed provisioning prefix
// before the normal seven-role constructor is usable. A missing journal means
// that this compatibility path never began.
func recoverAcornFoxLegacyUpgradeHost(ctx context.Context) (acornFoxInstallLayout, acornFoxLegacyHostProvisionEvidence, bool, error) {
	legacy, err := newProductionAcornFoxLegacy0034Layout()
	if err != nil {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, false, err
	}
	state, err := os.OpenRoot(legacy.stateRootPath)
	if err != nil {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, false, ErrAcornFoxUpgradeUnknown
	}
	defer state.Close()
	if _, err := state.Lstat(acornFoxLegacyHostJournalPath); errors.Is(err, os.ErrNotExist) {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, false, nil
	} else if err != nil {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, false, ErrAcornFoxUpgradeUnknown
	}
	raw, err := readAcornFoxLegacyEvidence(state, acornFoxLegacyHostJournalPath, legacy.stateOwner, acornFoxLegacyHostJournalMax)
	if err != nil {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, true, err
	}
	var journal acornFoxLegacyHostJournal
	if strictCanonicalJSON(raw, &journal, "AcornFox legacy host recovery journal") != nil {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, true, ErrAcornFoxUpgradeConflict
	}
	candidate, err := ParseAcornFoxCandidateBindingV1(journal.CandidateBinding, journal.CandidateBindingSHA256)
	if err != nil || !validSHA(journal.OldBindingSHA256) {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, true, ErrAcornFoxUpgradeConflict
	}
	oldRaw, err := readAcornFoxLegacyEvidence(state, "bindings/"+journal.OldBindingSHA256+".json", legacy.stateOwner, acornFoxCandidateBindingMaxBytes)
	if err != nil {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, true, err
	}
	identity, err := newAcornFoxLegacy0034Identity(oldRaw, journal.OldBindingSHA256, candidate)
	if err != nil || journal.validate(identity, legacy) != nil {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, true, ErrAcornFoxUpgradeConflict
	}
	layout, evidence, err := newAcornFoxLegacyHostProvisioner(legacy).ensure(ctx, identity)
	return layout, evidence, true, err
}

func newAcornFoxLegacyHostProvisioner(legacy acornFoxInstallLayout) *acornFoxLegacyHostProvisioner {
	p := &acornFoxLegacyHostProvisioner{
		legacy: legacy, lookupUser: user.Lookup, lookupGroup: user.LookupGroup,
		run: func(ctx context.Context, path string, args ...string) error {
			command := exec.CommandContext(ctx, path, args...)
			command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
			command.Stdin, command.Stdout, command.Stderr = nil, io.Discard, io.Discard
			return command.Run()
		},
		chown: func(file *os.File, uid, gid int) error { return file.Chown(uid, gid) },
		observe: func(info os.FileInfo) (acornFoxInstallPrincipal, bool) {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return acornFoxInstallPrincipal{}, false
			}
			return acornFoxInstallPrincipal{uid: int(stat.Uid), gid: int(stat.Gid)}, true
		},
		fault: func(string) error { return nil },
	}
	p.unitAbsent = p.realUnitAbsent
	p.verifyHost = p.verifyLegacyHost
	return p
}

func (p *acornFoxLegacyHostProvisioner) realUnitAbsent(ctx context.Context) (bool, error) {
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "acornfox-pi-worker.service", "--property=LoadState", "--value")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	command.Stdin, command.Stderr = nil, io.Discard
	raw, err := command.Output()
	if err != nil {
		return false, ErrAcornFoxUpgradeUnknown
	}
	value := strings.TrimSpace(string(raw))
	if value == "not-found" {
		return true, nil
	}
	if value == "loaded" {
		return false, nil
	}
	return false, ErrAcornFoxUpgradeUnknown
}

func (p *acornFoxLegacyHostProvisioner) ensure(ctx context.Context, identity acornFoxLegacy0034Identity) (acornFoxInstallLayout, acornFoxLegacyHostProvisionEvidence, error) {
	if ctx == nil || ctx.Err() != nil || p == nil || p.legacy.validateLegacy0034() != nil || !p.legacy.legacy0034HostRootPinned() || identity.oldSHA256 == "" || !identity.candidate.valid() {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, ErrAcornFoxUpgradeConflict
	}
	state, err := os.OpenRoot(p.legacy.stateRootPath)
	if err != nil {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, ErrAcornFoxUpgradeUnknown
	}
	defer state.Close()
	lock, err := p.lock(state)
	if err != nil {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, err
	}
	defer lock.Close()
	journal, exists, err := p.loadJournal(state, identity)
	if err != nil {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, err
	}
	if !exists {
		if err := p.verifyHost(identity); err != nil {
			return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, err
		}
		if err := p.verifyStrictPIAbsence(ctx); err != nil {
			return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, err
		}
		candidateRaw, marshalErr := json.Marshal(identity.candidate.binding)
		if marshalErr != nil {
			return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, ErrAcornFoxUpgradeConflict
		}
		journal = acornFoxLegacyHostJournal{SchemaVersion: 1, Phase: "PREPARED", OldBindingSHA256: identity.oldSHA256, CandidateBindingSHA256: identity.candidate.digest, CandidateBinding: candidateRaw, OldLayoutSHA256: p.legacy.evidence()}
		if err := p.saveJournal(state, journal, identity); err != nil {
			return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, err
		}
		if err := p.fault("journal-prepared"); err != nil {
			return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, ErrAcornFoxUpgradeUnknown
		}
	}
	group, err := p.ensureGroup(ctx, journal.PIGID)
	if err != nil {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, err
	}
	if journal.PIGID == 0 {
		journal.PIGID, journal.Phase = group, "GROUP_CREATED"
		if err := p.saveJournal(state, journal, identity); err != nil {
			return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, err
		}
	}
	account, err := p.ensureAccount(ctx, journal.PIUID, group)
	if err != nil {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, err
	}
	if journal.PIUID == 0 {
		journal.PIUID, journal.Phase = account, "ACCOUNT_CREATED"
		if err := p.saveJournal(state, journal, identity); err != nil {
			return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, err
		}
	}
	principal := acornFoxInstallPrincipal{uid: account, gid: group}
	for journal.Directories < len(acornFoxLegacyPIDataDirectories) {
		path := acornFoxLegacyPIDataDirectories[journal.Directories]
		if err := p.ensureDirectory(path, principal); err != nil {
			return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, err
		}
		if err := p.fault("directory-created-" + strconv.Itoa(journal.Directories)); err != nil {
			return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, ErrAcornFoxUpgradeUnknown
		}
		journal.Directories++
		journal.Phase = "DIRECTORIES_CREATED"
		if err := p.saveJournal(state, journal, identity); err != nil {
			return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, err
		}
	}
	current, err := p.legacy.withProvisionedPI(principal)
	if err != nil {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, ErrAcornFoxUpgradeConflict
	}
	evidence := acornFoxLegacyHostProvisionEvidence{1, identity.oldSHA256, identity.candidate.digest, p.legacy.evidence(), current.evidence(), account, group, acornFoxLegacyPIDirectorySetSHA256()}
	evidenceDigest, err := evidence.digest(identity, p.legacy, current)
	if err != nil {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, err
	}
	if journal.Phase != "COMPLETE" {
		journal.Phase, journal.NewLayoutSHA256, journal.EvidenceSHA256 = "COMPLETE", current.evidence(), evidenceDigest
		if err := p.saveJournal(state, journal, identity); err != nil {
			return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, err
		}
	}
	if journal.NewLayoutSHA256 != current.evidence() || journal.EvidenceSHA256 != evidenceDigest {
		return acornFoxInstallLayout{}, acornFoxLegacyHostProvisionEvidence{}, ErrAcornFoxUpgradeConflict
	}
	return current, evidence, nil
}

type acornFoxLegacyHostLock struct{ file *os.File }

func (l *acornFoxLegacyHostLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func (p *acornFoxLegacyHostProvisioner) lock(root *os.Root) (*acornFoxLegacyHostLock, error) {
	// Lock the already-existing pinned state directory. This serializes the
	// preflight without creating any host entry before absence is proven.
	file, err := root.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrAcornFoxUpgradeUnknown
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || verifyOwner(info, p.legacy.stateOwner.uid, p.legacy.stateOwner.gid) != nil {
		file.Close()
		return nil, ErrAcornFoxUpgradeConflict
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, ErrAcornFoxUpgradeUnknown
	}
	current, statErr := root.Lstat(".")
	if statErr != nil || !os.SameFile(info, current) {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
		return nil, ErrAcornFoxUpgradeConflict
	}
	return &acornFoxLegacyHostLock{file: file}, nil
}

func (p *acornFoxLegacyHostProvisioner) verifyStrictPIAbsence(ctx context.Context) error {
	if _, err := p.lookupUser("acornfox-pi"); err == nil {
		return ErrAcornFoxUpgradeConflict
	} else if !unknownAcornFoxUser(err) {
		return ErrAcornFoxUpgradeUnknown
	}
	if _, err := p.lookupGroup("acornfox-pi"); err == nil {
		return ErrAcornFoxUpgradeConflict
	} else if !unknownAcornFoxGroup(err) {
		return ErrAcornFoxUpgradeUnknown
	}
	absent, err := p.unitAbsent(ctx)
	if err != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	if !absent {
		return ErrAcornFoxUpgradeConflict
	}
	root, err := os.OpenRoot(p.legacy.hostRootPath)
	if err != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	defer root.Close()
	for _, path := range []string{"etc/systemd/system/acornfox-pi-worker.service", "etc/systemd/system/multi-user.target.wants/acornfox-pi-worker.service", "etc/acornfox/pi", "var/lib/acornfox/pi", "run/acornfox-pi"} {
		if _, statErr := root.Lstat(path); statErr == nil {
			return ErrAcornFoxUpgradeConflict
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return ErrAcornFoxUpgradeUnknown
		}
	}
	if err := acornFoxLegacyPIEnableLinksAbsent(root); err != nil {
		return err
	}
	return nil
}

func acornFoxLegacyPIEnableLinksAbsent(root *os.Root) error {
	const systemdRoot = "etc/systemd/system"
	dir, err := root.OpenFile(systemdRoot, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	children, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil || closeErr != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	for _, child := range children {
		if !strings.HasSuffix(child.Name(), ".wants") && !strings.HasSuffix(child.Name(), ".requires") {
			continue
		}
		path := systemdRoot + "/" + child.Name()
		info, statErr := root.Lstat(path)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrAcornFoxUpgradeConflict
		}
		if _, statErr := root.Lstat(path + "/acornfox-pi-worker.service"); statErr == nil {
			return ErrAcornFoxUpgradeConflict
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return ErrAcornFoxUpgradeUnknown
		}
	}
	return nil
}

func unknownAcornFoxUser(err error) bool {
	var unknown user.UnknownUserError
	return errors.As(err, &unknown)
}

func unknownAcornFoxGroup(err error) bool {
	var unknown user.UnknownGroupError
	return errors.As(err, &unknown)
}

func (p *acornFoxLegacyHostProvisioner) ensureGroup(ctx context.Context, recorded int) (int, error) {
	group, err := p.lookupGroup("acornfox-pi")
	if unknownAcornFoxGroup(err) {
		if runErr := p.run(ctx, "/usr/sbin/groupadd", "--system", "acornfox-pi"); runErr != nil {
			return 0, ErrAcornFoxUpgradeUnknown
		}
		if faultErr := p.fault("group-created"); faultErr != nil {
			return 0, ErrAcornFoxUpgradeUnknown
		}
		group, err = p.lookupGroup("acornfox-pi")
	}
	if err != nil {
		return 0, ErrAcornFoxUpgradeUnknown
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil || group.Name != "acornfox-pi" || gid <= 0 || recorded != 0 && recorded != gid {
		return 0, ErrAcornFoxUpgradeConflict
	}
	return gid, nil
}

func (p *acornFoxLegacyHostProvisioner) ensureAccount(ctx context.Context, recorded, gid int) (int, error) {
	account, err := p.lookupUser("acornfox-pi")
	if unknownAcornFoxUser(err) {
		if runErr := p.run(ctx, "/usr/sbin/useradd", "--system", "--gid", "acornfox-pi", "--home-dir", "/var/lib/acornfox/pi", "--shell", "/usr/sbin/nologin", "--no-create-home", "acornfox-pi"); runErr != nil {
			return 0, ErrAcornFoxUpgradeUnknown
		}
		if faultErr := p.fault("account-created"); faultErr != nil {
			return 0, ErrAcornFoxUpgradeUnknown
		}
		account, err = p.lookupUser("acornfox-pi")
	}
	if err != nil {
		return 0, ErrAcornFoxUpgradeUnknown
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	accountGID, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil || account.Username != "acornfox-pi" || account.HomeDir != "/var/lib/acornfox/pi" || uid <= 0 || accountGID != gid || recorded != 0 && recorded != uid {
		return 0, ErrAcornFoxUpgradeConflict
	}
	for _, role := range acornFoxLegacy0034InstallLayoutRoles[1:] {
		if p.legacy.principals[role].uid == uid {
			return 0, ErrAcornFoxUpgradeConflict
		}
	}
	return uid, nil
}

func (p *acornFoxLegacyHostProvisioner) ensureDirectory(path string, principal acornFoxInstallPrincipal) error {
	root, err := os.OpenRoot(p.legacy.hostRootPath)
	if err != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	defer root.Close()
	info, err := root.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err = root.Mkdir(path, 0o700); err != nil {
			return ErrAcornFoxUpgradeUnknown
		}
		file, openErr := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return ErrAcornFoxUpgradeUnknown
		}
		err = p.chown(file, principal.uid, principal.gid)
		if err == nil {
			err = file.Chmod(0o700)
		}
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil || acornFoxLiveSyncDir(root, acornFoxUpgradeParent(path)) != nil {
			return ErrAcornFoxUpgradeUnknown
		}
		info, err = root.Lstat(path)
	}
	owner, observed := p.observe(info)
	if err != nil || !observed || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || owner != principal {
		return ErrAcornFoxUpgradeConflict
	}
	return nil
}

func (p *acornFoxLegacyHostProvisioner) loadJournal(root *os.Root, identity acornFoxLegacy0034Identity) (acornFoxLegacyHostJournal, bool, error) {
	info, err := root.Lstat(acornFoxLegacyHostJournalPath)
	if errors.Is(err, os.ErrNotExist) {
		return acornFoxLegacyHostJournal{}, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || acornFoxRepoNlink(info) != 1 || verifyOwner(info, p.legacy.stateOwner.uid, p.legacy.stateOwner.gid) != nil || info.Size() <= 0 || info.Size() > acornFoxLegacyHostJournalMax {
		return acornFoxLegacyHostJournal{}, false, ErrAcornFoxUpgradeConflict
	}
	file, err := root.OpenFile(acornFoxLegacyHostJournalPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return acornFoxLegacyHostJournal{}, false, ErrAcornFoxUpgradeUnknown
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, acornFoxLegacyHostJournalMax+1))
	opened, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || !os.SameFile(info, opened) || int64(len(raw)) != info.Size() {
		return acornFoxLegacyHostJournal{}, false, ErrAcornFoxUpgradeUnknown
	}
	var journal acornFoxLegacyHostJournal
	if strictCanonicalJSON(raw, &journal, "AcornFox legacy host journal") != nil || journal.validate(identity, p.legacy) != nil {
		return acornFoxLegacyHostJournal{}, false, ErrAcornFoxUpgradeConflict
	}
	return journal, true, nil
}

func (p *acornFoxLegacyHostProvisioner) saveJournal(root *os.Root, journal acornFoxLegacyHostJournal, identity acornFoxLegacy0034Identity) error {
	if journal.validate(identity, p.legacy) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	raw, err := json.Marshal(journal)
	if err != nil {
		return ErrAcornFoxUpgradeConflict
	}
	if temp, statErr := root.Lstat(acornFoxLegacyHostJournalTemp); statErr == nil {
		tempRaw, readErr := readAcornFoxLegacyEvidence(root, acornFoxLegacyHostJournalTemp, p.legacy.stateOwner, acornFoxLegacyHostJournalMax)
		var tempJournal acornFoxLegacyHostJournal
		if !temp.Mode().IsRegular() || temp.Mode().Perm() != 0o600 || acornFoxRepoNlink(temp) != 1 || verifyOwner(temp, p.legacy.stateOwner.uid, p.legacy.stateOwner.gid) != nil || readErr != nil || strictCanonicalJSON(tempRaw, &tempJournal, "AcornFox legacy host temporary journal") != nil || tempJournal.validate(identity, p.legacy) != nil || root.Remove(acornFoxLegacyHostJournalTemp) != nil {
			return ErrAcornFoxUpgradeConflict
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return ErrAcornFoxUpgradeUnknown
	}
	file, err := root.OpenFile(acornFoxLegacyHostJournalTemp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	writeErr := writeAcornFoxRepoAll(file, raw)
	if writeErr == nil {
		writeErr = file.Chmod(0o600)
	}
	if writeErr == nil {
		writeErr = file.Chown(p.legacy.stateOwner.uid, p.legacy.stateOwner.gid)
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || root.Rename(acornFoxLegacyHostJournalTemp, acornFoxLegacyHostJournalPath) != nil || acornFoxLiveSyncDir(root, ".") != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	return nil
}

func (p *acornFoxLegacyHostProvisioner) verifyLegacyHost(identity acornFoxLegacy0034Identity) error {
	state, err := os.OpenRoot(p.legacy.stateRootPath)
	if err != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	defer state.Close()
	substrateRaw, err := readAcornFoxLegacyEvidence(state, acornFoxSubstrateReceipt, p.legacy.stateOwner, acornFoxUpgradeMaxJournal)
	if err != nil {
		return err
	}
	substrate, err := parseAcornFoxLegacy0034SubstrateReceipt(substrateRaw, identity.old, identity.oldSHA256)
	if err != nil {
		return ErrAcornFoxUpgradeConflict
	}
	liveRaw, err := readAcornFoxLegacyEvidence(state, "live-receipt.json", p.legacy.stateOwner, acornFoxUpgradeMaxJournal)
	if err != nil {
		return err
	}
	var live AcornFoxLiveReceiptV1
	if strictCanonicalJSON(liveRaw, &live, "AcornFox legacy 0034 live receipt") != nil || validateAcornFoxLegacy0034LiveReceiptForLayout(p.legacy, substrate, identity.old, identity.oldSHA256, live) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	return p.verifyLegacyLiveEntries(live)
}

func readAcornFoxLegacyEvidence(root *os.Root, path string, principal acornFoxInstallPrincipal, limit int64) ([]byte, error) {
	info, err := root.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > limit || acornFoxRepoNlink(info) != 1 || verifyOwner(info, principal.uid, principal.gid) != nil {
		return nil, ErrAcornFoxUpgradeConflict
	}
	file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrAcornFoxUpgradeUnknown
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	opened, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || !os.SameFile(info, opened) || int64(len(raw)) != info.Size() {
		return nil, ErrAcornFoxUpgradeUnknown
	}
	return raw, nil
}

func (p *acornFoxLegacyHostProvisioner) verifyLegacyLiveEntries(live AcornFoxLiveReceiptV1) error {
	root, err := os.OpenRoot(p.legacy.hostRootPath)
	if err != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	defer root.Close()
	for _, entry := range live.Entries {
		info, statErr := root.Lstat(entry.Path)
		if statErr != nil {
			return ErrAcornFoxUpgradeConflict
		}
		principal, roleOK := p.legacy.owner(entry.Role)
		group, groupOK := p.legacy.owner(entry.Group)
		owner, observed := p.observe(info)
		if !roleOK || !groupOK || !observed || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != os.FileMode(entry.Mode) || owner.uid != principal.uid || owner.gid != group.gid || (entry.Kind == SubstrateEntryDirectory) != info.IsDir() {
			return ErrAcornFoxUpgradeConflict
		}
		if entry.Kind == SubstrateEntryDirectory {
			continue
		}
		if acornFoxRepoNlink(info) != 1 {
			return ErrAcornFoxUpgradeConflict
		}
		file, openErr := root.OpenFile(entry.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return ErrAcornFoxUpgradeUnknown
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, entry.Size+1))
		opened, openedErr := file.Stat()
		closeErr := file.Close()
		if readErr != nil || openedErr != nil || closeErr != nil || !os.SameFile(info, opened) || int64(len(raw)) != entry.Size || sha256Hex(raw) != entry.SHA256 {
			return ErrAcornFoxUpgradeConflict
		}
	}
	return nil
}
