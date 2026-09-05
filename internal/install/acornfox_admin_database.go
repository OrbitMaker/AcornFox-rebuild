package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"syscall"
)

// AcornFoxAdminDatabase holds the install lock throughout a local credential
// operation. Its DSN is deliberately excluded from serialized output.
type AcornFoxAdminDatabase struct {
	DatabaseURL         string `json:"-"`
	MigrationRowsSHA256 string
	adminSHA256         string
	store               *TaskAcornFoxRepoStore
}

func (d *AcornFoxAdminDatabase) Close() error {
	if d == nil || d.store == nil {
		return nil
	}
	s := d.store
	d.store = nil
	d.DatabaseURL = ""
	return s.Close()
}

// OpenAcornFoxAdminDatabase resolves only the installed AcornFox identity.
// Version and commit come from the release-stamped administrator executable.
func OpenAcornFoxAdminDatabase(ctx context.Context, version, commit string) (*AcornFoxAdminDatabase, error) {
	layout, err := newProductionAcornFoxLayout()
	if err != nil {
		return nil, ErrActiveDatabaseUnavailable
	}
	store, err := newAcornFoxRepoStoreForLayout(layout)
	if err != nil {
		return nil, ErrActiveDatabaseUnavailable
	}
	if _, err := store.Acquire(ctx); err != nil {
		store.Close()
		return nil, ErrActiveDatabaseUnavailable
	}
	database, err := resolveAcornFoxAdminDatabase(ctx, store, version, commit)
	if err != nil {
		store.Close()
		return nil, ErrActiveDatabaseUnavailable
	}
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		store.Close()
		return nil, ErrActiveDatabaseUnavailable
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (128<<20)+1))
	f.Close()
	if err != nil || n > 128<<20 || hex.EncodeToString(h.Sum(nil)) != database.adminSHA256 {
		store.Close()
		return nil, ErrActiveDatabaseUnavailable
	}
	database.store = store
	return database, nil
}

func resolveAcornFoxAdminDatabase(ctx context.Context, store *TaskAcornFoxRepoStore, version, commit string) (*AcornFoxAdminDatabase, error) {
	fail := func() (*AcornFoxAdminDatabase, error) { return nil, ErrActiveDatabaseUnavailable }
	if store == nil || !store.ownsLock() || store.layout.mode != acornFoxInstallLayoutProduction || !validID("release-"+version) || !acornFoxHostSourceCommit.MatchString(commit) {
		return fail()
	}
	j, err := store.Resume(ctx)
	if err != nil || j.Phase != AcornFoxRepoPreparedFinal || j.NeedsRecovery || j.LayoutSHA256 != store.layout.evidence() {
		return fail()
	}
	raw, err := newAcornFoxBindingStore(store).Read(j.BindingSHA256)
	if err != nil {
		return fail()
	}
	binding, err := ParseAcornFoxCandidateBindingV1(raw, j.BindingSHA256)
	if err != nil || binding.binding.ReleaseID != "release-"+version || binding.binding.SourceCommit != commit {
		return fail()
	}
	migrations, err := loadAcornFoxControlPlaneMigrations(store.layout, binding.binding)
	if err != nil {
		return fail()
	}
	id, err := AcornFoxRepoActivationID(j.BindingSHA256)
	if err != nil {
		return fail()
	}
	host, err := store.openHostRoot()
	if err != nil {
		return fail()
	}
	defer host.Close()
	state, err := store.openRoot()
	if err != nil {
		return fail()
	}
	defer state.Close()
	l := store.layout
	for _, name := range []string{"opt", "opt/acornfox", "opt/acornfox/activations", l.activationDir(id), "opt/acornfox/releases", "opt/acornfox/releases/" + binding.binding.ReleaseID} {
		info, e := host.Lstat(name)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || verifyOwner(info, store.uid, store.gid) != nil {
			return fail()
		}
	}
	read := func(root *os.Root, name string, mode os.FileMode) ([]byte, error) {
		f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			return nil, ErrActiveDatabaseUnavailable
		}
		defer f.Close()
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || acornFoxRepoNlink(info) != 1 || verifyOwner(info, store.uid, store.gid) != nil || info.Size() > 1<<20 {
			return nil, ErrActiveDatabaseUnavailable
		}
		b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if e != nil || len(b) > 1<<20 {
			return nil, ErrActiveDatabaseUnavailable
		}
		return b, nil
	}
	aRaw, err := read(host, l.activationReceiptPath(id), 0o600)
	if err != nil || sha256Bytes(aRaw) != j.ActivationSHA256 {
		return fail()
	}
	a, err := ParseAcornFoxRepoActivationV1(aRaw)
	if err != nil || a.Mode != "production_host" || a.ActivationID != id || a.BindingSHA256 != j.BindingSHA256 || a.TransactionID != j.TransactionID || a.LayoutSHA256 != l.evidence() || a.ReleaseID != binding.binding.ReleaseID {
		return fail()
	}
	env, err := read(host, l.activationDir(id)+"/database.env", 0o600)
	if err != nil || !validAcornFoxControlPlaneEnvironment(env) {
		return fail()
	}
	stateEnv, err := read(state, acornFoxControlPlaneStateEnv, 0o600)
	if err != nil || !bytes.Equal(env, stateEnv) {
		return fail()
	}
	rRaw, err := read(state, acornFoxControlPlaneReceipt, 0o600)
	if err != nil {
		return fail()
	}
	r, err := ParseAcornFoxControlPlaneMigrationReceiptV1(rRaw)
	if err != nil || r.BindingSHA256 != a.BindingSHA256 || r.ReleaseID != a.ReleaseID || r.SourceCommit != commit || r.DatabaseEnvSHA256 != sha256Bytes(env) || r.DatabaseIdentitySHA256 != acornFoxControlPlaneIdentitySHA256() || r.MigrationRowsSHA256 != acornFoxMigrationRowsSHA256(migrations.rows) {
		return fail()
	}
	for _, p := range []struct{ name, target string }{{l.activePath(), "activations/" + id}, {l.currentPath(), "active/release"}, {l.activationReleasePath(id), "../../releases/" + a.ReleaseID}} {
		if target, e := host.Readlink(p.name); e != nil || target != p.target {
			return fail()
		}
	}
	if !store.ownsLock() {
		return fail()
	}
	manifestRaw, err := read(host, "opt/acornfox/releases/"+a.ReleaseID+"/manifest.json", 0o644)
	if err != nil || sha256Bytes(manifestRaw) != binding.binding.ManifestSHA256 {
		return fail()
	}
	var manifest Manifest
	if json.Unmarshal(manifestRaw, &manifest) != nil {
		return fail()
	}
	adminSHA := ""
	for _, entry := range manifest.Files {
		if entry.Path == "bin/acornfox-admin" && entry.Mode == 0o755 {
			adminSHA = entry.SHA256
		}
	}
	if !validSHA(adminSHA) {
		return fail()
	}
	dsn, err := parseAcornFoxControlPlaneEnvironment(env)
	if err != nil {
		return fail()
	}
	return &AcornFoxAdminDatabase{DatabaseURL: dsn, MigrationRowsSHA256: r.MigrationRowsSHA256, adminSHA256: adminSHA}, nil
}
