package install

// Runtime configuration is a separate, intent-first transition after C1. This
// file does not start services, create accounts, or assert network isolation.
import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/acornfoxsetup"
)

var ErrAcornFoxRuntimeConfigConflict = errors.New("AcornFox runtime configuration conflicts with installed state")
var ErrAcornFoxRuntimeConfigUnknown = errors.New("AcornFox runtime configuration outcome is unknown")

const acornFoxRuntimeIntentName = "runtime-config-intent.json"
const acornFoxRuntimeReceiptName = "runtime-config.json"
const acornFoxRuntimeParent = "etc/acornfox"
const acornFoxRuntimeTarget = "etc/acornfox/runtime"
const acornFoxRuntimeMaxIntent = 1 << 20

type AcornFoxRuntimeConfigReceiptV1 struct {
	SchemaVersion int    `json:"schema_version"`
	State         string `json:"state"`
	BindingSHA256 string `json:"binding_sha256"`
	ReleaseID     string `json:"release_id"`
	SourceCommit  string `json:"source_commit"`
	IntentSHA256  string `json:"intent_sha256"`
}

func (r AcornFoxRuntimeConfigReceiptV1) Validate() error {
	if r.SchemaVersion != 1 || r.State != "RUNTIME_CONFIGURED" || !validSHA(r.BindingSHA256) || !validID(r.ReleaseID) || !acornFoxHostSourceCommit.MatchString(r.SourceCommit) || !validSHA(r.IntentSHA256) {
		return ErrAcornFoxRuntimeConfigConflict
	}
	return nil
}
func MarshalAcornFoxRuntimeConfigReceiptV1(r AcornFoxRuntimeConfigReceiptV1) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}
func ParseAcornFoxRuntimeConfigReceiptV1(raw []byte) (AcornFoxRuntimeConfigReceiptV1, error) {
	var r AcornFoxRuntimeConfigReceiptV1
	if strictCanonicalJSON(raw, &r, "runtime configuration receipt") != nil {
		return r, ErrAcornFoxRuntimeConfigConflict
	}
	return r, r.Validate()
}

// The only serializable private-key representation is this package-private
// wire type. Do not export it or include it in an error/receipt. fmt is redacted.
type acornFoxRuntimeFileWire struct {
	Path  string             `json:"path"`
	Mode  uint32             `json:"mode"`
	Owner acornfoxsetup.Role `json:"owner"`
	Group acornfoxsetup.Role `json:"group"`
	Data  []byte             `json:"data"`
}
type acornFoxRuntimeIntent struct {
	SchemaVersion int                       `json:"schema_version"`
	BindingSHA256 string                    `json:"binding_sha256"`
	ReleaseID     string                    `json:"release_id"`
	SourceCommit  string                    `json:"source_commit"`
	Inputs        acornfoxsetup.Inputs      `json:"inputs"`
	Files         []acornFoxRuntimeFileWire `json:"files"`
}

func (acornFoxRuntimeIntent) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "runtime intent [redacted]")
}
func (acornFoxRuntimeFileWire) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "runtime file [redacted]")
}
func (i acornFoxRuntimeIntent) bundle() acornfoxsetup.Bundle {
	b := acornfoxsetup.Bundle{}
	for _, f := range i.Files {
		b.Files = append(b.Files, acornfoxsetup.File{Path: f.Path, Mode: f.Mode, Owner: f.Owner, Group: f.Group, Data: f.Data})
	}
	return b
}
func (i acornFoxRuntimeIntent) validate() error {
	if i.SchemaVersion != 1 || !validSHA(i.BindingSHA256) || !validID(i.ReleaseID) || !acornFoxHostSourceCommit.MatchString(i.SourceCommit) || i.ReleaseID != "release-"+i.Inputs.Version || acornfoxsetup.Validate(i.bundle(), i.Inputs) != nil {
		return ErrAcornFoxRuntimeConfigConflict
	}
	return nil
}
func parseAcornFoxRuntimeIntent(raw []byte) (acornFoxRuntimeIntent, error) {
	var i acornFoxRuntimeIntent
	if len(raw) > acornFoxRuntimeMaxIntent || strictCanonicalJSON(raw, &i, "runtime intent") != nil || i.validate() != nil {
		return acornFoxRuntimeIntent{}, ErrAcornFoxRuntimeConfigConflict
	}
	return i, nil
}
func (i acornFoxRuntimeIntent) receipt(raw []byte) AcornFoxRuntimeConfigReceiptV1 {
	return AcornFoxRuntimeConfigReceiptV1{1, "RUNTIME_CONFIGURED", i.BindingSHA256, i.ReleaseID, i.SourceCommit, sha256Hex(raw)}
}
func acornFoxRuntimeTemporary(raw []byte) string {
	return acornFoxRuntimeParent + "/.runtime-" + sha256Hex(raw)[:32]
}

type acornFoxRuntimeConfig struct {
	layout       acornFoxInstallLayout
	ownership    acornFoxOwnershipEdge
	self         acornFoxSelfVerifier
	random       io.Reader
	now          func() time.Time
	step         func(string) error
	rename       func(*os.File, string, string) error
	syncMetadata func(*os.File) error
}

func newAcornFoxRuntimeConfig(layout acornFoxInstallLayout) *acornFoxRuntimeConfig {
	return &acornFoxRuntimeConfig{layout: layout, ownership: newAcornFoxRealOwnershipEdge(), self: newAcornFoxProductionSelfVerifier(), random: rand.Reader, now: time.Now, step: func(string) error { return nil }, rename: acornFoxRuntimeRenameNoReplace, syncMetadata: func(f *os.File) error { return f.Sync() }}
}

func ConfigureAcornFoxRuntimeV1(ctx context.Context, expected AcornFoxBuildIdentityV1, origin string, resolvers []string) (AcornFoxRuntimeConfigReceiptV1, error) {
	layout, err := newProductionAcornFoxLayout()
	if err != nil {
		return AcornFoxRuntimeConfigReceiptV1{}, ErrAcornFoxRuntimeConfigConflict
	}
	return newAcornFoxRuntimeConfig(layout).run(ctx, expected, origin, resolvers, false)
}
func RecoverAcornFoxRuntimeV1(ctx context.Context, expected AcornFoxBuildIdentityV1) error {
	layout, err := newProductionAcornFoxLayout()
	if err != nil {
		return ErrAcornFoxRuntimeConfigConflict
	}
	_, err = newAcornFoxRuntimeConfig(layout).run(ctx, expected, "", nil, true)
	return err
}

func (s *acornFoxRuntimeConfig) run(ctx context.Context, expected AcornFoxBuildIdentityV1, origin string, resolvers []string, recoverOnly bool) (AcornFoxRuntimeConfigReceiptV1, error) {
	empty := AcornFoxRuntimeConfigReceiptV1{}
	if s == nil || ctx == nil || ctx.Err() != nil || s.layout.mode != acornFoxInstallLayoutProduction || s.layout.validate() != nil || !validAcornFoxControlPlaneHelperIdentity(expected) || s.step == nil || s.rename == nil {
		return empty, ErrAcornFoxRuntimeConfigConflict
	}
	store, err := newAcornFoxRepoStoreForLayout(s.layout)
	if err != nil {
		return empty, ErrAcornFoxRuntimeConfigConflict
	}
	defer store.Close()
	store.ownership = s.ownership
	lock, err := store.Acquire(ctx)
	if err != nil {
		return empty, err
	}
	defer lock.Release()
	state, err := TaskDurableWriter(s.layout.stateRootPath, s.layout.stateOwner.uid, s.layout.stateOwner.gid)
	if err != nil {
		return empty, ErrAcornFoxRuntimeConfigConflict
	}
	defer state.Close()
	raw, err := acornFoxRuntimeReadState(store, acornFoxRuntimeIntentName)
	intentMissing := errors.Is(err, os.ErrNotExist)
	if recoverOnly && errors.Is(err, os.ErrNotExist) {
		if _, rerr := acornFoxRuntimeReadState(store, acornFoxRuntimeReceiptName); !errors.Is(rerr, os.ErrNotExist) {
			return empty, ErrAcornFoxRuntimeConfigConflict
		}
		return empty, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return empty, ErrAcornFoxRuntimeConfigConflict
	}
	a, identity, err := acornFoxRuntimeAuthority(ctx, store, store.hostRoot)
	if err != nil || identity != expected {
		return empty, ErrAcornFoxRuntimeConfigConflict
	}
	// Prove the actual installed executable and the executing helper against the
	// same release receipt, without invoking full-scope preparation recovery.
	if err = s.verifySelf(store, expected); err != nil {
		return empty, ErrAcornFoxRuntimeConfigConflict
	}
	if intentMissing {
		if recoverOnly || s.random == nil || s.now == nil {
			return empty, ErrAcornFoxRuntimeConfigConflict
		}
		if _, rerr := acornFoxRuntimeReadState(store, acornFoxRuntimeReceiptName); !errors.Is(rerr, os.ErrNotExist) {
			return empty, ErrAcornFoxRuntimeConfigConflict
		}
		if _, x := store.hostRoot.Lstat(acornFoxRuntimeTarget); !errors.Is(x, os.ErrNotExist) {
			return empty, ErrAcornFoxRuntimeConfigConflict
		}
		if err = acornFoxRuntimeCheckParent(store.hostRoot, store, ""); err != nil {
			return empty, err
		}
		input := acornfoxsetup.Inputs{Origin: origin, Version: expected.Version, ResolverEndpoints: append([]string(nil), resolvers...), Now: s.now()}
		bundle, gerr := acornfoxsetup.Generate(input, s.random)
		if gerr != nil {
			return empty, ErrAcornFoxRuntimeConfigConflict
		}
		intent := acornFoxRuntimeIntent{SchemaVersion: 1, BindingSHA256: a.BindingSHA256, ReleaseID: identity.ReleaseID, SourceCommit: identity.SourceCommit, Inputs: input}
		for _, f := range bundle.Files {
			intent.Files = append(intent.Files, acornFoxRuntimeFileWire{f.Path, f.Mode, f.Owner, f.Group, f.Data})
		}
		raw, err = json.Marshal(intent)
		if err != nil || len(raw) > acornFoxRuntimeMaxIntent {
			return empty, ErrAcornFoxRuntimeConfigConflict
		}
		if s.createMetadata(state, store, acornFoxRuntimeIntentName, raw) != nil {
			return empty, ErrAcornFoxRuntimeConfigUnknown
		}
		if s.step("intent") != nil {
			return empty, ErrAcornFoxRuntimeConfigUnknown
		}
	}
	intent, err := parseAcornFoxRuntimeIntent(raw)
	if err != nil || intent.BindingSHA256 != a.BindingSHA256 || intent.ReleaseID != identity.ReleaseID || intent.SourceCommit != identity.SourceCommit {
		return empty, ErrAcornFoxRuntimeConfigConflict
	}
	if !recoverOnly && (intent.Inputs.Origin != origin || !equalAcornFoxRuntimeResolvers(intent.Inputs.ResolverEndpoints, resolvers)) {
		return empty, ErrAcornFoxRuntimeConfigConflict
	}
	receipt := intent.receipt(raw)
	receiptRaw, rerr := acornFoxRuntimeReadState(store, acornFoxRuntimeReceiptName)
	complete := rerr == nil
	if rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		return empty, ErrAcornFoxRuntimeConfigConflict
	}
	if complete {
		got, perr := ParseAcornFoxRuntimeConfigReceiptV1(receiptRaw)
		if perr != nil || got != receipt {
			return empty, ErrAcornFoxRuntimeConfigConflict
		}
	}
	if _, err = acornFoxRuntimeInspect(store.hostRoot, store, intent, raw, complete); err != nil {
		return empty, err
	}
	if err = s.createMetadata(state, store, acornFoxRuntimeIntentName, raw); err != nil {
		return empty, err
	}
	if complete {
		if err = s.createMetadata(state, store, acornFoxRuntimeReceiptName, receiptRaw); err != nil {
			return empty, err
		}
		return receipt, nil
	}
	if err = s.publish(ctx, store, intent, raw); err != nil {
		return empty, err
	}
	if s.step("published") != nil {
		return empty, ErrAcornFoxRuntimeConfigUnknown
	}
	receiptRaw, err = MarshalAcornFoxRuntimeConfigReceiptV1(receipt)
	if err != nil || s.createMetadata(state, store, acornFoxRuntimeReceiptName, receiptRaw) != nil {
		return empty, ErrAcornFoxRuntimeConfigUnknown
	}
	if _, err = acornFoxRuntimeInspect(store.hostRoot, store, intent, raw, true); err != nil {
		return empty, err
	}
	return receipt, nil
}
func equalAcornFoxRuntimeResolvers(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Bounded reads validate the named inode and descriptor, including a single
// link. Errors never include raw JSON, environment or private-key bytes.
func acornFoxRuntimeReadState(store *TaskAcornFoxRepoStore, name string) ([]byte, error) {
	path, info, err := acornFoxRuntimeMetadataFile(store, name)
	if err != nil {
		return nil, err
	}
	f, err := store.root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	raw, err := io.ReadAll(io.LimitReader(f, acornFoxRuntimeMaxIntent+1))
	if err != nil || len(raw) > acornFoxRuntimeMaxIntent {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	return raw, nil
}

func acornFoxRuntimeAuthority(ctx context.Context, store *TaskAcornFoxRepoStore, root *os.Root) (AcornFoxRepoActivationV1, AcornFoxBuildIdentityV1, error) {
	bad := func() (AcornFoxRepoActivationV1, AcornFoxBuildIdentityV1, error) {
		return AcornFoxRepoActivationV1{}, AcornFoxBuildIdentityV1{}, ErrAcornFoxRuntimeConfigConflict
	}
	if root == nil || store == nil || !store.ownsLock() || store.layout.validate() != nil || !store.layout.hostRootPinned() {
		return bad()
	}
	host, err := root.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return bad()
	}
	hostInfo, statErr := host.Stat()
	closeErr := host.Close()
	if statErr != nil || closeErr != nil || !os.SameFile(hostInfo, store.layout.hostRootInfo) {
		return bad()
	}
	j, err := store.Resume(ctx)
	if err != nil || j.Phase != AcornFoxRepoPreparedFinal || j.NeedsRecovery || j.LayoutSHA256 != store.layout.evidence() {
		return bad()
	}
	bindingRaw, err := newAcornFoxBindingStore(store).Read(j.BindingSHA256)
	if err != nil {
		return bad()
	}
	binding, err := ParseAcornFoxCandidateBindingV1(bindingRaw, j.BindingSHA256)
	if err != nil {
		return bad()
	}
	id := AcornFoxBuildIdentityV1{1, AcornFoxV1Product, 1, "upgrade", binding.binding.Version, binding.binding.ReleaseID, binding.binding.SourceCommit}
	if id.Validate() != nil {
		return bad()
	}
	activationID, err := AcornFoxRepoActivationID(j.BindingSHA256)
	if err != nil {
		return bad()
	}
	principal, _ := store.layout.owner(AcornFoxLiveRootRole)
	raw, err := acornFoxRuntimeReadHost(root, store, store.layout.activationReceiptPath(activationID), 0600, acornFoxRuntimeMaxIntent)
	if err != nil {
		return bad()
	}
	a, err := ParseAcornFoxRepoActivationV1(raw)
	if err != nil || sha256Hex(raw) != j.ActivationSHA256 || a.Mode != "production_host" || a.TransactionID != j.TransactionID || a.BindingSHA256 != j.BindingSHA256 || a.ReleaseID != id.ReleaseID || a.LayoutSHA256 != j.LayoutSHA256 || a.SubstrateReceiptSHA256 != j.SubstrateReceiptSHA256 || a.LiveTreeSHA256 != j.LiveTreeSHA256 || a.StaticSetSHA256 != j.StaticSetSHA256 || a.OwnershipPlanSHA256 != j.OwnershipPlanSHA256 {
		return bad()
	}
	for path, target := range map[string]string{store.layout.currentPath(): "active/release", store.layout.activePath(): "activations/" + a.ActivationID, store.layout.activationReleasePath(a.ActivationID): "../../releases/" + a.ReleaseID} {
		if !acornFoxRepoPointerForLayout(root, store, store.layout, path, target, false) {
			return bad()
		}
	}
	for _, path := range []string{"opt", "opt/acornfox", "opt/acornfox/activations", store.layout.activationDir(a.ActivationID), "opt/acornfox/releases", "opt/acornfox/releases/" + a.ReleaseID} {
		info, e := root.Lstat(path)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || !acornFoxLiveObservedOwner(store, info, principal) {
			return bad()
		}
	}
	cpRaw, err := acornFoxRuntimeReadState(store, acornFoxControlPlaneReceipt)
	if err != nil {
		return bad()
	}
	cp, err := ParseAcornFoxControlPlaneMigrationReceiptV1(cpRaw)
	if err != nil || cp.BindingSHA256 != j.BindingSHA256 || cp.ReleaseID != id.ReleaseID || cp.SourceCommit != id.SourceCommit || cp.DatabaseIdentitySHA256 != acornFoxControlPlaneIdentitySHA256() {
		return bad()
	}
	migrations, err := loadAcornFoxControlPlaneMigrations(store.layout, binding.binding)
	if err != nil || cp.MigrationRowsSHA256 != acornFoxMigrationRowsSHA256(migrations.rows) {
		return bad()
	}
	env, err := acornFoxRuntimeReadState(store, acornFoxControlPlaneStateEnv)
	if err != nil || !validAcornFoxControlPlaneEnvironment(env) || sha256Hex(env) != cp.DatabaseEnvSHA256 {
		return bad()
	}
	hostEnv, err := acornFoxRuntimeReadHost(root, store, store.layout.activationDir(a.ActivationID)+"/database.env", 0600, 16384)
	if err != nil || !bytes.Equal(env, hostEnv) {
		return bad()
	}
	return a, id, nil
}
func (s *acornFoxRuntimeConfig) verifySelf(store *TaskAcornFoxRepoStore, expected AcornFoxBuildIdentityV1) error {
	receipt, err := store.root.OpenFile("releases/"+expected.ReleaseID+".json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrAcornFoxRuntimeConfigConflict
	}
	defer receipt.Close()
	self, _, err := s.self.openPinnedSelf()
	if err != nil {
		return ErrAcornFoxRuntimeConfigConflict
	}
	defer self.Close()
	result := verifyAcornFoxHelperOpenedFiles(expected, receipt, self, store.uid, store.gid)
	if !result.OK {
		return ErrAcornFoxRuntimeConfigConflict
	}
	j, err := store.Resume(context.Background())
	if err != nil || result.BindingSHA256 != j.BindingSHA256 || result.SubstrateReceiptSHA256 != j.SubstrateReceiptSHA256 {
		return ErrAcornFoxRuntimeConfigConflict
	}
	installed, err := acornFoxRuntimeReadHost(store.hostRoot, store, AcornFoxUpgradeHelperPath, 0755, acornFoxHelperExecutableMaxBytes)
	if err != nil || sha256Hex(installed) != result.ExecutableSHA256 {
		return ErrAcornFoxRuntimeConfigConflict
	}
	return nil
}
func acornFoxRuntimeReadHost(root *os.Root, store *TaskAcornFoxRepoStore, path string, mode os.FileMode, max int) ([]byte, error) {
	info, err := root.Lstat(path)
	p, _ := store.layout.owner(AcornFoxLiveRootRole)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || acornFoxRepoNlink(info) != 1 || info.Size() > int64(max) || !acornFoxLiveObservedOwner(store, info, p) {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	f, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil || len(raw) > max {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	return raw, nil
}

// Scope is read-only and never authorizes arbitrary descendants. The caller
// already owns the repository lock. No intent means no dynamic scope entries.
func acornFoxRuntimeConfigScope(root *os.Root, store *TaskAcornFoxRepoStore, activation AcornFoxRepoActivationV1) ([]SubstrateEntry, error) {
	if root == nil || store == nil {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	raw, err := acornFoxRuntimeReadState(store, acornFoxRuntimeIntentName)
	if errors.Is(err, os.ErrNotExist) {
		if _, e := acornFoxRuntimeReadState(store, acornFoxRuntimeReceiptName); !errors.Is(e, os.ErrNotExist) {
			return nil, ErrAcornFoxRuntimeConfigConflict
		}
		return nil, nil
	}
	if err != nil {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	i, err := parseAcornFoxRuntimeIntent(raw)
	if err != nil {
		return nil, err
	}
	actual, identity, err := acornFoxRuntimeAuthority(context.Background(), store, root)
	if err != nil || actual != activation || i.BindingSHA256 != actual.BindingSHA256 || i.ReleaseID != identity.ReleaseID || i.SourceCommit != identity.SourceCommit {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	rraw, rerr := acornFoxRuntimeReadState(store, acornFoxRuntimeReceiptName)
	done := rerr == nil
	if rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	if done {
		r, e := ParseAcornFoxRuntimeConfigReceiptV1(rraw)
		if e != nil || r != i.receipt(raw) {
			return nil, ErrAcornFoxRuntimeConfigConflict
		}
	}
	return acornFoxRuntimeInspect(root, store, i, raw, done)
}

func acornFoxRuntimeCheckParent(root *os.Root, store *TaskAcornFoxRepoStore, temp string) error {
	p, _ := store.layout.owner(AcornFoxLiveRootRole)
	for _, path := range []string{"etc", acornFoxRuntimeParent} {
		info, err := root.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || !acornFoxLiveObservedOwner(store, info, p) {
			return ErrAcornFoxRuntimeConfigConflict
		}
	}
	dir, err := root.OpenFile(acornFoxRuntimeParent, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrAcornFoxRuntimeConfigConflict
	}
	defer dir.Close()
	children, err := dir.ReadDir(-1)
	if err != nil {
		return ErrAcornFoxRuntimeConfigConflict
	}
	for _, child := range children {
		if strings.HasPrefix(child.Name(), ".runtime-") && acornFoxRuntimeParent+"/"+child.Name() != temp {
			return ErrAcornFoxRuntimeConfigConflict
		}
	}
	return nil
}

func acornFoxRuntimeInspect(root *os.Root, store *TaskAcornFoxRepoStore, i acornFoxRuntimeIntent, raw []byte, done bool) ([]SubstrateEntry, error) {
	temp := acornFoxRuntimeTemporary(raw)
	if err := acornFoxRuntimeCheckParent(root, store, temp); err != nil {
		return nil, err
	}
	_, ferr := root.Lstat(acornFoxRuntimeTarget)
	_, terr := root.Lstat(temp)
	final := ferr == nil
	temporary := terr == nil
	if ferr != nil && !errors.Is(ferr, os.ErrNotExist) || terr != nil && !errors.Is(terr, os.ErrNotExist) || final && temporary || done && !final {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	if final {
		return acornFoxRuntimeInspectDirectory(root, store, acornFoxRuntimeTarget, i, true)
	}
	if temporary {
		return acornFoxRuntimeInspectDirectory(root, store, temp, i, false)
	}
	return nil, nil
}
func acornFoxRuntimeInspectDirectory(root *os.Root, store *TaskAcornFoxRepoStore, path string, i acornFoxRuntimeIntent, final bool) ([]SubstrateEntry, error) {
	p, _ := store.layout.owner(AcornFoxLiveRootRole)
	info, err := root.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !acornFoxLiveObservedOwner(store, info, p) || (info.Mode().Perm() != 0700 && info.Mode().Perm() != 0755) || final && info.Mode().Perm() != 0755 {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	dir, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	defer dir.Close()
	opened, err := dir.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	children, err := dir.ReadDir(-1)
	if err != nil {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	entries := []SubstrateEntry{{Path: path, Kind: SubstrateEntryDirectory, Mode: uint32(info.Mode().Perm()), Role: OwnerRoleRoot, Group: GroupRoleRoot}}
	if len(children) > 7 || (final || info.Mode().Perm() == 0755) && len(children) != 7 {
		return nil, ErrAcornFoxRuntimeConfigConflict
	}
	for _, child := range children {
		var want *acornFoxRuntimeFileWire
		for idx := range i.Files {
			if filepath.Base(i.Files[idx].Path) == child.Name() {
				want = &i.Files[idx]
				break
			}
		}
		if want == nil {
			return nil, ErrAcornFoxRuntimeConfigConflict
		}
		fpath := path + "/" + child.Name()
		finfo, err := root.Lstat(fpath)
		if err != nil {
			return nil, ErrAcornFoxRuntimeConfigConflict
		}
		mode := finfo.Mode().Perm()
		if mode != os.FileMode(want.Mode) && (final || info.Mode().Perm() == 0755 || mode != 0600) {
			return nil, ErrAcornFoxRuntimeConfigConflict
		}
		got, err := acornFoxRuntimeReadHost(root, store, fpath, mode, len(want.Data))
		if err != nil || !bytes.HasPrefix(want.Data, got) || (final || info.Mode().Perm() == 0755 || mode != 0600) && !bytes.Equal(got, want.Data) {
			return nil, ErrAcornFoxRuntimeConfigConflict
		}
		entries = append(entries, SubstrateEntry{Path: fpath, Kind: SubstrateEntryFile, Mode: uint32(mode), Role: OwnerRoleRoot, Group: GroupRoleRoot, Size: int64(len(got)), SHA256: sha256Hex(got)})
	}
	return entries, nil
}

func (s *acornFoxRuntimeConfig) publish(ctx context.Context, store *TaskAcornFoxRepoStore, i acornFoxRuntimeIntent, raw []byte) error {
	root := store.hostRoot
	temp := acornFoxRuntimeTemporary(raw)
	p, _ := store.layout.owner(AcornFoxLiveRootRole)
	if _, err := root.Lstat(acornFoxRuntimeTarget); err == nil {
		return nil
	}
	if _, err := root.Lstat(temp); errors.Is(err, os.ErrNotExist) {
		if root.Mkdir(temp, 0700) != nil {
			return ErrAcornFoxRuntimeConfigUnknown
		}
		d, err := root.OpenFile(temp, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return ErrAcornFoxRuntimeConfigUnknown
		}
		err = acornFoxLiveApplyOwner(store, d, p)
		if err == nil {
			err = d.Sync()
		}
		d.Close()
		if err != nil || acornFoxLiveSyncDir(root, acornFoxRuntimeParent) != nil {
			return ErrAcornFoxRuntimeConfigUnknown
		}
	}
	for _, f := range i.Files {
		if ctx.Err() != nil {
			return ErrAcornFoxRuntimeConfigUnknown
		}
		path := temp + "/" + filepath.Base(f.Path)
		info, err := root.Lstat(path)
		flags := os.O_RDWR | syscall.O_NOFOLLOW
		if errors.Is(err, os.ErrNotExist) {
			flags |= os.O_CREATE | os.O_EXCL
		} else if err != nil {
			return ErrAcornFoxRuntimeConfigConflict
		}
		out, err := root.OpenFile(path, flags, 0600)
		if err != nil {
			return ErrAcornFoxRuntimeConfigUnknown
		}
		opened, err := out.Stat()
		if err != nil || info != nil && !os.SameFile(info, opened) {
			out.Close()
			return ErrAcornFoxRuntimeConfigConflict
		}
		if info == nil {
			if err = acornFoxLiveApplyOwner(store, out, p); err != nil {
				out.Close()
				return ErrAcornFoxRuntimeConfigUnknown
			}
		}
		existing, err := io.ReadAll(io.LimitReader(out, int64(len(f.Data))+1))
		if err != nil || !bytes.HasPrefix(f.Data, existing) {
			out.Close()
			return ErrAcornFoxRuntimeConfigConflict
		}
		if len(existing) < len(f.Data) {
			rest := f.Data[len(existing):]
			mid := len(rest) / 2
			if _, err = out.Write(rest[:mid]); err == nil {
				err = out.Sync()
			}
			if err == nil {
				err = s.step("file-prefix")
			}
			if err != nil {
				out.Close()
				return ErrAcornFoxRuntimeConfigUnknown
			}
			if _, err = out.Write(rest[mid:]); err != nil {
				out.Close()
				return ErrAcornFoxRuntimeConfigUnknown
			}
		}
		if err = out.Sync(); err == nil {
			err = out.Chmod(os.FileMode(f.Mode))
		}
		if err == nil {
			err = out.Sync()
		}
		closeErr := out.Close()
		if err != nil || closeErr != nil {
			return ErrAcornFoxRuntimeConfigUnknown
		}
		if acornFoxLiveSyncDir(root, temp) != nil || s.step("file") != nil {
			return ErrAcornFoxRuntimeConfigUnknown
		}
	}
	if _, err := acornFoxRuntimeInspectDirectory(root, store, temp, i, false); err != nil {
		return err
	}
	d, err := root.OpenFile(temp, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrAcornFoxRuntimeConfigUnknown
	}
	err = d.Chmod(0755)
	if err == nil {
		err = d.Sync()
	}
	d.Close()
	if err != nil {
		return ErrAcornFoxRuntimeConfigUnknown
	}
	if s.step("directory-ready") != nil {
		return ErrAcornFoxRuntimeConfigUnknown
	}
	if _, err = acornFoxRuntimeInspectDirectory(root, store, temp, i, true); err != nil {
		return err
	}
	parent, err := root.OpenFile(acornFoxRuntimeParent, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrAcornFoxRuntimeConfigUnknown
	}
	defer parent.Close()
	if err = s.rename(parent, filepath.Base(temp), "runtime"); err != nil {
		return ErrAcornFoxRuntimeConfigConflict
	}
	if parent.Sync() != nil {
		return ErrAcornFoxRuntimeConfigUnknown
	}
	return nil
}
