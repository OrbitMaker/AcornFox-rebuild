//go:build linux

package desktopupdateguest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/desktopupdate"
	"github.com/open-card/open-card/internal/install"
)

var macID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var windowsID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func jsonMarker(raw []byte, v any) error {
	// Marker formatting belongs to the original installer. Preserve those bytes
	// and reject duplicate fields without requiring our own canonical encoding.
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[strings.ToLower(s)] {
					return ErrConflict
				}
				seen[strings.ToLower(s)] = true
				if e := walk(); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		case json.Delim('['):
			for d.More() {
				if e := walk(); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if walk() != nil {
		return ErrConflict
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrConflict
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrConflict
	}
	return nil
}
func indexPayloadSHA(envelope []byte) (string, error) {
	var e desktopupdate.IndexEnvelope
	if json.Unmarshal(envelope, &e) != nil {
		return "", ErrConflict
	}
	raw, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return "", ErrConflict
	}
	return digest(raw), nil
}
func currentProcess() (processIdentity, error) {
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return processIdentity{}, e
	}
	start, e := processStart(os.Getpid())
	if e != nil {
		return processIdentity{}, e
	}
	group, e := syscall.Getpgid(0)
	return processIdentity{os.Getpid(), group, strings.TrimSpace(string(boot)), start}, e
}
func processStart(pid int) (string, error) {
	raw, e := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if e != nil {
		return "", e
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return "", ErrConflict
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return "", ErrConflict
	}
	if fields[0] == "Z" {
		return "", os.ErrNotExist
	}
	return fields[19], nil
}
func processAlive(p processIdentity) bool {
	if p.PID < 1 || p.Start == "" || p.Boot == "" {
		return false
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil || strings.TrimSpace(string(boot)) != p.Boot {
		return false
	}
	start, e := processStart(p.PID)
	if e == nil {
		return start == p.Start
	}
	// Detached successor helpers inherit the worker session. If the worker dies
	// first, the live child group still forbids starting recovery concurrently.
	return p.Group == p.PID && syscall.Kill(-p.Group, 0) == nil
}

func extractCandidate(b *desktopupdate.VerifiedHostBundle, dir string) error {
	candidate := filepath.Join(dir, "candidate")
	if e := os.Mkdir(candidate, 0700); e != nil {
		return e
	}
	m := b.Manifest()
	archive := ""
	count := 0
	for _, entry := range m.Files {
		if !strings.HasPrefix(entry.Path, "backend/candidate/") {
			continue
		}
		if entry.Mode != 0644 {
			return ErrConflict
		}
		name := strings.TrimPrefix(entry.Path, "backend/candidate/")
		if name != path.Base(name) {
			return ErrConflict
		}
		count++
		f, e := os.OpenFile(filepath.Join(candidate, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if e != nil {
			return e
		}
		e = b.ReadFile(entry.Path, f)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		if strings.HasSuffix(name, "-production.tar.gz") {
			archive = filepath.Join(candidate, name)
		}
	}
	if count != 6 || archive == "" {
		return ErrConflict
	}
	if e := extractHelper(archive, filepath.Join(dir, "successor"), m.Backend.HelperSHA256); e != nil {
		return e
	}
	return syncDir(candidate)
}
func extractHelper(archive, output, want string) error {
	f, e := os.Open(archive)
	if e != nil {
		return e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, 4<<30))
	found := false
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return ErrConflict
		}
		if h.Name != "release/bin/acornfox-upgrade" {
			continue
		}
		if found || h.Typeflag != tar.TypeReg || h.Mode != 0755 || h.Size < 1 || h.Size > 256<<20 || len(h.PAXRecords) > 0 || h.Linkname != "" {
			return ErrConflict
		}
		found = true
		out, e := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
		if e != nil {
			return e
		}
		hash := sha256.New()
		n, e := io.Copy(io.MultiWriter(out, hash), tr)
		if e == nil {
			e = out.Sync()
		}
		ce := out.Close()
		if e != nil || ce != nil || n != h.Size || hex.EncodeToString(hash.Sum(nil)) != want {
			return ErrConflict
		}
	}
	if !found {
		return ErrConflict
	}
	return nil
}
func verifyExtracted(x *Executor, b *desktopupdate.VerifiedHostBundle, dir string) error {
	expected := map[string]bool{}
	for _, entry := range b.Manifest().Files {
		if !strings.HasPrefix(entry.Path, "backend/candidate/") {
			continue
		}
		name := path.Base(entry.Path)
		expected[name] = true
		f, e := openSafe(x.paths.anchor, filepath.Join(dir, "candidate", name), 0644)
		if e != nil {
			return e
		}
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(f, entry.Size+1))
		f.Close()
		if e != nil || n != entry.Size || hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
			return ErrConflict
		}
	}
	entries, e := os.ReadDir(filepath.Join(dir, "candidate"))
	if e != nil || len(entries) != len(expected) {
		return ErrConflict
	}
	for _, entry := range entries {
		if !expected[entry.Name()] {
			return ErrConflict
		}
	}
	f, e := openSafe(x.paths.anchor, filepath.Join(dir, "successor"), 0755)
	if e != nil {
		return e
	}
	defer f.Close()
	h := sha256.New()
	if _, e := io.Copy(h, io.LimitReader(f, 256<<20+1)); e != nil {
		return e
	}
	if hex.EncodeToString(h.Sum(nil)) != b.Manifest().Backend.HelperSHA256 {
		return ErrConflict
	}
	return nil
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > 65536-b.Len() {
		return 0, ErrConflict
	}
	return b.Buffer.Write(p)
}
func (x *Executor) helper(ctx context.Context, helper, expected string, args ...string) ([]byte, error) {
	f, e := openSafe(x.paths.anchor, helper, 0755)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	if expected != "" {
		h := sha256.New()
		if _, e := io.Copy(h, io.LimitReader(f, 256<<20+1)); e != nil {
			return nil, e
		}
		if hex.EncodeToString(h.Sum(nil)) != expected {
			return nil, ErrConflict
		}
	}
	// Execute the verified open file, so a path replacement cannot change code.
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	var out boundedOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	e = cmd.Run()
	return out.Bytes(), e
}

type productionBackend struct{ x *Executor }

func (p productionBackend) Observe(ctx context.Context) (desktopupdate.BackendObservation, error) {
	if e := p.x.verifyInstance(); e != nil {
		return desktopupdate.BackendObservation{}, e
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	raw, e := p.x.helper(ctx, "/"+install.AcornFoxUpgradeHelperPath, "", "contract-check", "--product", "acornfox", "--layout-schema", "1")
	if e != nil {
		return desktopupdate.BackendObservation{}, ErrConflict
	}
	contract, e := install.ParseAcornFoxHelperContractResultV1(bytes.TrimSpace(raw))
	if e != nil || !contract.OK || contract.Identity.Role != "upgrade" {
		return desktopupdate.BackendObservation{}, ErrConflict
	}
	obs := desktopupdate.BackendObservation{InstanceID: p.x.instance.InstanceID, Architecture: p.x.policy.HostArch, Binding: contract.BindingSHA256}
	raw, e = readSafe("/", "/var/lib/acornfox/install/runtime-config.json", 0600, 1<<20)
	if e != nil {
		return obs, ErrConflict
	}
	config, e := install.ParseAcornFoxRuntimeConfigReceiptV1(raw)
	if e != nil || config.BindingSHA256 != obs.Binding || config.ReleaseID != contract.Identity.ReleaseID || config.SourceCommit != contract.Identity.SourceCommit {
		return obs, ErrConflict
	}
	// This private intent contains secrets: only decode its non-secret origin in
	// memory, and never put raw bytes or command stderr into an error or receipt.
	raw, e = readSafe("/", "/var/lib/acornfox/install/runtime-config-intent.json", 0600, 1<<20)
	if e != nil || digest(raw) != config.IntentSHA256 {
		return obs, ErrConflict
	}
	var intent struct {
		Inputs struct {
			Origin string `json:"origin"`
		} `json:"inputs"`
	}
	if json.Unmarshal(raw, &intent) != nil {
		return obs, ErrConflict
	}
	obs.LocalLoopback = intent.Inputs.Origin == "http://127.0.0.1:8080"
	if !obs.LocalLoopback {
		return obs, ErrConflict
	}
	prepared, e := install.VerifyPreparedAcornFoxHostV1(ctx)
	if e != nil || prepared.Validate() != nil || prepared.BindingSHA256 != obs.Binding || prepared.ReleaseID != contract.Identity.ReleaseID || prepared.SourceCommit != contract.Identity.SourceCommit {
		return obs, ErrConflict
	}
	substrateRaw, e := readSafe("/", "/var/lib/acornfox/install/releases/"+contract.Identity.ReleaseID+".json", 0600, 1<<20)
	if e != nil || digest(substrateRaw) != contract.SubstrateReceiptSHA256 {
		return obs, ErrConflict
	}
	substrate, e := install.ParseInactiveSubstrateReceiptV1(substrateRaw)
	if e != nil {
		return obs, ErrConflict
	}
	obs.Architecture = substrate.CandidateReceipt.Architecture
	bindingRaw, e := readSafe("/", "/var/lib/acornfox/install/bindings/"+obs.Binding+".json", 0600, 2<<20)
	if e != nil {
		return obs, ErrConflict
	}
	binding, e := install.ParseAcornFoxCandidateBindingV1(bindingRaw, obs.Binding)
	if e != nil {
		return obs, ErrConflict
	}
	_ = binding
	var metadata struct {
		Migration string `json:"migration_version"`
	}
	if json.Unmarshal(bindingRaw, &metadata) != nil {
		return obs, ErrConflict
	}
	obs.MigrationVersion = metadata.Migration
	if _, e := os.Lstat("/var/lib/acornfox/upgrade-in-progress"); !errors.Is(e, os.ErrNotExist) {
		return obs, ErrBusy
	}
	entries, e := os.ReadDir("/var/lib/acornfox/install")
	if e != nil {
		return obs, ErrConflict
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".acornfox-local-") {
			return obs, ErrBusy
		}
	}
	raw, e = readSafe("/", "/var/lib/acornfox/install/upgrade/journal.json", 0600, 8<<20)
	if e == nil {
		var journal struct {
			Phase string          `json:"phase"`
			Local json.RawMessage `json:"local_rollover"`
		}
		if json.Unmarshal(raw, &journal) != nil || (journal.Phase != "UPGRADED" && journal.Phase != "ROLLED_BACK") || (len(journal.Local) > 0 && string(journal.Local) != "null") {
			return obs, ErrBusy
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return obs, ErrConflict
	}
	obs.Finalized = true
	obs.Ready = install.VerifyAcornFoxLocalReadyV1(ctx) == nil
	return obs, nil
}
func (p productionBackend) Upgrade(ctx context.Context, dir, sha string, i desktopupdate.HostUpgradeIntent) error {
	raw, e := p.x.helper(ctx, filepath.Join(dir, "successor"), sha, "repository-upgrade", "--candidate-dir", filepath.Join(dir, "candidate"), "--binding-sha256", i.ToBinding, "--current-binding-sha256", i.FromBinding, "--self-sha256", sha)
	var result struct {
		OK      bool                             `json:"ok"`
		Code    string                           `json:"code"`
		Command string                           `json:"command"`
		Receipt install.AcornFoxUpgradeReceiptV1 `json:"receipt"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Receipt.Validate() != nil {
		return ErrBusy
	}
	if e == nil && result.OK && result.Command == "repository-upgrade" && result.Receipt.State == "UPGRADED" && result.Receipt.BindingSHA256 == i.ToBinding && result.Receipt.PreviousBindingSHA256 == i.FromBinding {
		return nil
	}
	if result.Code == "upgrade_rolled_back" && result.Receipt.State == "ROLLED_BACK" && result.Receipt.BindingSHA256 == i.FromBinding {
		return install.ErrAcornFoxUpgradeRolledBack
	}
	return ErrBusy
}
func (p productionBackend) Recover(ctx context.Context) error {
	for _, verb := range []string{"recover-prepare", "recover-finalize"} {
		raw, e := p.x.helper(ctx, "/"+install.AcornFoxUpgradeHelperPath, "", verb, "--pending")
		if e != nil {
			return ErrBusy
		}
		var r struct {
			OK      bool            `json:"ok"`
			Command string          `json:"command"`
			Receipt json.RawMessage `json:"receipt"`
		}
		if json.Unmarshal(raw, &r) != nil || !r.OK || r.Command != verb {
			return ErrBusy
		}
		var upgraded install.AcornFoxUpgradeReceiptV1
		if json.Unmarshal(r.Receipt, &upgraded) == nil && upgraded.Validate() == nil {
			continue
		}
		if _, e := install.ParseAcornFoxHostBootstrapReceiptV1(r.Receipt); e != nil {
			return ErrBusy
		}
	}
	return nil
}
