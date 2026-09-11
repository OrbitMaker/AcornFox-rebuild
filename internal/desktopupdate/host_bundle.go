package desktopupdate

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

var ErrHostConflict = errors.New("desktopupdate: host update state or artifact conflicts")

const maxHostExpanded = int64(4 << 30)
const maxHostManifest = 2 << 20

type HostBundleFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   int64  `json:"mode"`
}
type HostBackendPlan struct {
	Mode         string `json:"mode"`
	FromBinding  string `json:"from_binding"`
	ToBinding    string `json:"to_binding"`
	Architecture string `json:"architecture"`
	HelperSHA256 string `json:"helper_sha256,omitempty"`
	APIProtocol  int    `json:"api_protocol"`
}
type HostBundleManifest struct {
	SchemaVersion      int              `json:"schema_version"`
	Product            string           `json:"product"`
	Kind               string           `json:"kind"`
	OS                 string           `json:"os"`
	Architecture       string           `json:"arch"`
	Version            string           `json:"version"`
	ControllerProtocol int              `json:"controller_protocol"`
	InstanceProtocol   int              `json:"instance_protocol"`
	Launcher           string           `json:"launcher"`
	Controller         string           `json:"controller"`
	Backend            HostBackendPlan  `json:"backend"`
	Files              []HostBundleFile `json:"files"`
}

// VerifiedHostBundle can only be constructed by full signature/payload/inventory
// verification. It carries no caller-controlled executable or deletion path.
type VerifiedHostBundle struct {
	envelope    []byte
	manifest    HostBundleManifest
	artifact    Artifact
	payload     *os.File
	payloadPath string
	manifestSHA string
}

func (b *VerifiedHostBundle) Manifest() HostBundleManifest {
	m := b.manifest
	m.Files = append([]HostBundleFile(nil), m.Files...)
	return m
}
func (b *VerifiedHostBundle) SHA256() string { return b.artifact.SHA256 }
func (b *VerifiedHostBundle) Close() error   { return b.payload.Close() }

// ReadFile rechecks the pinned whole payload before exposing a signed member.
// Callers stream potentially large files; this does not extract or execute them.
func (b *VerifiedHostBundle) ReadFile(name string, out io.Writer) error {
	var wanted *HostBundleFile
	for i := range b.manifest.Files {
		if b.manifest.Files[i].Path == name {
			wanted = &b.manifest.Files[i]
			break
		}
	}
	if wanted == nil || verifyHostPayload(b.payload, b.payloadPath, b.artifact) != nil {
		return ErrHostConflict
	}
	gz, err := gzip.NewReader(io.NewSectionReader(b.payload, 0, b.artifact.Size))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			return ErrHostConflict
		}
		if h.Name == name {
			sum := sha256.New()
			n, err := io.Copy(io.MultiWriter(out, sum), tr)
			if err != nil || n != wanted.Size || hex.EncodeToString(sum.Sum(nil)) != wanted.SHA256 {
				return ErrHostConflict
			}
			return nil
		}
	}
}

func hostJSON(raw []byte, v any) error {
	if len(raw) > 8<<20 {
		return ErrHostConflict
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func() error
	walk = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				t, e := d.Token()
				if e != nil {
					return e
				}
				key, ok := t.(string)
				if !ok || seen[strings.ToLower(key)] {
					return ErrHostConflict
				}
				seen[strings.ToLower(key)] = true
				if e := walk(); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e := walk(); e != nil {
					return e
				}
			}
		default:
			return ErrHostConflict
		}
		_, e = d.Token()
		return e
	}
	if walk() != nil {
		return ErrHostConflict
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrHostConflict
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(v) != nil || !bytes.Equal(raw, hostBytes(v)) {
		return ErrHostConflict
	}
	return nil
}
func hostBytes(v any) []byte  { b, _ := json.Marshal(v); return b }
func hostSHA(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

var hostComponent = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,100}$`)

func validHostMember(p string) bool {
	if len(p) > 240 || path.Clean(p) != p || strings.HasPrefix(p, "/") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if !hostComponent.MatchString(part) || strings.HasSuffix(part, ".") {
			return false
		}
		lower := strings.ToLower(part)
		stem := strings.Split(lower, ".")[0]
		if lower == "userdata" || lower == "user-data" || lower == "uploads" || lower == "workspaces" || lower == "secrets" || lower == "oci" || lower == "distro" || lower == "vm" {
			return false
		}
		if stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" || regexp.MustCompile(`^(com|lpt)[1-9]$`).MatchString(stem) {
			return false
		}
		if strings.Contains(lower, "rootfs") || strings.Contains(lower, "guest.raw") || strings.Contains(lower, "base.raw") || strings.Contains(lower, "seed") || strings.Contains(lower, "ssh") || lower == "efi" || strings.HasSuffix(lower, ".vhdx") || strings.HasSuffix(lower, ".qcow2") || strings.HasSuffix(lower, ".img") || strings.HasSuffix(lower, ".iso") || strings.HasSuffix(lower, ".key") {
			return false
		}
	}
	return strings.HasPrefix(p, "launcher/") || strings.HasPrefix(p, "controller/") || strings.HasPrefix(p, "backend/candidate/")
}
func (m HostBundleManifest) validate(c CandidateResult) error {
	if c.Artifact == nil || m.SchemaVersion != 1 || m.Product != "acornfox" || m.Kind != "host-update-v1" || m.OS != c.Artifact.OS || m.Architecture != c.Artifact.Arch || m.Version != c.Version || m.ControllerProtocol != 1 || m.InstanceProtocol != 1 || m.Backend.APIProtocol != 1 || validateSHA256(m.Backend.FromBinding) != nil || validateSHA256(m.Backend.ToBinding) != nil || m.Backend.ToBinding != c.Artifact.BackendBinding || m.Backend.Architecture != m.Architecture {
		return ErrHostConflict
	}
	if _, err := ParseSemver(m.Version); err != nil {
		return ErrHostConflict
	}
	if m.Backend.Mode != "candidate" && m.Backend.Mode != "unchanged" {
		return ErrHostConflict
	}
	if m.Backend.Mode == "candidate" && (m.Backend.FromBinding == m.Backend.ToBinding || validateSHA256(m.Backend.HelperSHA256) != nil) {
		return ErrHostConflict
	}
	if m.Backend.Mode == "unchanged" && (m.Backend.FromBinding != m.Backend.ToBinding || m.Backend.HelperSHA256 != "") {
		return ErrHostConflict
	}
	controller := "controller/acornfox-host-update"
	if m.OS == "windows" {
		controller += ".exe"
	}
	if m.Controller != controller || !strings.HasPrefix(m.Launcher, "launcher/") || len(m.Files) < 2 || len(m.Files) > 4096 {
		return ErrHostConflict
	}
	seen := map[string]bool{}
	tree := map[string]string{}
	files := map[string]bool{}
	var total int64
	launcherOK, controllerOK := false, false
	previous := ""
	for _, f := range m.Files {
		if !validHostMember(f.Path) || f.Path <= previous || seen[strings.ToLower(f.Path)] || validateSHA256(f.SHA256) != nil || f.Size < 1 || f.Size > maxHostExpanded-total || (f.Mode != 0644 && f.Mode != 0755) {
			return ErrHostConflict
		}
		for ancestor := path.Dir(f.Path); ancestor != "."; ancestor = path.Dir(ancestor) {
			key := strings.ToLower(ancestor)
			if prior, ok := tree[key]; ok && (prior != ancestor || files[key]) {
				return ErrHostConflict
			}
			tree[key] = ancestor
		}
		key := strings.ToLower(f.Path)
		if _, ok := tree[key]; ok {
			return ErrHostConflict
		}
		tree[key] = f.Path
		files[key] = true
		if len(tree) > 8192 {
			return ErrHostConflict
		}
		previous = f.Path
		seen[strings.ToLower(f.Path)] = true
		total += f.Size
		if f.Path == m.Launcher {
			launcherOK = f.Mode == 0755
		}
		if f.Path == m.Controller {
			controllerOK = f.Mode == 0755
		}
	}
	if !launcherOK || !controllerOK {
		return ErrHostConflict
	}
	return nil
}

// VerifyHostBundle reuses the existing signed index rules; a supplied receipt or
// CandidateResult alone never grants verification authority.
func VerifyHostBundle(ctx context.Context, payloadPath string, envelope []byte, opts CheckUpdateOptions) (*VerifiedHostBundle, error) {
	if ctx == nil {
		return nil, ErrInvalidOptions
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	c, err := VerifyAndSelectUpdate(envelope, opts)
	if err != nil {
		return nil, err
	}
	b, e := verifyHostBundle(ctx, payloadPath, *c)
	if e == nil {
		b.envelope = append([]byte(nil), envelope...)
	}
	return b, e
}
func verifyHostPayload(f *os.File, p string, a Artifact) error {
	return verifyHostPayloadLinks(f, p, a, 1)
}
func verifyHostPayloadLinks(f *os.File, p string, a Artifact, links uint64) error {
	before, err := os.Lstat(p)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() != a.Size {
		return ErrHostConflict
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) || hostCheckLinkedFile(f, p, links) != nil {
		return ErrHostConflict
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.NewSectionReader(f, 0, a.Size+1))
	if err != nil || n != a.Size || hex.EncodeToString(hash.Sum(nil)) != a.SHA256 {
		return ErrHostConflict
	}
	return nil
}
func verifyHostBundle(ctx context.Context, payloadPath string, c CandidateResult) (result *VerifiedHostBundle, err error) {
	if c.Artifact == nil || validateSHA256(c.Artifact.BackendBinding) != nil {
		return nil, ErrHostConflict
	}
	f, err := os.Open(payloadPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	if err = verifyHostPayload(f, payloadPath, *c.Artifact); err != nil {
		return nil, err
	}
	compressed := bufio.NewReader(io.NewSectionReader(f, 0, c.Artifact.Size))
	gz, e := gzip.NewReader(compressed)
	if e != nil {
		return nil, ErrHostConflict
	}
	defer gz.Close()
	gz.Multistream(false)
	tr := tar.NewReader(gz)
	h, e := tr.Next()
	if e != nil || h.Name != "bundle.json" || h.Typeflag != tar.TypeReg || h.Mode != 0644 || h.Size < 1 || h.Size > maxHostManifest || len(h.PAXRecords) != 0 {
		return nil, ErrHostConflict
	}
	raw, e := io.ReadAll(tr)
	if e != nil {
		return nil, e
	}
	var m HostBundleManifest
	if hostJSON(raw, &m) != nil || m.validate(c) != nil {
		return nil, ErrHostConflict
	}
	expected := map[string]HostBundleFile{}
	dirs := map[string]bool{}
	seen := map[string]bool{"bundle.json": true}
	small := map[string][]byte{}
	for _, entry := range m.Files {
		expected[entry.Path] = entry
		for p := path.Dir(entry.Path); p != "."; p = path.Dir(p) {
			dirs[p] = true
		}
	}
	count := 1
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		h, e = tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, ErrHostConflict
		}
		count++
		if count > 8192 || len(h.PAXRecords) != 0 || h.Linkname != "" {
			return nil, ErrHostConflict
		}
		name := strings.TrimSuffix(h.Name, "/")
		if seen[strings.ToLower(name)] {
			return nil, ErrHostConflict
		}
		seen[strings.ToLower(name)] = true
		if h.Typeflag == tar.TypeDir {
			if !dirs[name] || h.Size != 0 || h.Mode != 0755 {
				return nil, ErrHostConflict
			}
			continue
		}
		want, ok := expected[h.Name]
		if !ok || h.Typeflag != tar.TypeReg || h.Size != want.Size || h.Mode != want.Mode {
			return nil, ErrHostConflict
		}
		hash := sha256.New()
		var capture bytes.Buffer
		out := io.Writer(hash)
		if strings.HasPrefix(h.Name, "backend/candidate/") && !strings.HasSuffix(h.Name, ".tar.gz") {
			if h.Size > maxHostManifest {
				return nil, ErrHostConflict
			}
			out = io.MultiWriter(hash, &capture)
		}
		n, e := io.Copy(out, tr)
		if e != nil || n != want.Size || hex.EncodeToString(hash.Sum(nil)) != want.SHA256 {
			return nil, ErrHostConflict
		}
		if capture.Len() > 0 {
			small[path.Base(h.Name)] = capture.Bytes()
		}
		delete(expected, h.Name)
	}
	if len(expected) != 0 || validateHostBackend(m, small) != nil {
		return nil, ErrHostConflict
	}
	// Reject a second tar/nonzero trailing payload, including gzip concatenation.
	tail, e := io.ReadAll(io.LimitReader(gz, 1025))
	if e != nil || len(tail) > 1024 || bytes.Count(tail, []byte{0}) != len(tail) {
		return nil, ErrHostConflict
	}
	if _, e := compressed.Peek(1); e != io.EOF {
		return nil, ErrHostConflict
	}
	return &VerifiedHostBundle{manifest: m, artifact: *c.Artifact, payload: f, payloadPath: filepath.Clean(payloadPath), manifestSHA: hostSHA(raw)}, nil
}
func validateHostBackend(m HostBundleManifest, small map[string][]byte) error {
	members := map[string]HostBundleFile{}
	for _, f := range m.Files {
		if strings.HasPrefix(f.Path, "backend/") {
			members[path.Base(f.Path)] = f
		}
	}
	if m.Backend.Mode == "unchanged" {
		if len(members) != 0 {
			return ErrHostConflict
		}
		return nil
	}
	if len(members) != 6 || len(small) != 5 {
		return ErrHostConflict
	}
	bindingRaw := small["candidate-binding.json"]
	if hostSHA(bindingRaw) != m.Backend.ToBinding || string(small["candidate-binding.sha256"]) != m.Backend.ToBinding+"\n" {
		return ErrHostConflict
	}
	var b struct {
		Schema    int    `json:"schema_version"`
		Product   string `json:"product"`
		Version   string `json:"version"`
		Release   string `json:"release_id"`
		Source    string `json:"source_commit"`
		Arch      string `json:"architecture"`
		Migration string `json:"migration_version"`
		Archive   string `json:"archive_sha256"`
		Manifest  string `json:"manifest_sha256"`
		Bundle    string `json:"bundle_manifest_sha256"`
		Previous  struct {
			Binding string `json:"binding_sha256"`
		} `json:"n_minus_one"`
	}
	// Backend's existing verifier owns the full backend schema. Here every byte is
	// signed and cross-bound; do not duplicate its migration or runtime transaction.
	if json.Unmarshal(bindingRaw, &b) != nil || b.Schema != 1 || b.Product != "acornfox" || b.Arch != m.Backend.Architecture || b.Migration != "0040" || b.Release != "release-"+b.Version || b.Previous.Binding != m.Backend.FromBinding {
		return ErrHostConflict
	}
	if _, e := ParseSemver(b.Version); e != nil {
		return ErrHostConflict
	}
	if members["acornfox-"+b.Version+"-production.tar.gz"].SHA256 != b.Archive || hostSHA(small["release-manifest.json"]) != b.Manifest || hostSHA(small["bundle-manifest.sha256"]) != b.Bundle {
		return ErrHostConflict
	}
	var manifest struct {
		Product, Version string
		Release          string `json:"release_id"`
		Source           string `json:"source_commit"`
		Arch             string `json:"architecture"`
		Files            []struct {
			Path, SHA256 string
			Mode         int64
		} `json:"files"`
	}
	if json.Unmarshal(small["release-manifest.json"], &manifest) != nil || manifest.Product != b.Product || manifest.Version != b.Version || manifest.Release != b.Release || manifest.Source != b.Source || manifest.Arch != b.Arch {
		return ErrHostConflict
	}
	helper := false
	for _, f := range manifest.Files {
		if f.Path == "bin/acornfox-upgrade" {
			helper = f.SHA256 == m.Backend.HelperSHA256 && f.Mode == 0755
		}
	}
	if !helper {
		return ErrHostConflict
	}
	return nil
}

// SignedEnvelope is for the privileged transport's independent verification,
// never a UI status/log. The original signed format is retained unchanged.
func (b *VerifiedHostBundle) SignedEnvelope() []byte { return append([]byte(nil), b.envelope...) }
func (b *VerifiedHostBundle) CopyPayload(out io.Writer) error {
	if b == nil || b.payload == nil || verifyHostPayload(b.payload, b.payloadPath, b.artifact) != nil {
		return ErrHostConflict
	}
	sum := sha256.New()
	n, e := io.Copy(io.MultiWriter(out, sum), io.NewSectionReader(b.payload, 0, b.artifact.Size))
	if e != nil {
		return e
	}
	if n != b.artifact.Size || hex.EncodeToString(sum.Sum(nil)) != b.artifact.SHA256 {
		return ErrHostConflict
	}
	return nil
}
func (VerifiedHostBundle) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "verified host bundle [private transport metadata redacted]")
}
