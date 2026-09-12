package desktopupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

func slotValidateFiles(files []HostBundleFile, launcher, controller string) error {
	if len(files) < 2 || len(files) > 4096 || launcher == controller {
		return ErrHostConflict
	}
	seen := map[string]bool{}
	names := map[string]string{}
	executables := 0
	var total int64
	for _, f := range files {
		if f.Path == "" || path.Clean(f.Path) != f.Path || strings.HasPrefix(f.Path, "/") || strings.ContainsAny(f.Path, "\\:\x00") || strings.HasPrefix(f.Path, "../") || f.Path == ".." || f.Size < 1 || f.Size > maxHostExpanded-total || validateSHA256(f.SHA256) != nil || (f.Mode != 0644 && f.Mode != 0755) || seen[f.Path] {
			return ErrHostConflict
		}
		for _, part := range strings.Split(f.Path, "/") {
			if part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
				return ErrHostConflict
			}
		}
		total += f.Size
		seen[f.Path] = true
		for cur := f.Path; cur != "."; cur = path.Dir(cur) {
			lower := strings.ToLower(cur)
			if prior, ok := names[lower]; ok && prior != cur {
				return ErrHostConflict
			}
			names[lower] = cur
		}
		if f.Path == launcher || f.Path == controller {
			if f.Mode != 0755 {
				return ErrHostConflict
			}
			executables++
		}
	}
	for name := range seen {
		for cur := path.Dir(name); cur != "."; cur = path.Dir(cur) {
			if seen[cur] {
				return ErrHostConflict
			}
		}
	}
	if executables != 2 {
		return ErrHostConflict
	}
	return nil
}
func slotExpected(files []HostBundleFile) map[string]*HostBundleFile {
	out := map[string]*HostBundleFile{}
	for i := range files {
		f := &files[i]
		out[f.Path] = f
		for p := path.Dir(f.Path); p != "."; p = path.Dir(p) {
			if _, ok := out[p]; !ok {
				out[p] = nil
			}
		}
	}
	return out
}

// Every visited component is checked without following links. Missing permits
// only a deletion prefix; it never authorizes an unlisted object.
func slotVerifyTree(root *os.Root, base string, files []HostBundleFile, launcher, controller, osName, arch string, closed, missing bool, writing *slotPreparation) error {
	a, e := root.Stat(".")
	b, be := os.Lstat(base)
	if e != nil || be != nil || !os.SameFile(a, b) || b.Mode()&os.ModeSymlink != 0 {
		return ErrHostConflict
	}
	if e = slotCheckDirectory(base, closed); e != nil {
		return e
	}
	expected := slotExpected(files)
	found := map[string]bool{}
	var walk func(string) error
	walk = func(dir string) error {
		f, e := root.Open(dir)
		if e != nil {
			return e
		}
		entries, e := f.ReadDir(-1)
		f.Close()
		if e != nil {
			return e
		}
		for _, entry := range entries {
			name := path.Join(dir, entry.Name())
			want, ok := expected[name]
			if !ok {
				if closed {
					return ErrHostConflict
				}
				continue
			}
			info, e := root.Lstat(name)
			if e != nil || info.Mode()&os.ModeSymlink != 0 {
				return ErrHostConflict
			}
			found[name] = true
			if want == nil {
				if !info.IsDir() {
					return ErrHostConflict
				}
				if e = slotCheckDirectory(filepath.Join(base, filepath.FromSlash(name)), closed); e != nil {
					return e
				}
				if e = walk(name); e != nil {
					return e
				}
				continue
			}
			f, e := root.Open(name)
			if e != nil {
				return e
			}
			e = slotCheckAsset(f, filepath.Join(base, filepath.FromSlash(name)), want.Mode, closed)
			if e == nil {
				if writing != nil && writing.Writing == name {
					key, ke := slotFileKey(f)
					if ke != nil || key != writing.FileIdentity || info.Size() > want.Size {
						e = ErrHostConflict
					}
				} else {
					e = slotHashFile(f, *want)
					if e == nil && (name == launcher || name == controller) {
						e = slotCPU(f, osName, arch)
					}
				}
			}
			f.Close()
			if e != nil {
				return e
			}
		}
		return nil
	}
	if e := walk("."); e != nil {
		return e
	}
	if !missing {
		for name := range expected {
			if !found[name] {
				return ErrHostConflict
			}
		}
	}
	return nil
}
func slotHashFile(f *os.File, want HostBundleFile) error {
	info, e := f.Stat()
	if e != nil || info.Size() != want.Size {
		return ErrHostConflict
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return e
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, want.Size+1))
	if e != nil || n != want.Size || hex.EncodeToString(h.Sum(nil)) != want.SHA256 {
		return ErrHostConflict
	}
	return nil
}
func slotCPU(f *os.File, osName, arch string) error {
	switch osName {
	case "linux":
		x, e := elf.NewFile(f)
		if e != nil {
			return ErrHostConflict
		}
		machine := elf.EM_X86_64
		if arch == "arm64" {
			machine = elf.EM_AARCH64
		} else if arch != "amd64" {
			return ErrHostConflict
		}
		if x.Class != elf.ELFCLASS64 || x.Data != elf.ELFDATA2LSB || x.Machine != machine || (x.Type != elf.ET_EXEC && x.Type != elf.ET_DYN) || x.Entry == 0 {
			return ErrHostConflict
		}
	case "darwin":
		x, e := macho.NewFile(f)
		if e != nil {
			return ErrHostConflict
		}
		cpu := macho.CpuAmd64
		if arch == "arm64" {
			cpu = macho.CpuArm64
		} else if arch != "amd64" {
			return ErrHostConflict
		}
		if x.Magic != macho.Magic64 || x.Type != macho.TypeExec || x.Cpu != cpu {
			return ErrHostConflict
		}
	case "windows":
		x, e := pe.NewFile(f)
		if e != nil {
			return ErrHostConflict
		}
		machine := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
		if arch == "arm64" {
			machine = pe.IMAGE_FILE_MACHINE_ARM64
		} else if arch != "amd64" {
			return ErrHostConflict
		}
		header, ok := x.OptionalHeader.(*pe.OptionalHeader64)
		if !ok || header.AddressOfEntryPoint == 0 || x.Machine != machine || x.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 || x.Characteristics&pe.IMAGE_FILE_DLL != 0 {
			return ErrHostConflict
		}
	default:
		return ErrHostConflict
	}
	return nil
}
func (s *slotStore) openRecord(r slotRecord) (*os.Root, error) {
	p := filepath.Join(s.path, r.Directory)
	key, e := hostDirectoryKey(p)
	if e != nil || key != r.Identity {
		return nil, ErrHostConflict
	}
	root, e := s.root.OpenRoot(r.Directory)
	if e != nil {
		return nil, e
	}
	a, e := root.Stat(".")
	b, be := s.root.Lstat(r.Directory)
	if e != nil || be != nil || !os.SameFile(a, b) {
		root.Close()
		return nil, ErrHostConflict
	}
	return root, nil
}
func (s *slotStore) prepareDirectory(l *slotLedger) error {
	p := l.Preparing
	r := &p.Record
	if r.Identity != "" {
		root, e := s.openRecord(*r)
		if e == nil {
			root.Close()
		}
		return e
	}
	dir := filepath.Join(s.path, r.Directory)
	if info, e := s.root.Lstat(r.Directory); errors.Is(e, os.ErrNotExist) {
		if e = s.root.Mkdir(r.Directory, 0700); e != nil {
			return e
		}
		if e = secureNewStageDirectory(context.Background(), dir); e != nil {
			return e
		}
		if e = hostSyncDirectory(s.path); e != nil {
			return e
		}
	} else if e != nil || !info.IsDir() {
		return ErrHostConflict
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 0 {
		return ErrHostConflict
	}
	key, e := hostDirectoryKey(dir)
	if e != nil {
		return e
	}
	r.Identity = key
	if e = s.save(l); e != nil {
		return e
	}
	return s.step("slot-directory")
}
func (s *slotStore) copyBundle(ctx context.Context, l *slotLedger, b *VerifiedHostBundle) error {
	p := l.Preparing
	r := p.Record
	root, e := s.openRecord(r)
	if e != nil {
		return e
	}
	defer root.Close()
	base := filepath.Join(s.path, r.Directory)
	if e = slotVerifyTree(root, base, r.Files, r.Launcher, r.Controller, r.OS, r.Architecture, true, true, p); e != nil {
		// An unregistered empty inode is the only legitimate create-before-register
		// prefix. Handle it below with the exact inventory path, never by scanning.
		if p.Writing != "" {
			return e
		}
		if e = slotVerifyPreparation(root, base, r); e != nil {
			return e
		}
	}
	for _, want := range r.Files {
		if e = ctx.Err(); e != nil {
			return e
		}
		name := want.Path
		full := filepath.Join(base, filepath.FromSlash(name))
		if p.Writing != "" && p.Writing != name {
			continue
		}
		if f, e := root.Open(name); e == nil {
			e = slotCheckAsset(f, full, want.Mode, true)
			if e == nil {
				e = slotHashFile(f, want)
			}
			f.Close()
			if e == nil {
				if p.Writing == name {
					p.Writing = ""
					p.FileIdentity = ""
					if e = s.save(l); e != nil {
						return e
					}
				}
				continue
			}
		}
		// Ensure only signed implicit directories exist, with private permissions.
		var dirs []string
		for d := path.Dir(name); d != "."; d = path.Dir(d) {
			dirs = append(dirs, d)
		}
		for i := len(dirs) - 1; i >= 0; i-- {
			d := dirs[i]
			if _, e = root.Lstat(d); errors.Is(e, os.ErrNotExist) {
				if e = root.Mkdir(d, 0700); e != nil {
					return e
				}
				if e = hostSyncDirectory(filepath.Join(base, filepath.FromSlash(path.Dir(d)))); e != nil {
					return e
				}
			}
			if e = slotCheckDirectory(filepath.Join(base, filepath.FromSlash(d)), true); e != nil {
				return e
			}
		}
		f, e := root.OpenFile(name, os.O_RDWR|os.O_CREATE, os.FileMode(want.Mode))
		if e != nil {
			return e
		}
		if e = slotCheckAsset(f, full, want.Mode, true); e != nil {
			f.Close()
			return e
		}
		info, e := f.Stat()
		if e != nil {
			f.Close()
			return e
		}
		key, e := slotFileKey(f)
		if e != nil {
			f.Close()
			return e
		}
		if p.Writing == "" {
			if info.Size() != 0 {
				f.Close()
				return ErrHostConflict
			}
			if e = f.Sync(); e == nil {
				e = hostSyncDirectory(filepath.Dir(full))
			}
			if e != nil {
				f.Close()
				return e
			}
			p.Writing = name
			p.FileIdentity = key
			if e = s.save(l); e != nil {
				f.Close()
				return e
			}
		} else if p.FileIdentity != key {
			f.Close()
			return ErrHostConflict
		}

		writer := &slotResumeWriter{file: f, ctx: ctx, prior: info.Size(), cut: want.Size / 2, step: s.step}
		e = b.ReadFile(name, writer)
		if e == nil {
			e = f.Sync()
		}
		if e == nil {
			e = slotHashFile(f, want)
		}
		f.Close()
		if e != nil {
			return e
		}

		if e = hostSyncDirectory(filepath.Dir(full)); e != nil {
			return e
		}
		if e = s.step("slot-file-written"); e != nil {
			return e
		}
		p.Writing = ""
		p.FileIdentity = ""
		if e = s.save(l); e != nil {
			return e
		}
	}
	// Re-enter if a resumed later entry initially skipped earlier complete files.
	return verifyHostPayload(b.payload, b.payloadPath, b.artifact)
}

// Before a writing cursor is committed, at most one exact inventory file can
// exist empty. No other unverified bytes or objects are admitted.
func slotVerifyPreparation(root *os.Root, base string, r slotRecord) error {
	var empty *slotPreparation
	for _, f := range r.Files {
		h, e := root.Open(f.Path)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		i, e := h.Stat()
		if e == nil && i.Size() == 0 {
			if empty != nil {
				h.Close()
				return ErrHostConflict
			}
			key, ke := slotFileKey(h)
			if ke != nil {
				h.Close()
				return ke
			}
			empty = &slotPreparation{Writing: f.Path, FileIdentity: key}
		}
		h.Close()
	}
	return slotVerifyTree(root, base, r.Files, r.Launcher, r.Controller, r.OS, r.Architecture, true, true, empty)
}
func (s *slotStore) validateDeletion(l slotLedger, ids []string, missing bool) error {
	for _, id := range ids {
		r, prep, ok := slotFind(l, id)
		if !ok {
			return ErrHostConflict
		}
		if r.Identity == "" {
			if _, e := s.root.Lstat(r.Directory); errors.Is(e, os.ErrNotExist) {
				continue
			}
			return ErrHostConflict
		}
		root, e := s.openRecord(r)
		if e != nil {
			if missing {
				if _, e = s.root.Lstat(r.Directory); errors.Is(e, os.ErrNotExist) {
					continue
				}
			}
			return ErrHostConflict
		}
		e = slotVerifyTree(root, filepath.Join(s.path, r.Directory), r.Files, r.Launcher, r.Controller, r.OS, r.Architecture, true, missing || prep != nil, prep)
		if e != nil && prep != nil && prep.Writing == "" {
			e = slotVerifyPreparation(root, filepath.Join(s.path, r.Directory), r)
		}
		root.Close()
		if e != nil {
			return e
		}
	}
	return nil
}
func slotFind(l slotLedger, id string) (slotRecord, *slotPreparation, bool) {
	for _, r := range l.Records {
		if r.ID == id {
			return r, nil, true
		}
	}
	if l.Preparing != nil && l.Preparing.Record.ID == id {
		return l.Preparing.Record, l.Preparing, true
	}
	return slotRecord{}, nil, false
}
func (s *slotStore) deleteSlots(ctx context.Context, l *slotLedger) error {
	if e := s.validateDeletion(*l, l.Deleting, true); e != nil {
		return e
	}
	for _, id := range l.Deleting {
		r, _, _ := slotFind(*l, id)
		if e := ctx.Err(); e != nil {
			return e
		}
		if _, e := s.root.Lstat(r.Directory); errors.Is(e, os.ErrNotExist) {
			continue
		}
		root, e := s.openRecord(r)
		if e != nil {
			return e
		}
		expected := slotExpected(r.Files)
		var names []string
		for n := range expected {
			names = append(names, n)
		}
		sort.Slice(names, func(i, j int) bool {
			a, b := strings.Count(names[i], "/"), strings.Count(names[j], "/")
			if a != b {
				return a > b
			}
			return names[i] > names[j]
		})
		for _, n := range names {
			if e = ctx.Err(); e != nil {
				root.Close()
				return e
			}
			if e = root.Remove(n); errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				root.Close()
				return e
			}
			if e = hostSyncDirectory(filepath.Join(s.path, r.Directory, filepath.FromSlash(path.Dir(n)))); e != nil {
				root.Close()
				return e
			}
			if e = s.step("slot-gc-entry"); e != nil {
				root.Close()
				return e
			}
		}
		root.Close()
		if e = s.root.Remove(r.Directory); e != nil {
			return e
		}
		if e = hostSyncDirectory(s.path); e != nil {
			return e
		}
		if e = s.step("slot-gc-directory"); e != nil {
			return e
		}
	}
	records := l.Records[:0]
	for _, r := range l.Records {
		if !slotContains(l.Deleting, r.ID) {
			records = append(records, r)
		}
	}
	l.Records = records
	if l.Preparing != nil && slotContains(l.Deleting, l.Preparing.Record.ID) {
		l.Preparing = nil
	}
	l.Deleting = nil
	return s.save(l)
}

// Bounded streaming comparison validates a resumed prefix against the exact
// signed source; only the missing suffix is appended to the registered inode.
type slotResumeWriter struct {
	file               *os.File
	ctx                context.Context
	prior, offset, cut int64
	stepped            bool
	step               func(string) error
}

func (w *slotResumeWriter) Write(data []byte) (int, error) {
	if e := w.ctx.Err(); e != nil {
		return 0, e
	}
	original := len(data)
	for len(data) > 0 {
		count := len(data)
		if !w.stepped && w.offset < w.cut && int64(count) > w.cut-w.offset {
			count = int(w.cut - w.offset)
		}
		chunk := data[:count]
		overlap := int64(count)
		if w.offset+overlap > w.prior {
			overlap = w.prior - w.offset
		}
		if overlap < 0 {
			overlap = 0
		}
		if overlap > 0 {
			prior := make([]byte, int(overlap))
			if _, e := w.file.ReadAt(prior, w.offset); e != nil {
				return original - len(data), e
			}
			if !bytes.Equal(prior, chunk[:int(overlap)]) {
				return original - len(data), ErrHostConflict
			}
		}
		if overlap < int64(count) {
			if _, e := w.file.WriteAt(chunk[int(overlap):], w.offset+overlap); e != nil {
				return original - len(data), e
			}
		}
		w.offset += int64(count)
		data = data[count:]
		if !w.stepped && w.offset >= w.cut {
			w.stepped = true
			if e := w.file.Sync(); e != nil {
				return original - len(data), e
			}
			if e := w.step("slot-file-prefix"); e != nil {
				return original - len(data), e
			}
		}
	}
	return original, nil
}
