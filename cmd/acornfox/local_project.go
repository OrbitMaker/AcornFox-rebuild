package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

type localProjectEntry struct {
	path, name string
	info       fs.FileInfo
}
type localProjectSnapshot struct {
	root       string
	files      []localProjectEntry
	bytes      int64
	excluded   []string
	dockerfile bool
}
type multipartPayload struct {
	reader      io.Reader
	contentType string
	size        int64
}
type reportedCLIResult struct {
	code    int
	message string
}

func (e reportedCLIResult) Error() string { return e.message }

type apiSourceUpload struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Status    string    `json:"status"`
	Digest    string    `json:"digest"`
	Bytes     *int64    `json:"bytes"`
	FileCount *int      `json:"file_count"`
	ExpiresAt time.Time `json:"expires_at"`
}

func validateSourceUpload(v *apiSourceUpload) bool {
	return nonempty(v.ID) && validCLIHash(v.Digest) && (v.Kind == "archive" || v.Kind == "directory") && (v.Status == "ready" || v.Status == "claimed" || v.Status == "expired" || v.Status == "failed") && v.Bytes != nil && *v.Bytes >= 0 && v.FileCount != nil && *v.FileCount > 0 && validTime(v.ExpiresAt)
}
func excludeLocalProjectEntry(name string, directory bool) bool {
	name = strings.ToLower(name)
	if directory {
		switch name {
		case ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".cache", ".codex", ".codex-artifacts", ".omx", ".claude", ".ssh", ".aws", ".azure", ".gnupg", ".terraform":
			return true
		}
	}
	if name == ".env" || strings.HasPrefix(name, ".env.") && name != ".env.example" && name != ".env.sample" && name != ".env.template" {
		return true
	}
	switch name {
	case ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", ".ds_store", ".netrc", ".git-credentials", "credentials.json", "application_default_credentials.json":
		return true
	}
	return strings.HasPrefix(name, "terraform.tfstate") || strings.HasSuffix(name, ".tfstate") || strings.HasSuffix(name, ".tfstate.backup") || strings.HasSuffix(name, ".key") || strings.HasSuffix(name, ".p12") || strings.HasSuffix(name, ".pfx") || strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".jks") || strings.HasSuffix(name, ".keystore")
}
func inspectLocalProject(input string, protectedPaths ...string) (localProjectSnapshot, error) {
	protected := map[string]bool{}
	for _, path := range protectedPaths {
		absolute, err := filepath.Abs(path)
		if err == nil {
			protected[absolute] = true
			if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
				protected[resolved] = true
			}
		}
	}
	root, err := filepath.Abs(input)
	if err != nil {
		return localProjectSnapshot{}, errors.New("project directory is unavailable")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return localProjectSnapshot{}, errors.New("project directory is unavailable")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return localProjectSnapshot{}, errors.New("source must be a public HTTPS Git URL or a local project directory")
	}
	snapshot := localProjectSnapshot{root: root, excluded: []string{}}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("project contains an unreadable path")
		}
		if path == root {
			return nil
		}
		relative, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		relative = filepath.ToSlash(relative)
		lowerPath := "/" + strings.ToLower(relative)
		credentialPath := strings.HasSuffix(lowerPath, "/.docker/config.json") || strings.HasSuffix(lowerPath, "/.kube/config") || strings.Contains(lowerPath, "/.config/gcloud/") || strings.HasSuffix(lowerPath, "/.config/gcloud")
		if protected[path] || credentialPath || excludeLocalProjectEntry(entry.Name(), entry.IsDir() || entry.Type()&os.ModeSymlink != 0) {
			if len(snapshot.excluded) < 100 {
				snapshot.excluded = append(snapshot.excluded, relative)
			}
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("project symlink is unsupported: %s", relative)
		}
		if entry.IsDir() {
			return nil
		}
		info, e := entry.Info()
		if e != nil || !singleLinkedProjectFile(info) {
			return fmt.Errorf("project path is not a regular file: %s", relative)
		}
		if _, e := domain.NormalizeSourceUploadPath(relative); e != nil {
			return fmt.Errorf("project filename is unsupported: %s", relative)
		}
		if info.Size() > 32<<20 || info.Size() < 0 {
			return fmt.Errorf("project file exceeds 32 MiB: %s", relative)
		}
		snapshot.bytes += info.Size()
		if snapshot.bytes > 100<<20 || len(snapshot.files) >= 10000 {
			return errors.New("project exceeds 100 MiB or 10000 uploadable files")
		}
		snapshot.files = append(snapshot.files, localProjectEntry{path, relative, info})
		snapshot.dockerfile = snapshot.dockerfile || relative == "Dockerfile"
		return nil
	})
	if err != nil {
		return localProjectSnapshot{}, err
	}
	if len(snapshot.files) == 0 {
		return localProjectSnapshot{}, errors.New("project has no uploadable files")
	}
	sort.Slice(snapshot.files, func(i, j int) bool { return snapshot.files[i].name < snapshot.files[j].name })
	return snapshot, nil
}
func projectMultipart(snapshot localProjectSnapshot) (multipartPayload, func(), error) {
	file, err := os.CreateTemp("", "acornfox-upload-*.multipart")
	if err != nil {
		return multipartPayload{}, nil, err
	}
	cleanup := func() { file.Close(); os.Remove(file.Name()) }
	fail := func(err error) (multipartPayload, func(), error) { cleanup(); return multipartPayload{}, nil, err }
	if err := file.Chmod(0600); err != nil {
		return fail(err)
	}
	writer := multipart.NewWriter(file)
	if err := writer.WriteField("mode", "archive"); err != nil {
		return fail(err)
	}
	part, err := writer.CreateFormFile("archive", "project.tar.gz")
	if err != nil {
		return fail(err)
	}
	zipped := gzip.NewWriter(part)
	archive := tar.NewWriter(zipped)
	for _, entry := range snapshot.files {
		current, err := os.Lstat(entry.path)
		if err != nil || !singleLinkedProjectFile(current) || !os.SameFile(current, entry.info) {
			archive.Close()
			zipped.Close()
			return fail(errors.New("project changed during upload preparation"))
		}
		input, err := os.Open(entry.path)
		if err != nil {
			archive.Close()
			zipped.Close()
			return fail(err)
		}
		opened, err := input.Stat()
		if err != nil || !singleLinkedProjectFile(opened) || !os.SameFile(opened, entry.info) || opened.Size() != entry.info.Size() {
			input.Close()
			archive.Close()
			zipped.Close()
			return fail(errors.New("project changed during upload preparation"))
		}
		header := &tar.Header{Name: entry.name, Mode: int64(0644 | entry.info.Mode().Perm()&0111), Size: entry.info.Size(), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg}
		if err := archive.WriteHeader(header); err != nil {
			input.Close()
			archive.Close()
			zipped.Close()
			return fail(err)
		}
		n, copyErr := io.Copy(archive, io.LimitReader(input, entry.info.Size()+1))
		input.Close()
		if copyErr != nil || n != entry.info.Size() {
			archive.Close()
			zipped.Close()
			return fail(errors.New("project changed during upload preparation"))
		}
	}
	if err := archive.Close(); err != nil {
		zipped.Close()
		return fail(err)
	}
	if err := zipped.Close(); err != nil {
		return fail(err)
	}
	if err := writer.Close(); err != nil {
		return fail(err)
	}
	size, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return fail(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	return multipartPayload{file, writer.FormDataContentType(), size}, cleanup, nil
}
func readRuntimeInput(path string) (*contracts.AcornFoxRuntimeInput, error) {
	if path == "" {
		return nil, nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
		return nil, errors.New("runtime file must be a regular JSON file no larger than 64 KiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var value contracts.AcornFoxRuntimeInput
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("runtime file must contain one supported JSON configuration")
	}
	if len(value.Secrets) > 0 {
		return nil, errors.New("runtime secret files are not supported; do not put passwords or tokens in plain settings")
	}
	for i := range value.Environment {
		if value.Environment[i].Kind == "" {
			value.Environment[i].Kind = contracts.RuntimeEnvironmentLiteral
		}
	}
	resources := contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 500, MemoryBytes: 512 << 20, PIDs: 128, DiskReservationBytes: 1 << 30}
	if value.Resources != nil {
		resources = *value.Resources
	} else {
		for _, v := range value.Volumes {
			if v.SizeBytes <= 0 || v.SizeBytes > 1<<50 || resources.DiskReservationBytes > (1<<50)-v.SizeBytes {
				return nil, errors.New("runtime volume reservation is invalid")
			}
			resources.DiskReservationBytes += v.SizeBytes
		}
	}
	digest, err := contracts.CanonicalAcornFoxRuntimeConfigDigest(value.AcornFoxRuntimeConfiguration, resources, 0)
	if err != nil {
		return nil, errors.New("runtime configuration has invalid arguments, resources or volumes")
	}
	raw, _ := json.Marshal(value.AcornFoxRuntimeConfiguration)
	safe, err := foundation.RedactJSON(raw, nil)
	var checked contracts.AcornFoxRuntimeConfiguration
	if err != nil || json.Unmarshal(safe, &checked) != nil {
		return nil, errors.New("runtime configuration contains protected values")
	}
	after, err := contracts.CanonicalAcornFoxRuntimeConfigDigest(checked, resources, 0)
	if err != nil || after != digest {
		return nil, errors.New("runtime configuration contains protected values")
	}
	return &value, nil
}
func (c *cli) uploadLocalProject(state sessionState, path, key string) (apiSourceUpload, error) {
	snapshot, err := c.inspectLocalProject(path)
	if err != nil {
		return apiSourceUpload{}, err
	}
	payload, cleanup, err := projectMultipart(snapshot)
	if err != nil {
		return apiSourceUpload{}, err
	}
	defer cleanup()
	if len(snapshot.excluded) > 0 {
		fmt.Fprintf(c.err, "Excluded %d dependency/cache/credential paths; use acornfox check to see the list.\n", len(snapshot.excluded))
	}
	result, err := c.performCall(state, "POST", "/source-uploads", payload, true, key, 3*time.Minute, shapeSourceUpload)
	if err != nil {
		return apiSourceUpload{}, err
	}
	upload := result.(apiSourceUpload)
	if upload.Status != "ready" && upload.Status != "claimed" {
		return apiSourceUpload{}, errors.New("uploaded project is not available for use")
	}
	return upload, nil
}
func (c *cli) checkLocalProject(args []string) error {
	paths, values, err := parseFlags(args, "--runtime-file")
	if err != nil {
		return err
	}
	if len(paths) != 1 {
		return errors.New("usage: acornfox check PROJECT_DIRECTORY [--runtime-file JSON_FILE]")
	}
	snapshot, err := c.inspectLocalProject(paths[0])
	if err != nil {
		return err
	}
	runtime, err := readRuntimeInput(values["--runtime-file"])
	if err != nil {
		return err
	}
	status := "ready_for_upload"
	issues := []string{}
	if !snapshot.dockerfile {
		status = "configuration_required"
		issues = append(issues, "Dockerfile is missing; ask your AI to prepare it, then run check again")
	}
	result := map[string]any{"status": status, "files": len(snapshot.files), "bytes": snapshot.bytes, "excluded_paths": snapshot.excluded, "dockerfile_present": snapshot.dockerfile, "runtime_file_provided": runtime != nil, "issues": issues, "deployment_verified": false}
	if err := c.emit(result); err != nil {
		return err
	}
	if !snapshot.dockerfile {
		return reportedCLIResult{2, issues[0]}
	}
	return nil
}
func (c *cli) uploadCommand(args []string) error {
	if len(args) == 2 && args[0] == "get" {
		id, err := requireID(args[1], "upload ID")
		if err != nil {
			return err
		}
		return c.callCommand("GET", "/source-uploads/"+pathID(id), nil, false, "", 15*time.Second, shapeSourceUpload)
	}
	paths, values, err := parseFlags(args, "--idempotency-key")
	if err != nil {
		return err
	}
	if len(paths) != 1 {
		return errors.New("usage: acornfox upload PROJECT_DIRECTORY [--idempotency-key KEY]")
	}
	key, err := idempotencyKey(values)
	if err != nil {
		return err
	}
	state, err := loadState(c.env)
	if err != nil {
		return err
	}
	value, err := c.uploadLocalProject(state, paths[0], key)
	if err != nil {
		return err
	}
	return c.emit(value)
}
func (c *cli) planCommand(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: acornfox plan APP_ID SOURCE_ID")
	}
	app, err := requireID(args[0], "application ID")
	if err != nil {
		return err
	}
	source, err := requireID(args[1], "source ID")
	if err != nil {
		return err
	}
	return c.callCommand("GET", "/apps/"+pathID(app)+"/sources/"+pathID(source)+"/deployment-plan", nil, false, "", 15*time.Second, shapeDeploymentPlan)
}

func (c *cli) inspectLocalProject(path string) (localProjectSnapshot, error) {
	if c.env != nil {
		if session, err := statePath(c.env); err == nil {
			return inspectLocalProject(path, session)
		}
	}
	return inspectLocalProject(path)
}
