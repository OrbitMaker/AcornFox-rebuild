package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/acornfox/acornfox/internal/client"
)

// targetsFile is the on-disk shape of <UserConfigDir>/acornfox/targets.json.
type targetsFile struct {
	Default string                    `json:"default"`
	Targets map[string]*client.Target `json:"targets"`
}

// projectFile is the on-disk shape of <projectDir>/.acornfox. It never holds
// any credential, only the selected target name and app name.
type projectFile struct {
	Target string `json:"target"`
	App    string `json:"app"`
}

const (
	targetsDirName  = "acornfox"
	targetsFileName = "targets.json"
	projectFileName = ".acornfox"
	defaultRemote   = "acornfox proxy"
)

// configPaths resolves the targets.json directory and file. The directory is
// created lazily by writers (0700). configDir, when non-empty, overrides
// os.UserConfigDir (used by tests to inject a temp location).
func configPaths(configDir string) (dir, file string, err error) {
	base := configDir
	if base == "" {
		base, err = os.UserConfigDir()
		if err != nil {
			return "", "", err
		}
	}
	dir = filepath.Join(base, targetsDirName)
	file = filepath.Join(dir, targetsFileName)
	return dir, file, nil
}

// loadTargets reads targets.json, returning an empty structure if it is absent.
func loadTargets(configDir string) (*targetsFile, error) {
	_, file, err := configPaths(configDir)
	if err != nil {
		return nil, err
	}
	tf := &targetsFile{Targets: map[string]*client.Target{}}
	data, err := os.ReadFile(file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return tf, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, tf); err != nil {
		return nil, err
	}
	if tf.Targets == nil {
		tf.Targets = map[string]*client.Target{}
	}
	return tf, nil
}

// saveTargets writes targets.json atomically with 0600, creating the parent
// directory with 0700 when necessary.
func saveTargets(configDir string, tf *targetsFile) error {
	dir, file, err := configPaths(configDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(tf, "", "  ")
	if err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// findProjectFile searches for .acornfox starting at dir and walking up to the
// filesystem root. It returns the file path if found, else empty string.
func findProjectFile(dir string) string {
	cur, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for {
		candidate := filepath.Join(cur, projectFileName)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		cur = parent
	}
}

// loadProject reads the .acornfox for the given start directory (upward
// search). Returns nil (no error) when none exists.
func loadProject(dir string) (*projectFile, string, error) {
	path := findProjectFile(dir)
	if path == "" {
		return nil, "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var pf projectFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, "", err
	}
	return &pf, path, nil
}

// saveProject writes .acornfox into projectDir with 0600. It never stores any
// credential.
func saveProject(projectDir string, pf *projectFile) error {
	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(projectDir, projectFileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var appNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,38}[a-z0-9]$`)

// normalizeAppName lowercases the input and replaces illegal characters with
// "-", collapsing repeats and trimming leading/trailing "-". It returns the
// normalized name and whether it is a valid app name.
func normalizeAppName(raw string) (string, bool) {
	lower := strings.ToLower(raw)
	var b strings.Builder
	prevDash := false
	for _, r := range lower {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
		} else {
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	name := strings.Trim(b.String(), "-")
	if name == "" {
		return "", false
	}
	if appNameRe.MatchString(name) {
		return name, true
	}
	return name, false
}
