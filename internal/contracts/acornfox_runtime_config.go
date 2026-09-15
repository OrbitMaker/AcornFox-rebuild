package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/open-card/open-card/internal/domain"
)

// AcornFoxRuntimeConfiguration is the immutable, single-container configuration.
// It contains no host paths, arbitrary Docker flags, or secret values.
type AcornFoxRuntimeConfiguration struct {
	Entrypoint  []string                       `json:"entrypoint,omitempty"`
	Command     []string                       `json:"command,omitempty"`
	Environment []RuntimeEnvironmentVariable   `json:"environment,omitempty"`
	Volumes     []AcornFoxRuntimeVolume        `json:"volumes,omitempty"`
	Secrets     []AcornFoxRuntimeSecretBinding `json:"secrets,omitempty"`
}

type AcornFoxRuntimeVolume struct {
	Name      string `json:"name"`
	MountPath string `json:"mount_path"`
	SizeBytes int64  `json:"size_bytes"`
	ReadOnly  bool   `json:"read_only,omitempty"`
}

// Syntax validation does not prove application ownership or revocation state.
// A caller must obtain that proof before resolving a runtime secret reference.
type AcornFoxRuntimeSecretBinding struct {
	Name      string                 `json:"name"`
	Reference domain.SecretReference `json:"secret_ref"`
}

var acornFoxEnvironmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
var acornFoxSecretComponent = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@+\-]{0,255}$`)
var acornFoxVolumeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)

func (c AcornFoxRuntimeConfiguration) Empty() bool {
	return len(c.Entrypoint)+len(c.Command)+len(c.Environment)+len(c.Volumes)+len(c.Secrets) == 0
}

func (c AcornFoxRuntimeConfiguration) Validate() error {
	for _, argv := range [][]string{c.Entrypoint, c.Command} {
		if len(argv) > 64 {
			return fmt.Errorf("runtime argument count is invalid")
		}
		for _, arg := range argv {
			if arg == "" || len(arg) > 4096 || strings.ContainsRune(arg, 0) {
				return fmt.Errorf("runtime argument is invalid")
			}
		}
	}
	if len(c.Environment) > 128 || len(c.Volumes) > 16 || len(c.Secrets) > 32 {
		return fmt.Errorf("runtime configuration has too many entries")
	}
	seen := map[string]bool{}
	for _, v := range c.Environment {
		if !acornFoxEnvironmentName.MatchString(v.Name) || seen[v.Name] || v.Kind != RuntimeEnvironmentLiteral || len(v.Value) > 8192 || v.Validate() != nil {
			return fmt.Errorf("runtime environment is invalid")
		}
		seen[v.Name] = true
	}
	seen = map[string]bool{}
	for i, v := range c.Volumes {
		if !acornFoxVolumeName.MatchString(v.Name) || seen[v.Name] || v.SizeBytes <= 0 || v.SizeBytes > 1<<50 || !acornFoxDataMountAllowed(v.MountPath) {
			return fmt.Errorf("runtime volume is invalid")
		}
		seen[v.Name] = true
		for _, other := range c.Volumes[:i] {
			if acornFoxPathsOverlap(v.MountPath, other.MountPath) {
				return fmt.Errorf("runtime volume paths overlap")
			}
		}
	}
	seen = map[string]bool{}
	for _, s := range c.Secrets {
		if !acornFoxEnvironmentName.MatchString(s.Name) || seen[s.Name] || s.Reference.Validate() != nil {
			return fmt.Errorf("runtime secret reference is invalid")
		}
		for _, v := range []string{s.Reference.ID.String(), s.Reference.Name, s.Reference.Provider} {
			if !acornFoxSecretComponent.MatchString(v) || strings.ContainsAny(v, "\\/\x00\r\n") {
				return fmt.Errorf("runtime secret reference is invalid")
			}
		}
		if v := s.Reference.Version; v != "" && (!acornFoxSecretComponent.MatchString(v) || strings.ContainsAny(v, "\\/\x00\r\n")) {
			return fmt.Errorf("runtime secret version is invalid")
		}
		seen[s.Name] = true
	}
	return nil
}

func acornFoxPathsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func acornFoxDataMountAllowed(value string) bool {
	if len(value) > 512 || value == "/" || !path.IsAbs(value) || path.Clean(value) != value || strings.ContainsAny(value, "\x00\\,") {
		return false
	}
	for _, protected := range []string{"/proc", "/sys", "/dev", "/run/secrets", "/var/run/docker.sock", "/run/docker.sock"} {
		if acornFoxPathsOverlap(value, protected) {
			return false
		}
	}
	return true
}

// CanonicalAcornFoxRuntimeConfigDigest preserves argv order and does not mutate
// input slices. Resources and port participate in the same immutable identity.
func CanonicalAcornFoxRuntimeConfigDigest(c AcornFoxRuntimeConfiguration, r AcornFoxRuntimeRequestedResources, port int) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if r.Validate() != nil || r.CPUMillis < 10 || r.MemoryBytes < 6<<20 || r.CPUMillis > 1000000 || r.MemoryBytes > 1<<50 || r.PIDs > 1000000 || r.DiskReservationBytes > 1<<50 || port < 0 || port > 65535 {
		return "", fmt.Errorf("runtime resources or port are invalid")
	}
	// DiskReservationBytes accounts for this runtime's total requested capacity,
	// including persistent volumes. It is not a filesystem quota.
	var volumeBytes int64
	for _, v := range c.Volumes {
		if v.SizeBytes > r.DiskReservationBytes-volumeBytes {
			return "", fmt.Errorf("runtime volumes exceed disk reservation")
		}
		volumeBytes += v.SizeBytes
	}
	c.Environment = append([]RuntimeEnvironmentVariable(nil), c.Environment...)
	c.Volumes = append([]AcornFoxRuntimeVolume(nil), c.Volumes...)
	c.Secrets = append([]AcornFoxRuntimeSecretBinding(nil), c.Secrets...)
	sort.Slice(c.Environment, func(i, j int) bool { return c.Environment[i].Name < c.Environment[j].Name })
	sort.Slice(c.Volumes, func(i, j int) bool { return c.Volumes[i].Name < c.Volumes[j].Name })
	sort.Slice(c.Secrets, func(i, j int) bool { return c.Secrets[i].Name < c.Secrets[j].Name })
	wire := struct {
		Configuration AcornFoxRuntimeConfiguration      `json:"configuration"`
		Resources     AcornFoxRuntimeRequestedResources `json:"resources"`
		ContainerPort int                               `json:"container_port"`
	}{c, r, port}
	raw, err := json.Marshal(wire)
	if err != nil || len(raw) > 65536 {
		return "", fmt.Errorf("runtime configuration exceeds payload limit")
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// AcornFoxRuntimeInput is the user-facing configuration; omitted resources use
// the platform defaults with declared volume capacity added to the reservation.
type AcornFoxRuntimeInput struct {
	AcornFoxRuntimeConfiguration
	Resources *AcornFoxRuntimeRequestedResources `json:"resources,omitempty"`
}
