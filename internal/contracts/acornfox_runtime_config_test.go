package contracts

import (
	"encoding/json"
	"github.com/open-card/open-card/internal/domain"
	"reflect"
	"strings"
	"testing"
)

func runtimeConfigFixture() (AcornFoxRuntimeConfiguration, AcornFoxRuntimeRequestedResources) {
	return AcornFoxRuntimeConfiguration{
		Entrypoint: []string{"/app/server", "--quiet"}, Command: []string{"serve", "--port=8080"},
		Environment: []RuntimeEnvironmentVariable{{Name: "Z", Kind: RuntimeEnvironmentLiteral, Value: "z"}, {Name: "A", Kind: RuntimeEnvironmentLiteral, Value: "a"}},
		Volumes:     []AcornFoxRuntimeVolume{{Name: "z", MountPath: "/data-z", SizeBytes: 1 << 20}, {Name: "a", MountPath: "/data-a", SizeBytes: 1 << 20}},
		Secrets:     []AcornFoxRuntimeSecretBinding{{Name: "Z", Reference: domain.SecretReference{ID: "sec_z", Name: "z", Provider: "filesystem-secret", Version: "1"}}, {Name: "A", Reference: domain.SecretReference{ID: "sec_a", Name: "a", Provider: "filesystem-secret", Version: "1"}}},
	}, AcornFoxRuntimeRequestedResources{CPUMillis: 500, MemoryBytes: 512 << 20, PIDs: 128, DiskReservationBytes: 1 << 30}
}
func cloneRuntimeConfig(c AcornFoxRuntimeConfiguration) AcornFoxRuntimeConfiguration {
	var out AcornFoxRuntimeConfiguration
	raw, _ := json.Marshal(c)
	_ = json.Unmarshal(raw, &out)
	return out
}
func TestAcornFoxRuntimeConfigCanonicalIdentity(t *testing.T) {
	c, r := runtimeConfigFixture()
	before := cloneRuntimeConfig(c)
	first, err := CanonicalAcornFoxRuntimeConfigDigest(c, r, 8080)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, before) {
		t.Fatal("digest modified input")
	}
	reversed := cloneRuntimeConfig(c)
	reversed.Environment[0], reversed.Environment[1] = reversed.Environment[1], reversed.Environment[0]
	reversed.Volumes[0], reversed.Volumes[1] = reversed.Volumes[1], reversed.Volumes[0]
	reversed.Secrets[0], reversed.Secrets[1] = reversed.Secrets[1], reversed.Secrets[0]
	same, err := CanonicalAcornFoxRuntimeConfigDigest(reversed, r, 8080)
	if err != nil || same != first {
		t.Fatal("unordered settings changed identity", err)
	}
	for name, change := range map[string]func(*AcornFoxRuntimeConfiguration, *AcornFoxRuntimeRequestedResources, *int){
		"argv order": func(c *AcornFoxRuntimeConfiguration, _ *AcornFoxRuntimeRequestedResources, _ *int) {
			c.Command[0], c.Command[1] = c.Command[1], c.Command[0]
		},
		"resources": func(_ *AcornFoxRuntimeConfiguration, r *AcornFoxRuntimeRequestedResources, _ *int) { r.MemoryBytes++ },
		"port":      func(_ *AcornFoxRuntimeConfiguration, _ *AcornFoxRuntimeRequestedResources, p *int) { *p = 9090 },
		"volume size": func(c *AcornFoxRuntimeConfiguration, _ *AcornFoxRuntimeRequestedResources, _ *int) {
			c.Volumes[0].SizeBytes++
		},
		"secret version": func(c *AcornFoxRuntimeConfiguration, _ *AcornFoxRuntimeRequestedResources, _ *int) {
			c.Secrets[0].Reference.Version = "2"
		},
	} {
		t.Run(name, func(t *testing.T) {
			next := cloneRuntimeConfig(c)
			resources := r
			port := 8080
			change(&next, &resources, &port)
			got, err := CanonicalAcornFoxRuntimeConfigDigest(next, resources, port)
			if err != nil || got == first {
				t.Fatal("changed setting did not change identity", err)
			}
		})
	}
	empty := AcornFoxRuntimeConfiguration{}
	slices := AcornFoxRuntimeConfiguration{Entrypoint: []string{}, Command: []string{}, Environment: []RuntimeEnvironmentVariable{}, Volumes: []AcornFoxRuntimeVolume{}, Secrets: []AcornFoxRuntimeSecretBinding{}}
	a, _ := CanonicalAcornFoxRuntimeConfigDigest(empty, r, 0)
	b, _ := CanonicalAcornFoxRuntimeConfigDigest(slices, r, 0)
	if a != b || !empty.Empty() || !slices.Empty() {
		t.Fatal("empty normalization differs")
	}
}
func TestAcornFoxRuntimeConfigRejectsUnsafeInput(t *testing.T) {
	base, r := runtimeConfigFixture()
	changes := map[string]func(*AcornFoxRuntimeConfiguration){
		"sensitive env":    func(c *AcornFoxRuntimeConfiguration) { c.Environment[0].Name = "API_KEY" },
		"duplicate env":    func(c *AcornFoxRuntimeConfiguration) { c.Environment[0].Name = "A" },
		"secret env":       func(c *AcornFoxRuntimeConfiguration) { c.Environment[0].Kind = RuntimeEnvironmentSecret },
		"empty argv":       func(c *AcornFoxRuntimeConfiguration) { c.Command = []string{""} },
		"NUL argv":         func(c *AcornFoxRuntimeConfiguration) { c.Command = []string{"a\x00b"} },
		"long argv":        func(c *AcornFoxRuntimeConfiguration) { c.Command = []string{strings.Repeat("x", 4097)} },
		"nested volumes":   func(c *AcornFoxRuntimeConfiguration) { c.Volumes[0].MountPath = "/data-a/child" },
		"bad secret":       func(c *AcornFoxRuntimeConfiguration) { c.Secrets[0].Reference.ID = "" },
		"duplicate secret": func(c *AcornFoxRuntimeConfiguration) { c.Secrets[0].Name = "A" },
		"large total": func(c *AcornFoxRuntimeConfiguration) {
			c.Command = make([]string, 64)
			for i := range c.Command {
				c.Command[i] = strings.Repeat("x", 4096)
			}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c := cloneRuntimeConfig(base)
			change(&c)
			if _, err := CanonicalAcornFoxRuntimeConfigDigest(c, r, 8080); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	for _, mount := range []string{"/", "/proc", "/proc/a", "/sys", "/dev", "/run", "/var", "/var/run", "/var/run/docker.sock", "/run/secrets/token", "relative", "/data/../data", "/data/", "/data,x", "/data\\x"} {
		t.Run("mount="+mount, func(t *testing.T) {
			c := cloneRuntimeConfig(base)
			c.Volumes[0].MountPath = mount
			if c.Validate() == nil {
				t.Fatal("unsafe mount accepted")
			}
		})
	}
	for _, port := range []int{-1, 65536} {
		if _, err := CanonicalAcornFoxRuntimeConfigDigest(base, r, port); err == nil {
			t.Fatal("bad port accepted")
		}
	}
	for _, resources := range []AcornFoxRuntimeRequestedResources{{}, {CPUMillis: 1000001, MemoryBytes: 1, PIDs: 1, DiskReservationBytes: 1}, {CPUMillis: 1, MemoryBytes: 1 << 51, PIDs: 1, DiskReservationBytes: 1}, {CPUMillis: 1, MemoryBytes: 1, PIDs: 1000001, DiskReservationBytes: 1}} {
		if _, err := CanonicalAcornFoxRuntimeConfigDigest(base, resources, 8080); err == nil {
			t.Fatal("invalid resources accepted")
		}
	}
}

func TestAcornFoxRuntimeConfigResourceAndSecretBoundaries(t *testing.T) {
	c, r := runtimeConfigFixture()
	r.DiskReservationBytes = 2 << 20
	if _, err := CanonicalAcornFoxRuntimeConfigDigest(c, r, 8080); err != nil {
		t.Fatal("exact volume reservation rejected", err)
	}
	r.DiskReservationBytes--
	if _, err := CanonicalAcornFoxRuntimeConfigDigest(c, r, 8080); err == nil {
		t.Fatal("volume total exceeds reservation")
	}
	r.DiskReservationBytes = 1 << 30
	c.Volumes[0].SizeBytes = 1 << 62
	if _, err := CanonicalAcornFoxRuntimeConfigDigest(c, r, 8080); err == nil {
		t.Fatal("overflowing volume size accepted")
	}
	empty := AcornFoxRuntimeConfiguration{}
	r = AcornFoxRuntimeRequestedResources{CPUMillis: 10, MemoryBytes: 6 << 20, PIDs: 1, DiskReservationBytes: 1}
	if _, err := CanonicalAcornFoxRuntimeConfigDigest(empty, r, 0); err != nil {
		t.Fatal("minimum supported resources rejected", err)
	}
	r.CPUMillis = 9
	if _, err := CanonicalAcornFoxRuntimeConfigDigest(empty, r, 0); err == nil {
		t.Fatal("CPU below executable minimum accepted")
	}
	r.CPUMillis = 10
	r.MemoryBytes--
	if _, err := CanonicalAcornFoxRuntimeConfigDigest(empty, r, 0); err == nil {
		t.Fatal("memory below executable minimum accepted")
	}
	for _, invalid := range []string{"x/y", "x\\y", "x\ny", "x\ry", " ", "x y"} {
		for _, field := range []string{"id", "name", "provider", "version"} {
			c, _ := runtimeConfigFixture()
			ref := &c.Secrets[0].Reference
			switch field {
			case "id":
				ref.ID = domain.ID(invalid)
			case "name":
				ref.Name = invalid
			case "provider":
				ref.Provider = invalid
			case "version":
				ref.Version = invalid
			}
			if c.Validate() == nil {
				t.Fatal("unsafe secret component accepted", field)
			}
		}
	}
}
