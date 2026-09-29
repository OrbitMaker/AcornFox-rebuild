package contracts

import (
	"encoding/json"
	"github.com/acornfox/acornfox/internal/domain"
	"strings"
	"testing"
	"time"
)

func TestAcornFoxRuntimeConfigFactPreservesLegacyAndRejectsDrift(t *testing.T) {
	c, r := runtimeConfigFixture()
	digest, err := CanonicalAcornFoxRuntimeConfigDigest(c, r, 8080)
	if err != nil {
		t.Fatal(err)
	}
	image := domain.ImageDigest{Repository: "registry.test/web", Digest: "sha256:" + strings.Repeat("a", 64)}
	release, err := domain.NewRelease("app_1", "legacy", 1, digest, map[string]domain.ImageDigest{"web": image}, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := ProjectAcornFoxRuntimeReleaseFact(*release, "env_1", r, 8080, time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	legacyID, _ := AcornFoxRuntimeDeploymentID(legacy)
	expected := domain.ID("dep_" + acornFoxRuntimeHash(legacy.ApplicationID.String(), legacy.EnvironmentID.String(), legacy.ReleaseID.String(), legacy.ServiceName, legacy.Image.Repository, legacy.Image.Digest, "{500 536870912 128 1073741824}", "8080")[:32])
	if legacyID != expected {
		t.Fatal("legacy deployment identity changed")
	}
	raw, _ := json.Marshal(legacy)
	for _, field := range []string{"schema_version", "configuration", "config_digest"} {
		if strings.Contains(string(raw), field) {
			t.Fatal("legacy wire changed")
		}
	}
	fact, err := ProjectAcornFoxConfiguredRuntimeReleaseFact(*release, "env_1", r, 8080, time.Unix(2, 0), c)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := AcornFoxRuntimeDeploymentID(fact)
	if id == legacyID {
		t.Fatal("new configuration collided with legacy identity")
	}
	c.Command[0] = "caller-changed"
	if fact.Validate() != nil {
		t.Fatal("caller mutation changed accepted fact")
	}
	raw, _ = json.Marshal(fact)
	var restored AcornFoxRuntimeReleaseFact
	if json.Unmarshal(raw, &restored) != nil || restored.Validate() != nil {
		t.Fatal("fact did not survive persistence")
	}
	restoredID, _ := AcornFoxRuntimeDeploymentID(restored)
	if restoredID != id {
		t.Fatal("persistence changed identity")
	}
	for name, change := range map[string]func(*AcornFoxRuntimeReleaseFact){
		"version":        func(f *AcornFoxRuntimeReleaseFact) { f.SchemaVersion = 1 },
		"digest":         func(f *AcornFoxRuntimeReleaseFact) { f.ConfigDigest = "sha256:" + strings.Repeat("0", 64) },
		"missing config": func(f *AcornFoxRuntimeReleaseFact) { f.Configuration = nil },
		"resource":       func(f *AcornFoxRuntimeReleaseFact) { f.Resources.MemoryBytes++ },
		"port":           func(f *AcornFoxRuntimeReleaseFact) { f.ContainerPort++ },
		"argv":           func(f *AcornFoxRuntimeReleaseFact) { f.Configuration.Command[0] = "drift" },
	} {
		t.Run(name, func(t *testing.T) {
			var changed AcornFoxRuntimeReleaseFact
			_ = json.Unmarshal(raw, &changed)
			change(&changed)
			if changed.Validate() == nil {
				t.Fatal("drift accepted")
			}
		})
	}
	release.ConfigDigest = "sha256:" + strings.Repeat("b", 64)
	if _, err := ProjectAcornFoxConfiguredRuntimeReleaseFact(*release, "env_1", r, 8080, time.Unix(2, 0), *fact.Configuration); err == nil {
		t.Fatal("release/config mismatch accepted")
	}
}
