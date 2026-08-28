package imagegc

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

type dockerGCRunner struct {
	mu        sync.Mutex
	calls     [][]string
	responses map[string]string
	fail      map[string]error
}

func TestDockerInventoryAcceptsOnlyDigestAuthorizedByDurableSnapshotWithoutImageLabels(t *testing.T) {
	prefix := "opencard-mvp-fa8f8eab"
	image := domain.ImageDigest{Repository: "open-card.local/app/web", Digest: "sha256:" + strings.Repeat("b", 64)}
	runner := &dockerGCRunner{responses: map[string]string{
		"image ls":      "",
		"image inspect": `{"Id":"sha256:local","Created":"2026-08-24T01:00:00Z","Size":10,"RepoDigests":["open-card.local/app/web@` + image.Digest + `"],"Config":{"Labels":{}}}`,
		"volume ls":     "",
		"ps":            "",
	}, fail: map[string]error{}}
	snapshot := dockerGCSnapshot{releases: []ReleaseRecord{{ID: "release-authorized", Status: ReleaseFailed, CreatedAt: time.Now().UTC(), Images: []domain.ImageDigest{image}}}}
	inv, err := NewDockerInventory(DockerConfig{TaskPrefix: prefix, DiskPath: "/tmp", Runner: runner, Snapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := inv.ListResources(context.Background())
	if err != nil || len(resources) != 1 || resources[0].Image != image {
		t.Fatalf("snapshot-authorized image missing: resources=%#v err=%v", resources, err)
	}
	if err := inv.DeleteImage(context.Background(), image); err != nil {
		t.Fatal(err)
	}
}

func TestDockerInventoryFallsBackToUntaggedDigestForSnapshotResource(t *testing.T) {
	prefix := "opencard-mvp-fa8f8eab"
	image := domain.ImageDigest{Repository: "open-card.local/app/group/web", Digest: "sha256:" + strings.Repeat("d", 64)}
	repositoryInspect := strings.Join([]string{"image", "inspect", "--format", "{{json .}}", image.Repository + "@" + image.Digest}, " ")
	digestInspect := strings.Join([]string{"image", "inspect", "--format", "{{json .}}", image.Digest}, " ")
	runner := &dockerGCRunner{responses: map[string]string{
		"image ls":    "",
		"volume ls":   "",
		"ps --filter": "",
		digestInspect: `{"Id":"` + image.Digest + `","Created":"2026-08-24T01:00:00Z","Size":10,"RepoDigests":[],"Config":{"Labels":{}}}`,
	}, fail: map[string]error{repositoryInspect: errors.New("repository digest is intentionally untagged")}}
	snapshot := dockerGCSnapshot{releases: []ReleaseRecord{{ID: "release-untagged", Status: ReleaseCurrent, CreatedAt: time.Now().UTC(), Images: []domain.ImageDigest{image}}}}
	inv, err := NewDockerInventory(DockerConfig{TaskPrefix: prefix, DiskPath: "/tmp", Runner: runner, Snapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := inv.ListResources(context.Background())
	if err != nil || len(resources) != 1 || resources[0].Image != image {
		t.Fatalf("untagged snapshot resource missing: resources=%#v err=%v", resources, err)
	}
}

func TestDockerInventoryProtectsUntaggedRunningBuildImageBySnapshotDigest(t *testing.T) {
	prefix := "opencard-mvp-fa8f8eab"
	image := domain.ImageDigest{Repository: "open-card.local/app/group/web", Digest: "sha256:" + strings.Repeat("c", 64)}
	runner := &dockerGCRunner{responses: map[string]string{
		"ps --filter":       `{"ID":"container-1"}` + "\n",
		"container inspect": `{"Image":"` + image.Digest + `","Config":{"Labels":{"open-card.managed":"true","open-card.task-prefix":"` + prefix + `","open-card.deployment-id":"dep-1"}}}`,
		"image inspect":     `{"Id":"` + image.Digest + `","Created":"2026-08-24T01:00:00Z","Size":10,"RepoDigests":[],"Config":{"Labels":{}}}`,
	}, fail: map[string]error{}}
	snapshot := dockerGCSnapshot{releases: []ReleaseRecord{{ID: "release-running", Status: ReleaseCurrent, CreatedAt: time.Now().UTC(), Images: []domain.ImageDigest{image}}}}
	inv, err := NewDockerInventory(DockerConfig{TaskPrefix: prefix, DiskPath: "/tmp", Runner: runner, Snapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	uses, err := inv.ListRuntimeUse(context.Background())
	if err != nil || len(uses) != 1 || uses[0].Image != image || !uses[0].InUse {
		t.Fatalf("untagged running image was not protected: uses=%#v err=%v", uses, err)
	}
}

func (f *dockerGCRunner) Run(_ context.Context, _ string, args []string, stdout, _ io.Writer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string(nil), args...))
	key := strings.Join(args[:minGC(2, len(args))], " ")
	fullKey := strings.Join(args, " ")
	if err := f.fail[fullKey]; err != nil {
		return err
	}
	if err := f.fail[key]; err != nil {
		return err
	}
	response, ok := f.responses[fullKey]
	if !ok {
		response = f.responses[key]
	}
	_, _ = io.WriteString(stdout, response)
	return nil
}
func (f *dockerGCRunner) snapshot() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.calls...)
}
func minGC(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type dockerGCSnapshot struct {
	releases []ReleaseRecord
	builds   []BuildRecord
}

func (f dockerGCSnapshot) ListGCReleases(context.Context) ([]ReleaseRecord, error) {
	return f.releases, nil
}
func (f dockerGCSnapshot) ListGCBuilds(context.Context) ([]BuildRecord, error) { return f.builds, nil }

func gcDockerImageFacts(prefix string) string {
	return `{"Id":"sha256:abc","Created":"2026-08-24T01:00:00Z","Size":10,"RepoDigests":["opencard/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"Config":{"Labels":{"open-card.managed":"true","open-card.task-prefix":"` + prefix + `"}}}`
}

func TestDockerInventoryReadsOnlyTaskLabelledResourcesAndNeverDeletesVolumes(t *testing.T) {
	prefix := "opencard-mvp-fa8f8eab"
	runner := &dockerGCRunner{responses: map[string]string{
		"image ls":      `{"Repository":"opencard/app","Digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}` + "\n",
		"image inspect": gcDockerImageFacts(prefix),
		"volume ls":     `{"Name":"opencard-mvp-fa8f8eab-volume-data"}` + "\n",
		"ps":            "",
	}, fail: map[string]error{}}
	inv, err := NewDockerInventory(DockerConfig{TaskPrefix: prefix, DiskPath: "/tmp", Runner: runner, Snapshot: dockerGCSnapshot{}})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := inv.ListResources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 2 || resources[0].Kind != ResourceImage || resources[1].Kind != ResourceVolume {
		t.Fatalf("resources=%#v", resources)
	}
	if err := inv.DeleteImage(context.Background(), resources[0].Image); err != nil {
		t.Fatal(err)
	}
	calls := runner.snapshot()
	joined := make([]string, 0, len(calls))
	for _, call := range calls {
		joined = append(joined, strings.Join(call, " "))
	}
	all := strings.Join(joined, "\n")
	if !strings.Contains(all, "--filter label=open-card.task-prefix="+prefix) || strings.Contains(all, "volume rm") || !strings.Contains(all, "image rm opencard/app@sha256:") {
		t.Fatalf("unsafe docker calls: %s", all)
	}
}

func TestDockerInventoryFailsClosedOnOwnershipChangeAndDoesNotRemoveImage(t *testing.T) {
	prefix := "opencard-mvp-fa8f8eab"
	runner := &dockerGCRunner{responses: map[string]string{"image inspect": `{"Id":"sha256:abc","Size":10,"Config":{"Labels":{"open-card.managed":"true","open-card.task-prefix":"other"}}}`}, fail: map[string]error{}}
	inv, err := NewDockerInventory(DockerConfig{TaskPrefix: prefix, DiskPath: "/tmp", Runner: runner, Snapshot: dockerGCSnapshot{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.DeleteImage(context.Background(), gcImage("foreign", 11)); err == nil {
		t.Fatal("foreign image deletion was accepted")
	}
	for _, call := range runner.snapshot() {
		if len(call) >= 3 && call[0] == "image" && call[1] == "rm" {
			t.Fatalf("foreign image reached rm: %#v", call)
		}
	}
}

func TestDockerInventoryRejectsIncompleteConfiguration(t *testing.T) {
	for _, config := range []DockerConfig{{TaskPrefix: "../bad", Snapshot: dockerGCSnapshot{}}, {TaskPrefix: "ok", DiskPath: "relative", Snapshot: dockerGCSnapshot{}}, {TaskPrefix: "ok", Snapshot: nil}} {
		if _, err := NewDockerInventory(config); err == nil {
			t.Fatalf("unsafe config accepted: %#v", config)
		}
	}
}
