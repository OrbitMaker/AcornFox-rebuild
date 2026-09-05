package acornfoxrelease

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPlanCloseReleasesSharedCachePinsWithoutDeletingCaches(t *testing.T) {
	root, cacheRoot, _, _, _ := syntheticGoReleaseRepository(t)
	_, cache, _, err := sealedGoEnvironment(root, cacheRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.close()
	if err := os.WriteFile(filepath.Join(cache.goPath, "ordinary-cache-write"), []byte("cache"), 0600); err != nil {
		t.Fatal(err)
	}
	if !cache.valid() {
		t.Fatal("normal cache writes changed identity")
	}
	plan := GoBuildPlanV1{cache: cache}
	copy := plan
	if err := plan.Close(); err != nil {
		t.Fatal(err)
	}
	if cache.valid() || copy.cache.valid() {
		t.Fatal("a plan copy retained closed cache authority")
	}
	for _, pin := range []*directoryPin{cache.taskPin, cache.goPin, cache.modPin} {
		if _, err := pin.file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("directory handle remained open")
		}
		if _, err := os.Stat(pin.path); err != nil {
			t.Fatal("Close removed caller-owned cache")
		}
	}
	if err := copy.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNPMCacheRejectsDeletedAndRecreatedDirectory(t *testing.T) {
	root := buildTaskRoot(t)
	cache, err := pinNPMCache(root)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.pin.close()
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if cache.valid() {
		t.Fatal("replacement cache reused directory authority")
	}
}

func TestFailedStageCleanupPreservesRecreatedDirectoryAndClosesPins(t *testing.T) {
	for _, kind := range []string{"go-failure", "web-close"} {
		t.Run(kind, func(t *testing.T) {
			parent := buildTaskRoot(t)
			root, err := os.MkdirTemp(parent, "stage-")
			if err != nil {
				t.Fatal(err)
			}
			parentPin, err := pinDirectory(parent)
			if err != nil {
				t.Fatal(err)
			}
			defer parentPin.close()
			stagePin, err := pinDirectory(root)
			if err != nil {
				t.Fatal(err)
			}
			defer stagePin.close()
			if err := os.Remove(root); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(root, "foreign")
			if err := os.WriteFile(sentinel, []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "go-failure" {
				cleanupFailedStage(&GoBinaryStageV1{root: root, parent: parent, parentPin: parentPin, stagePin: stagePin}, ErrGoStage)
			} else {
				if err := (&WebAssetStageV1{root: root, parent: parent, parentPin: parentPin, stagePin: stagePin}).Close(); err == nil {
					t.Fatal("replacement stage accepted")
				}
			}
			if raw, err := os.ReadFile(sentinel); err != nil || string(raw) != "preserve" {
				t.Fatal("foreign directory was removed")
			}
			for _, pin := range []*directoryPin{parentPin, stagePin} {
				if _, err := pin.file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("failure leaked a directory handle")
				}
			}
		})
	}
}
