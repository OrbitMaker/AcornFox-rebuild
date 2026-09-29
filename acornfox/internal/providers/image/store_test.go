package image

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

func TestStoreOpenPersistsVerifiedReadOnlyArchive(t *testing.T) {
	root := t.TempDir()
	provider := newTestProvider(t, root)
	image := testImage("a")
	content := []byte("oci-archive-content")
	stored, err := provider.StoreOCI(context.Background(), storeRequest(image, "build-001", "store-001", content))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Image != image || stored.SizeBytes != int64(len(content)) || stored.StorageRef == "" {
		t.Fatalf("incomplete store result: %#v", stored)
	}
	wantDigest := "sha256:" + hexDigest(content)
	if stored.Evidence.Digest != wantDigest || len(stored.Evidence.Refs) != 1 || stored.Evidence.Refs[0].Digest != wantDigest {
		t.Fatalf("content evidence is incomplete: %#v", stored.Evidence)
	}
	archivePath, _, err := provider.paths(image)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("stored OCI archive is writable: %v", info.Mode())
	}

	// A fresh Provider proves metadata and bytes survived the original process.
	reopened := newTestProvider(t, root)
	reader, opened, err := reopened.OpenOCI(context.Background(), image, operation("open-001"))
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, content) {
		t.Fatalf("opened OCI archive mismatch: %q %v %v", got, readErr, closeErr)
	}
	if opened.StorageRef != stored.StorageRef || opened.Evidence.Digest != wantDigest {
		t.Fatalf("open result lost persisted evidence: %#v", opened)
	}
}

func TestStoreRejectsConflictsAndUnsafeInputs(t *testing.T) {
	provider := newTestProvider(t, t.TempDir())
	image := testImage("b")
	if _, err := provider.StoreOCI(context.Background(), storeRequest(image, "build-002", "same-key", []byte("first"))); err != nil {
		t.Fatal(err)
	}
	_, err := provider.StoreOCI(context.Background(), storeRequest(testImage("c"), "build-003", "same-key", []byte("second")))
	assertProviderCode(t, err, contracts.ErrConflict)
	_, err = provider.StoreOCI(context.Background(), storeRequest(image, "build-004", "different-key", []byte("different")))
	assertProviderCode(t, err, contracts.ErrConflict)

	for _, request := range []contracts.StoreOCIRequest{
		storeRequest(image, "../escape", "unsafe-storage-key", []byte("x")),
		storeRequest(domain.ImageDigest{Repository: "../../escape", Digest: image.Digest}, "build-005", "unsafe-repository", []byte("x")),
		storeRequest(image, "build-007", "empty", nil),
	} {
		_, err := provider.StoreOCI(context.Background(), request)
		assertProviderCode(t, err, contracts.ErrValidation)
	}
	tagged := testImage("d")
	tagged.ResolvedTag = "stable"
	result, err := provider.StoreOCI(context.Background(), storeRequest(tagged, "app_1/src_1/web", "resolved-tag", []byte("tagged")))
	if err != nil {
		t.Fatal(err)
	}
	if result.Image.ResolvedTag != "" {
		t.Fatalf("stored immutable image retained mutable tag annotation: %#v", result.Image)
	}
	_, err = provider.Resolve(context.Background(), contracts.ImageResolveRequest{Repository: image.Repository, Tag: "latest", Operation: operation("resolve-tag")})
	assertProviderCode(t, err, contracts.ErrUnsupportedCapability)
}

func TestDeleteFailsClosedForRetainedRunningAndRollbackReferences(t *testing.T) {
	provider := newTestProvider(t, t.TempDir())
	image := testImage("d")
	if _, err := provider.StoreOCI(context.Background(), storeRequest(image, "build-008", "store-delete", []byte("archive"))); err != nil {
		t.Fatal(err)
	}
	if err := provider.Retain(context.Background(), image, operation("retain")); err != nil {
		t.Fatal(err)
	}
	assertDeleteConflict(t, provider, image, "delete-retained")
	if err := provider.SetRetained(context.Background(), image, operation("unretain"), false); err != nil {
		t.Fatal(err)
	}
	if err := provider.SetRunning(context.Background(), image, operation("running"), true); err != nil {
		t.Fatal(err)
	}
	assertDeleteConflict(t, provider, image, "delete-running")
	if err := provider.SetRunning(context.Background(), image, operation("stopped"), false); err != nil {
		t.Fatal(err)
	}
	if err := provider.SetRollback(context.Background(), image, operation("rollback"), true); err != nil {
		t.Fatal(err)
	}
	assertDeleteConflict(t, provider, image, "delete-rollback")
	if err := provider.SetRollback(context.Background(), image, operation("no-rollback"), false); err != nil {
		t.Fatal(err)
	}
	if err := provider.Delete(context.Background(), image, operation("delete")); err != nil {
		t.Fatal(err)
	}
	_, _, err := provider.OpenOCI(context.Background(), image, operation("open-after-delete"))
	assertProviderCode(t, err, contracts.ErrNotFound)
}

func TestOpenRejectsTamperedSymlinkAndContent(t *testing.T) {
	root := t.TempDir()
	provider := newTestProvider(t, root)
	image := testImage("e")
	if _, err := provider.StoreOCI(context.Background(), storeRequest(image, "build-009", "store-tamper", []byte("archive"))); err != nil {
		t.Fatal(err)
	}
	archivePath, recordPath, err := provider.paths(image)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(recordPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(archivePath, recordPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, _, err = provider.OpenOCI(context.Background(), image, operation("open-symlink"))
	assertProviderCode(t, err, contracts.ErrUnavailable)
	if err := os.Remove(recordPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = provider.OpenOCI(context.Background(), image, operation("open-tampered-record"))
	assertProviderCode(t, err, contracts.ErrUnavailable)
}

func TestOpenRejectsTamperedArchiveContent(t *testing.T) {
	provider := newTestProvider(t, t.TempDir())
	image := testImage("1")
	if _, err := provider.StoreOCI(context.Background(), storeRequest(image, "build-010", "store-content-tamper", []byte("archive"))); err != nil {
		t.Fatal(err)
	}
	archivePath, _, err := provider.paths(image)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(archivePath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archivePath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(archivePath, 0o400); err != nil {
		t.Fatal(err)
	}
	_, _, err = provider.OpenOCI(context.Background(), image, operation("open-tampered-content"))
	assertProviderCode(t, err, contracts.ErrUnavailable)
}

func TestStoredOCIIsImmutableAndGroupReadableByRuntimeAgent(t *testing.T) {
	provider := newTestProvider(t, t.TempDir())
	image := testImage("7")
	if _, err := provider.StoreOCI(context.Background(), storeRequest(image, "build-group-read", "store-group-read", []byte("archive"))); err != nil {
		t.Fatal(err)
	}
	archivePath, recordPath, err := provider.paths(image)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{archivePath: 0o440, recordPath: 0o640, filepath.Dir(archivePath): 0o750, filepath.Dir(recordPath): 0o750} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("%s mode = %o, want %o", path, got, want)
		}
	}
}

func TestStoreConcurrentCallsAreRaceSafeAndIdempotent(t *testing.T) {
	provider := newTestProvider(t, t.TempDir())
	image := testImage("f")
	content := []byte("same archive from concurrent builders")
	const workers = 24
	errs := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			_, err := provider.StoreOCI(context.Background(), storeRequest(image, "build-concurrent", "store-concurrent", content))
			errs <- err
		}(index)
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestStoreConcurrentProvidersNeverOverwriteAnImmutableDigest(t *testing.T) {
	root := t.TempDir()
	first := newTestProvider(t, root)
	second := newTestProvider(t, root)
	image := testImage("1")
	start := make(chan struct{})
	errs := make(chan error, 2)
	for index, provider := range []*Provider{first, second} {
		content := []byte("first")
		if index == 1 {
			content = []byte("second")
		}
		go func(provider *Provider, content []byte) {
			<-start
			_, err := provider.StoreOCI(context.Background(), storeRequest(image, "cross-process", "cross-process-"+string(content), content))
			errs <- err
		}(provider, content)
	}
	close(start)
	var success, conflict int
	for range 2 {
		err := <-errs
		if err == nil {
			success++
			continue
		}
		var providerError *contracts.ProviderError
		if errors.As(err, &providerError) && providerError.Code == contracts.ErrConflict {
			conflict++
			continue
		}
		t.Fatalf("unexpected concurrent-store error: %v", err)
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("want one store and one conflict, got success=%d conflict=%d", success, conflict)
	}
}

func newTestProvider(t *testing.T, root string) *Provider {
	t.Helper()
	provider, err := New(Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func testImage(character string) domain.ImageDigest {
	return domain.ImageDigest{Repository: "registry.example.test/open-card/app", Digest: "sha256:" + strings.Repeat(character, 64)}
}

func storeRequest(image domain.ImageDigest, storageKey, key string, archive []byte) contracts.StoreOCIRequest {
	return contracts.StoreOCIRequest{Image: image, StorageKey: storageKey, Archive: bytes.NewReader(archive), Operation: operation(key)}
}

func operation(key string) contracts.OperationContext {
	return contracts.OperationContext{IdempotencyKey: key}
}

func assertDeleteConflict(t *testing.T, provider *Provider, image domain.ImageDigest, key string) {
	t.Helper()
	assertProviderCode(t, provider.Delete(context.Background(), image, operation(key)), contracts.ErrConflict)
}

func assertProviderCode(t *testing.T, err error, want contracts.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error, got nil", want)
	}
	var providerError *contracts.ProviderError
	if !errors.As(err, &providerError) || providerError.Code != want {
		t.Fatalf("expected %s provider error, got %T: %v", want, err, err)
	}
}

func hexDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return fmt.Sprintf("%x", sum[:])
}
