package secret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const canary = "m1-secret-canary-value-7f2c"

func testProvider(t *testing.T, now time.Time, ttl time.Duration) (*Provider, string, string, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "vault")
	materialRoot := filepath.Join(base, "material")
	keyPath := filepath.Join(base, "master.key")
	provider, err := New(Config{Root: root, MaterialRoot: materialRoot, MasterKeyPath: keyPath, MaterialTTL: ttl, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	return provider, root, materialRoot, keyPath
}

func testReference(id string) domain.SecretReference {
	return domain.SecretReference{ID: domain.ID(id), Name: "registry_token", Provider: "local", Version: "v1"}
}

func operation(key string) contracts.OperationContext {
	return contracts.OperationContext{IdempotencyKey: key}
}

func TestStoreResolveRevokeNeverPersistsCanary(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	provider, root, materialRoot, keyPath := testProvider(t, now, time.Minute)
	reference := testReference("secret_1")
	value := []byte(canary)

	stored, err := provider.Store(context.Background(), contracts.SecretRequest{Reference: reference, Value: value, Operation: operation("store-1")})
	if err != nil {
		t.Fatal(err)
	}
	if stored != reference {
		t.Fatalf("Store returned a non-reference result: %#v", stored)
	}
	assertNoCanary(t, canary, root, keyPath)

	material, err := provider.ResolveBuildSecret(context.Background(), reference, operation("resolve-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !within(materialRoot, material.Path) || material.Path == materialRoot {
		t.Fatalf("material path escaped its boundary: %q", material.Path)
	}
	info, err := os.Lstat(material.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || info.Mode().Perm() != 0o400 {
		t.Fatalf("material permissions/type are unsafe: %s", info.Mode())
	}
	contents, err := os.ReadFile(material.Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != canary {
		t.Fatalf("materialized content mismatch: %q", contents)
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), canary) || strings.Contains(string(encoded), material.Path) {
		t.Fatalf("BuildSecretMaterial serialized sensitive data: %s", encoded)
	}
	assertNoCanary(t, canary, root, keyPath)

	retry, err := provider.ResolveBuildSecret(context.Background(), reference, operation("resolve-1"))
	if err != nil || retry.Path != material.Path || retry.MountID != material.MountID {
		t.Fatalf("same resolve operation was not idempotent: %#v %v", retry, err)
	}
	if err := provider.RevokeBuildSecret(context.Background(), material, operation("revoke-1")); err != nil {
		t.Fatal(err)
	}
	if err := provider.RevokeBuildSecret(context.Background(), material, operation("revoke-1")); err != nil {
		t.Fatalf("revoke was not idempotent: %v", err)
	}
	if _, err := os.Stat(material.Path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("material file was not removed: %v", err)
	}
	if _, err := os.Stat(materialMetadataPath(material.Path)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("material metadata was not removed: %v", err)
	}
	assertNoCanary(t, canary, root, materialRoot, keyPath)
}

func TestRevokeBuildSecretHonorsContextWhileProviderLockIsHeld(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	provider, _, _, _ := testProvider(t, now, time.Minute)
	reference := testReference("secret_revoke_context")
	if _, err := provider.Store(context.Background(), contracts.SecretRequest{Reference: reference, Value: []byte("secret"), Operation: operation("store-revoke-context")}); err != nil {
		t.Fatal(err)
	}
	material, err := provider.ResolveBuildSecret(context.Background(), reference, operation("resolve-revoke-context"))
	if err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = provider.RevokeBuildSecret(ctx, material, contracts.OperationContext{IdempotencyKey: "revoke-context", Deadline: time.Now().Add(30 * time.Millisecond)})
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("revoke waited behind held mutex for %v", elapsed)
	}
	if !hasCode(err, contracts.ErrTimeout) {
		t.Fatalf("revoke error=%v", err)
	}
}

func TestEdgeCaddyCertificateObservationCanNeverBeResolvedAsASecret(t *testing.T) {
	provider, _, _, _ := testProvider(t, time.Unix(1_700_000_000, 0).UTC(), time.Minute)
	reference := domain.SecretReference{ID: "edge-caddy-observation:sha256:deadbeef", Name: "edge-observation", Provider: "edge-caddy"}
	if _, err := provider.ResolveBuildSecret(context.Background(), reference, operation("edge-observation-resolve")); !hasCode(err, contracts.ErrForbidden) {
		t.Fatalf("edge observation resolve error=%v", err)
	}
	if _, err := provider.Mount(context.Background(), contracts.SecretRequest{Reference: reference, Operation: operation("edge-observation-mount")}); !hasCode(err, contracts.ErrForbidden) {
		t.Fatalf("edge observation mount error=%v", err)
	}
}

func TestSecretProviderMountAndRevokeAreReferenceOnly(t *testing.T) {
	provider, _, materialRoot, _ := testProvider(t, time.Unix(1_700_000_000, 0).UTC(), time.Minute)
	reference := testReference("secret_1")
	if _, err := provider.Store(context.Background(), contracts.SecretRequest{Reference: reference, Value: []byte(canary), Operation: operation("store")}); err != nil {
		t.Fatal(err)
	}
	mount, err := provider.Mount(context.Background(), contracts.SecretRequest{Reference: reference, Operation: operation("mount")})
	if err != nil {
		t.Fatal(err)
	}
	if mount.MountID == "" || mount.Reference != reference || mount.ExpiresAt.IsZero() {
		t.Fatalf("mount did not return a reference-only handle: %#v", mount)
	}
	encoded, err := json.Marshal(mount)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), canary) || strings.Contains(string(encoded), materialRoot) {
		t.Fatalf("mount serialized sensitive material: %s", encoded)
	}
	if err := provider.Revoke(context.Background(), mount, operation("revoke")); err != nil {
		t.Fatal(err)
	}
	if err := provider.Revoke(context.Background(), mount, operation("revoke")); err != nil {
		t.Fatalf("reference-only revoke was not idempotent: %v", err)
	}
}

func TestStoreAndResolveIdempotencyAndConflict(t *testing.T) {
	provider, _, _, _ := testProvider(t, time.Unix(1_700_000_000, 0).UTC(), time.Minute)
	reference := testReference("secret_1")
	request := contracts.SecretRequest{Reference: reference, Value: []byte(canary), Operation: operation("same-store")}
	if _, err := provider.Store(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Store(context.Background(), request); err != nil {
		t.Fatalf("same Store operation was not idempotent: %v", err)
	}
	changed := request
	changed.Value = []byte("different-value")
	if _, err := provider.Store(context.Background(), changed); !hasCode(err, contracts.ErrConflict) {
		t.Fatalf("different Store input did not conflict: %v", err)
	}
	otherOperation := request
	otherOperation.Operation = operation("different-store")
	otherOperation.Value = []byte("different-value")
	if _, err := provider.Store(context.Background(), otherOperation); !hasCode(err, contracts.ErrConflict) {
		t.Fatalf("immutable reference accepted changed content: %v", err)
	}

	material, err := provider.ResolveBuildSecret(context.Background(), reference, operation("same-resolve"))
	if err != nil {
		t.Fatal(err)
	}
	otherReference := testReference("secret_2")
	if _, err := provider.ResolveBuildSecret(context.Background(), otherReference, operation("same-resolve")); !hasCode(err, contracts.ErrConflict) {
		t.Fatalf("different Resolve input did not conflict: %v", err)
	}
	if err := provider.RevokeBuildSecret(context.Background(), material, operation("same-revoke")); err != nil {
		t.Fatal(err)
	}
	otherMaterial := material
	otherMaterial.MountID = "mount_" + strings.Repeat("a", 48)
	if err := provider.RevokeBuildSecret(context.Background(), otherMaterial, operation("same-revoke")); !hasCode(err, contracts.ErrConflict) {
		t.Fatalf("different Revoke input did not conflict: %v", err)
	}
}

func TestEncryptionUsesRandomNonceAndMetadataHasNoPlaintext(t *testing.T) {
	provider, root, _, keyPath := testProvider(t, time.Unix(1_700_000_000, 0).UTC(), time.Minute)
	first := testReference("secret_1")
	second := testReference("secret_2")
	if _, err := provider.Store(context.Background(), contracts.SecretRequest{Reference: first, Value: []byte(canary), Operation: operation("store-first")}); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Store(context.Background(), contracts.SecretRequest{Reference: second, Value: []byte(canary), Operation: operation("store-second")}); err != nil {
		t.Fatal(err)
	}
	firstCipher, err := os.ReadFile(filepath.Join(provider.vaultRoot, referenceDigest(first)+".enc"))
	if err != nil {
		t.Fatal(err)
	}
	secondCipher, err := os.ReadFile(filepath.Join(provider.vaultRoot, referenceDigest(second)+".enc"))
	if err != nil {
		t.Fatal(err)
	}
	if string(firstCipher) == string(secondCipher) {
		t.Fatal("same plaintext was encrypted to identical ciphertext")
	}
	assertNoCanary(t, canary, root, keyPath)
}

func TestStartupRecoveryRemovesExpiredMaterialAndPreservesActiveIdempotentMaterial(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	provider, root, materialRoot, keyPath := testProvider(t, now, time.Minute)
	reference := testReference("secret_1")
	if _, err := provider.Store(context.Background(), contracts.SecretRequest{Reference: reference, Value: []byte(canary), Operation: operation("store")}); err != nil {
		t.Fatal(err)
	}
	active, err := provider.ResolveBuildSecret(context.Background(), reference, operation("resolve"))
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := New(Config{Root: root, MaterialRoot: materialRoot, MasterKeyPath: keyPath, MaterialTTL: time.Minute, Clock: func() time.Time { return now.Add(30 * time.Second) }})
	if err != nil {
		t.Fatal(err)
	}
	// The active material is recovered from its sidecar and reused.
	retry, err := restarted.ResolveBuildSecret(context.Background(), reference, operation("resolve"))
	_ = restarted.Close()
	if err != nil || retry.Path != active.Path {
		t.Fatalf("active material was not recovered idempotently: %#v %v", retry, err)
	}
	provider.Close()

	expired, err := New(Config{Root: root, MaterialRoot: materialRoot, MasterKeyPath: keyPath, MaterialTTL: time.Minute, Clock: func() time.Time { return now.Add(2 * time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	defer expired.Close()
	if _, err := os.Stat(active.Path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expired material survived startup recovery: %v", err)
	}
	assertNoCanary(t, canary, root, materialRoot, keyPath)
}

func TestPathAndPermissionBoundariesFailClosed(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	materialRoot := filepath.Join(base, "material")
	keyPath := filepath.Join(base, "key")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(materialRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(base, "root-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Root: filepath.Join(base, "root-link"), MaterialRoot: materialRoot, MasterKeyPath: keyPath}); err == nil {
		t.Fatal("symlink root was accepted")
	}

	provider, _, _, _ := testProvider(t, time.Unix(1_700_000_000, 0).UTC(), time.Minute)
	if _, err := provider.Store(context.Background(), contracts.SecretRequest{Reference: domain.SecretReference{ID: "../escape", Name: "name", Provider: "local"}, Value: []byte(canary), Operation: operation("unsafe")}); err == nil {
		t.Fatal("traversal reference was accepted")
	}
	material, err := provider.ResolveBuildSecret(context.Background(), testReference("secret_1"), operation("missing"))
	if !hasCode(err, contracts.ErrNotFound) || material.Path != "" {
		t.Fatalf("missing secret did not fail closed: %#v %v", material, err)
	}
	bad := contracts.BuildSecretMaterial{MountID: "mount_" + strings.Repeat("a", 48), Reference: testReference("secret_1"), Path: filepath.Join(base, "outside"), ExpiresAt: time.Now().Add(time.Minute)}
	if err := provider.RevokeBuildSecret(context.Background(), bad, operation("bad-path")); err == nil {
		t.Fatal("outside material path was accepted")
	}
}

func TestBoundaryReplacementIsRejectedAfterConstruction(t *testing.T) {
	provider, root, _, _ := testProvider(t, time.Unix(1_700_000_000, 0).UTC(), time.Minute)
	backup := root + "-backup"
	if err := os.Rename(root, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(backup, root); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Store(context.Background(), contracts.SecretRequest{Reference: testReference("secret_1"), Value: []byte(canary), Operation: operation("store")}); !hasCode(err, contracts.ErrUnavailable) && !hasCode(err, contracts.ErrForbidden) {
		t.Fatalf("replaced root was not rejected: %v", err)
	}
}

func TestInstaller0750DirectoriesAreAccepted(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	materialRoot := filepath.Join(base, "material")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(materialRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	provider, err := New(Config{Root: root, MaterialRoot: materialRoot, MasterKeyPath: filepath.Join(base, "key")})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	if _, err := provider.Store(context.Background(), contracts.SecretRequest{Reference: testReference("secret_1"), Value: []byte(canary), Operation: operation("store")}); err != nil {
		t.Fatal(err)
	}
}

func TestErrorsDoNotEchoCanary(t *testing.T) {
	provider, _, _, _ := testProvider(t, time.Unix(1_700_000_000, 0).UTC(), time.Minute)
	err := func() error {
		_, err := provider.Mount(context.Background(), contracts.SecretRequest{Reference: testReference("missing"), Value: []byte(canary), Operation: operation("mount")})
		return err
	}()
	if err == nil || strings.Contains(fmt.Sprintf("%v %#v", err, err), canary) {
		t.Fatalf("provider error echoed plaintext: %v", err)
	}
}

func assertNoCanary(t *testing.T, value string, roots ...string) {
	t.Helper()
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(data), value) {
				return fmt.Errorf("canary found in %s", filepath.Base(path))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func hasCode(err error, code contracts.ErrorCode) bool {
	var providerErr *contracts.ProviderError
	return errors.As(err, &providerErr) && providerErr.Code == code
}
