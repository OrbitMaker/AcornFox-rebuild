package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBackupKeyFixture(t *testing.T, root, version string, value byte) {
	t.Helper()
	writeBackupTestFile(t, root, version+backupKeyFileSuffix, bytesRepeat(value, backupKeySize), 0o400)
}

func bytesRepeat(value byte, count int) []byte {
	data := make([]byte, count)
	for i := range data {
		data[i] = value
	}
	return data
}

func TestBackupKeyResolverActiveExplicitCloseAndNoFallback(t *testing.T) {
	root := testSecureRoot(t)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	resolver, err := TaskBackupKeyResolver(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	writeBackupKeyFixture(t, root, "key-current", 0x11)
	writeBackupKeyFixture(t, root, "key-old", 0x22)
	writeBackupTestFile(t, root, backupKeyActiveFile, []byte("schema_version=1\nactive_key_version=key-current\n"), 0o400)
	key, err := resolver.ResolveActive()
	if err != nil {
		t.Fatal(err)
	}
	if version, err := key.Version(); err != nil || version != "key-current" {
		t.Fatalf("version = %q, %v", version, err)
	}
	if err := key.WithBytes(func(raw []byte) error {
		if len(raw) != backupKeySize || raw[0] != 0x11 {
			t.Fatalf("material = %x", raw)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve("key-old"); err != nil {
		t.Fatalf("explicit old = %v", err)
	}
	if err := os.Chmod(filepath.Join(root, backupKeyActiveFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, backupKeyActiveFile), []byte("schema_version=1\nactive_key_version=key-missing\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveActive(); !errors.Is(err, ErrBackupKeyUnavailable) {
		t.Fatalf("missing active target = %v", err)
	}
	if err := os.Remove(filepath.Join(root, backupKeyActiveFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveActive(); !errors.Is(err, ErrBackupKeyUnavailable) {
		t.Fatalf("missing active = %v", err)
	}
	if err := resolver.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve("key-old"); !errors.Is(err, ErrBackupKeyUnavailable) {
		t.Fatalf("closed resolve = %v", err)
	}
}

func TestBackupKeyMaterialZeroingDestroyAndRedaction(t *testing.T) {
	root := testSecureRoot(t)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	resolver, err := TaskBackupKeyResolver(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	writeBackupKeyFixture(t, root, "key-secret", 0x7a)
	key, err := resolver.Resolve("key-secret")
	if err != nil {
		t.Fatal(err)
	}
	var retained []byte
	if err := key.WithBytes(func(raw []byte) error { retained = raw; return nil }); err != nil {
		t.Fatal(err)
	}
	for _, value := range retained {
		if value != 0 {
			t.Fatal("transient copy was not zeroed")
		}
	}
	value := *key
	for _, candidate := range []any{key, value} {
		for _, verb := range []string{"%s", "%v", "%+v", "%#v"} {
			printed := fmt.Sprintf(verb, candidate)
			if strings.Contains(printed, "7a") || strings.Contains(printed, "key-secret") || strings.Contains(printed, "backupKeyMaterialState") {
				t.Fatalf("format %q leaked key: %q", verb, printed)
			}
		}
	}
	for _, candidate := range []any{key, value} {
		raw, err := json.Marshal(candidate)
		if err != nil || string(raw) != `"backup_key_material_redacted"` || strings.Contains(string(raw), "7a") || strings.Contains(string(raw), "key-secret") {
			t.Fatalf("json = %q, %v", raw, err)
		}
	}
	key.Destroy()
	key.Destroy()
	if _, err := key.Version(); !errors.Is(err, ErrBackupKeyDestroyed) {
		t.Fatalf("destroyed version = %v", err)
	}
	if err := key.WithBytes(func([]byte) error { return nil }); !errors.Is(err, ErrBackupKeyDestroyed) {
		t.Fatalf("destroyed bytes = %v", err)
	}
}

func TestBackupKeyResolverRejectsMalformedActiveAndUnsafeKeyLeaves(t *testing.T) {
	root := testSecureRoot(t)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	resolver, err := TaskBackupKeyResolver(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{
		[]byte("schema_version=1\nactive_key_version=key-good"),
		[]byte("schema_version=2\nactive_key_version=key-good\n"),
		[]byte("schema_version=1\nactive_key_version=old\n"),
		[]byte("schema_version=1\nactive_key_version=key-good\nextra=x\n"),
	} {
		writeBackupTestFile(t, root, backupKeyActiveFile, raw, 0o400)
		if _, err := resolver.ResolveActive(); !errors.Is(err, ErrBackupKeyUnavailable) {
			t.Fatalf("active %q = %v", raw, err)
		}
		if err := os.Remove(filepath.Join(root, backupKeyActiveFile)); err != nil {
			t.Fatal(err)
		}
	}
	path := writeBackupTestFile(t, root, "key-good"+backupKeyFileSuffix, bytesRepeat(1, backupKeySize), 0o400)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve("key-good"); !errors.Is(err, ErrBackupKeyUnavailable) {
		t.Fatalf("mode = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve("key-good"); !errors.Is(err, ErrBackupKeyUnavailable) {
		t.Fatalf("symlink = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	writeBackupTestFile(t, root, "key-good"+backupKeyFileSuffix, bytesRepeat(1, backupKeySize), 0o400)
	if err := os.Link(path, filepath.Join(root, "key-copy")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve("key-good"); !errors.Is(err, ErrBackupKeyUnavailable) {
		t.Fatalf("hardlink = %v", err)
	}
	if _, err := resolver.Resolve("../key-good"); !errors.Is(err, ErrBackupKeyUnavailable) {
		t.Fatalf("path traversal = %v", err)
	}
}
