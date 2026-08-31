package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func testBackupConfig() BackupConfigV1 {
	return BackupConfigV1{
		SchemaVersion:        1,
		InstallationIDSHA256: strings.Repeat("a", 64),
		Provider:             "tencent-cos",
		Bucket:               "open-card-backups-1234567890",
		Region:               "ap-shanghai",
		Endpoint:             "https://open-card-backups-1234567890.cos.ap-shanghai.tencentcos.cn",
		Prefix:               "open-card/backups",
		CredentialProvider:   "cvm-instance-role",
	}
}

func writeBackupTestFile(t *testing.T, root, name string, value []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, value, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func testSecureRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestBackupConfigV1StrictCanonicalBindingAndRedaction(t *testing.T) {
	config := testBackupConfig()
	raw, err := MarshalBackupConfigV1(config)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":1,"installation_id_sha256":"` + strings.Repeat("a", 64) + `","provider":"tencent-cos","bucket":"open-card-backups-1234567890","region":"ap-shanghai","endpoint":"https://open-card-backups-1234567890.cos.ap-shanghai.tencentcos.cn","prefix":"open-card/backups","credential_provider":"cvm-instance-role"}` + "\n"
	if string(raw) != want {
		t.Fatalf("canonical config mismatch: %q", raw)
	}
	parsed, err := ParseBoundBackupConfigV1(raw, config.InstallationIDSHA256)
	if err != nil || parsed != config {
		t.Fatalf("bound parse = %#v, %v", parsed, err)
	}
	if _, err := ParseBoundBackupConfigV1(raw, strings.Repeat("b", 64)); !errors.Is(err, ErrBackupConfigUnavailable) {
		t.Fatalf("hash mismatch = %v", err)
	}
	key, err := config.ObjectKey("backup-config-01")
	if err != nil || key != "open-card/backups/"+strings.Repeat("a", 64)+"/backup-config-01.ocbkp" {
		t.Fatalf("object key = %q, %v", key, err)
	}
	printed := fmt.Sprintf("%v %#v", config, config)
	if strings.Contains(printed, config.Bucket) || strings.Contains(printed, config.Endpoint) {
		t.Fatalf("format leaked topology: %q", printed)
	}
	// json.Marshal is deliberately canonical (and therefore not redacted).
	// The public error and formatting paths above are the safe diagnostics.
	if _, err := json.Marshal(config); err != nil {
		t.Fatal(err)
	}
}

func TestBackupConfigV1RejectsNonCanonicalJSONAndTopology(t *testing.T) {
	raw, err := MarshalBackupConfigV1(testBackupConfig())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"bom":             append([]byte{0xef, 0xbb, 0xbf}, raw...),
		"no newline":      raw[:len(raw)-1],
		"double newline":  append(append([]byte(nil), raw...), '\n'),
		"crlf":            []byte(strings.TrimSuffix(string(raw), "\n") + "\r\n"),
		"leading space":   append([]byte(" "), raw...),
		"space before LF": []byte(strings.TrimSuffix(string(raw), "\n") + " \n"),
		"trailing":        append(append([]byte(nil), raw...), []byte("{}")...),
		"unknown":         []byte(strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "}") + `,"unknown":1}` + "\n"),
		"field order":     []byte(`{"provider":"tencent-cos","schema_version":1,"installation_id_sha256":"` + strings.Repeat("a", 64) + `","bucket":"open-card-backups-1234567890","region":"ap-shanghai","endpoint":"https://open-card-backups-1234567890.cos.ap-shanghai.tencentcos.cn","prefix":"open-card/backups","credential_provider":"cvm-instance-role"}` + "\n"),
		"duplicate":       []byte(`{"schema_version":1,"schema_version":1,"installation_id_sha256":"` + strings.Repeat("a", 64) + `","provider":"tencent-cos","bucket":"open-card-backups-1234567890","region":"ap-shanghai","endpoint":"https://open-card-backups-1234567890.cos.ap-shanghai.tencentcos.cn","prefix":"open-card/backups","credential_provider":"cvm-instance-role"}` + "\n"),
		"missing":         []byte(`{"schema_version":1,"installation_id_sha256":"` + strings.Repeat("a", 64) + `","provider":"tencent-cos","bucket":"open-card-backups-1234567890","region":"ap-shanghai","endpoint":"https://open-card-backups-1234567890.cos.ap-shanghai.tencentcos.cn","prefix":"open-card/backups"}` + "\n"),
		"null":            []byte(`{"schema_version":1,"installation_id_sha256":null,"provider":"tencent-cos","bucket":"open-card-backups-1234567890","region":"ap-shanghai","endpoint":"https://open-card-backups-1234567890.cos.ap-shanghai.tencentcos.cn","prefix":"open-card/backups","credential_provider":"cvm-instance-role"}` + "\n"),
	}
	for name, invalid := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBackupConfigV1(invalid); !errors.Is(err, ErrBackupConfigUnavailable) {
				t.Fatalf("ParseBackupConfigV1(%q) = %v", invalid, err)
			}
		})
	}
	for name, mutate := range map[string]func(*BackupConfigV1){
		"uppercase bucket": func(c *BackupConfigV1) { c.Bucket = "Open-card-backups-1234567890" },
		"bad region":       func(c *BackupConfigV1) { c.Region = "AP-SHANGHAI" },
		"wrong endpoint":   func(c *BackupConfigV1) { c.Endpoint = "https://elsewhere.invalid" },
		"wrong provider":   func(c *BackupConfigV1) { c.Provider = "s3" },
		"wrong prefix":     func(c *BackupConfigV1) { c.Prefix = "backups" },
		"credential field": func(c *BackupConfigV1) { c.CredentialProvider = "static-key" },
	} {
		t.Run(name, func(t *testing.T) {
			config := testBackupConfig()
			mutate(&config)
			if err := config.Validate(); !errors.Is(err, ErrBackupConfigUnavailable) {
				t.Fatalf("Validate = %v", err)
			}
		})
	}
}

func TestBackupRoleProfileV1Strict(t *testing.T) {
	profile := BackupRoleProfileV1{SchemaVersion: 1, RoleName: "OpenCardBackupRole_1"}
	raw, err := MarshalBackupRoleProfileV1(profile)
	if err != nil || string(raw) != "schema_version=1\nrole_name=OpenCardBackupRole_1\n" {
		t.Fatalf("marshal = %q, %v", raw, err)
	}
	if got, err := ParseBackupRoleProfileV1(raw); err != nil || got != profile {
		t.Fatalf("parse = %#v, %v", got, err)
	}
	for _, invalid := range [][]byte{
		[]byte("schema_version=1\nrole_name=OpenCardBackupRole_1"),
		[]byte("schema_version=1\r\nrole_name=OpenCardBackupRole_1\r\n"),
		[]byte("role_name=OpenCardBackupRole_1\nschema_version=1\n"),
		[]byte("schema_version=1\nrole_name=other role\n"),
		[]byte("schema_version=1\nrole_name=OpenCardBackupRole_1\ncredential=x\n"),
		[]byte("schema_version=1\nrole_name=bad role\n"),
		[]byte("schema_version=1\nrole_name=" + strings.Repeat("a", 129) + "\n"),
	} {
		if _, err := ParseBackupRoleProfileV1(invalid); !errors.Is(err, ErrBackupRoleProfileUnavailable) {
			t.Fatalf("profile %q = %v", invalid, err)
		}
	}
	if strings.Contains(fmt.Sprintf("%v %#v", profile, profile), profile.RoleName) {
		t.Fatal("profile formatting leaked role")
	}
}

func TestBackupConfigReaderRejectsUnsafeLeaves(t *testing.T) {
	root := testSecureRoot(t)
	reader, err := TaskBackupConfigReader(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := MarshalBackupConfigV1(testBackupConfig())
	path := writeBackupTestFile(t, root, backupConfigFileName, raw, 0o600)
	if _, err := reader.ReadConfig(strings.Repeat("a", 64)); err != nil {
		t.Fatalf("secure config = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadConfig(strings.Repeat("a", 64)); !errors.Is(err, ErrBackupConfigUnavailable) {
		t.Fatalf("mode = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", path); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadConfig(strings.Repeat("a", 64)); !errors.Is(err, ErrBackupConfigUnavailable) {
		t.Fatalf("symlink = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	writeBackupTestFile(t, root, backupConfigFileName, raw, 0o600)
	if err := os.Link(path, filepath.Join(root, "linked-config")); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadConfig(strings.Repeat("a", 64)); !errors.Is(err, ErrBackupConfigUnavailable) {
		t.Fatalf("hardlink = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadConfig(strings.Repeat("a", 64)); !errors.Is(err, ErrBackupConfigUnavailable) {
		t.Fatalf("fifo = %v", err)
	}
}

func TestBackupConfigReaderRejectsSymlinkAncestorAndOwnerMismatch(t *testing.T) {
	base := testSecureRoot(t)
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := TaskBackupConfigReader(filepath.Join(link, "child"), os.Getuid(), os.Getgid()); !errors.Is(err, ErrBackupConfigUnavailable) {
		t.Fatalf("symlink ancestor = %v", err)
	}
	root := filepath.Join(base, "owner-root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := TaskBackupConfigReader(root, os.Getuid()+1, os.Getgid()); !errors.Is(err, ErrBackupConfigUnavailable) {
		t.Fatalf("owner mismatch = %v", err)
	}
}
