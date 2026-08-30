package install

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func scriptRoot(t *testing.T) string {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(workingDirectory, "..", ".."))
}

func writeScriptBundle(t *testing.T, directory, version, releaseID, protocol string, serverData []byte) string {
	t.Helper()
	bundle := filepath.Join(directory, "bundle-"+releaseID)
	if err := os.MkdirAll(filepath.Join(bundle, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	serverPath := filepath.Join(bundle, "bin", "open-card-server")
	agentPath := filepath.Join(bundle, "bin", "open-card-agent")
	if err := os.WriteFile(serverPath, serverData, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agentPath, []byte("agent-"+version+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	unitDirectory := filepath.Join(bundle, "systemd")
	if err := os.MkdirAll(unitDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	serverDigest, err := SHA256File(serverPath)
	if err != nil {
		t.Fatal(err)
	}
	agentDigest, err := SHA256File(agentPath)
	if err != nil {
		t.Fatal(err)
	}
	files := []FileDigest{
		{Path: "bin/open-card-server", SHA256: serverDigest, Mode: 0o755},
		{Path: "bin/open-card-agent", SHA256: agentDigest, Mode: 0o755},
	}
	for _, unit := range []string{"open-card-server.service", "open-card-agent.service", "open-card-buildkit.service", "open-card-caddy.service"} {
		contents, err := os.ReadFile(filepath.Join(scriptRoot(t), "deploy", "systemd", unit))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(unitDirectory, unit)
		if err := os.WriteFile(path, contents, 0o644); err != nil {
			t.Fatal(err)
		}
		digest, err := SHA256File(path)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, FileDigest{Path: filepath.ToSlash(filepath.Join("systemd", unit)), SHA256: digest, Mode: 0o644})
	}
	manifest := Manifest{
		SchemaVersion: ManifestSchemaVersion,
		Product:       ManifestProduct,
		Version:       version,
		ReleaseID:     releaseID,
		Protocol:      protocol,
		ConfigDir:     DefaultConfigDir,
		DataDir:       DefaultDataDir,
		Compatibility: Compatibility{MinDataVersion: 1, MaxDataVersion: 8, MinAgentProtocol: PreviousAgentProtocol, MaxAgentProtocol: AgentProtocolVersion},
		Files:         files,
	}
	if err := SaveManifest(filepath.Join(bundle, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func runScript(t *testing.T, script string, args ...string) (string, error) {
	t.Helper()
	command := exec.Command("bash", append([]string{script}, args...)...)
	output, err := command.CombinedOutput()
	return string(output), err
}

func runScriptEnv(t *testing.T, environment []string, script string, args ...string) (string, error) {
	t.Helper()
	command := exec.Command("bash", append([]string{script}, args...)...)
	command.Env = append(os.Environ(), environment...)
	output, err := command.CombinedOutput()
	return string(output), err
}

func TestG7ScriptLifecycle(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required by the G7 script contract")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is required by the JSON manifest script contract")
	}
	directory := t.TempDir()
	root := filepath.Join(directory, "root")
	safePrefix := directory
	scripts := filepath.Join(scriptRoot(t), "scripts", "mvp")
	install := filepath.Join(scripts, "install.sh")
	upgrade := filepath.Join(scripts, "upgrade.sh")
	backup := filepath.Join(scripts, "backup-control-plane.sh")
	restore := filepath.Join(scripts, "restore-control-plane.sh")
	uninstall := filepath.Join(scripts, "uninstall.sh")

	v1 := writeScriptBundle(t, directory, "1.0.0", "release-1.0.0", PreviousAgentProtocol, []byte("server-v1\n"))
	common := []string{"--root", root, "--bundle", v1, "--offline", "--test-safe-prefix", safePrefix}
	t.Run("fresh install and repeat", func(t *testing.T) {
		if output, err := runScript(t, install, common...); err != nil {
			t.Fatalf("fresh install: %v\n%s", err, output)
		}
		current := filepath.Join(root, "opt/open-card/current")
		if got, err := os.Readlink(current); err != nil || got != "releases/release-1.0.0" {
			t.Fatalf("current pointer: %q %v", got, err)
		}
		for _, unit := range []string{"open-card-server.service", "open-card-agent.service", "open-card-buildkit.service", "open-card-caddy.service"} {
			if info, err := os.Stat(filepath.Join(root, "etc", "systemd", "system", unit)); err != nil || info.Mode().Perm() != 0o644 {
				t.Fatalf("staged %s: %v (%v)", unit, info, err)
			}
		}
		output, err := runScript(t, install, common...)
		if err != nil || !strings.Contains(output, "idempotent") {
			t.Fatalf("repeat install: %v\n%s", err, output)
		}
	})
	t.Run("installed checksum tamper is rejected", func(t *testing.T) {
		path := filepath.Join(root, "opt/open-card/current/bin/open-card-server")
		if err := os.WriteFile(path, []byte("tampered\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if output, err := runScript(t, install, common...); err == nil || !strings.Contains(output, "checksum mismatch") {
			t.Fatalf("tamper result: %v\n%s", err, output)
		}
		if err := os.WriteFile(path, []byte("server-v1\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	})

	controlPlaneData := filepath.Join(root, "var/lib/open-card/control-plane.db")
	if err := os.WriteFile(controlPlaneData, []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := runScript(t, backup, "--root", root, "--reason", "test-backup", "--test-safe-prefix", safePrefix); err != nil {
		t.Fatalf("backup: %v\n%s", err, output)
	}
	metadataFiles, err := filepath.Glob(filepath.Join(root, "var/lib/open-card/backups", "*.json"))
	if err != nil || len(metadataFiles) != 1 {
		t.Fatalf("backup metadata files: %v %v", metadataFiles, err)
	}
	metadataBytes, err := os.ReadFile(metadataFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	var metadata BackupMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(controlPlaneData, []byte("after\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(filepath.Dir(metadataFiles[0]), metadata.Archive)
	archiveBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	corruptArchivePath := archivePath + ".corrupt"
	if err := os.WriteFile(corruptArchivePath, append(archiveBytes, []byte("corrupt\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	corruptMetadata := metadata
	corruptMetadata.Archive = filepath.Base(corruptArchivePath)
	corruptMetadataPath := strings.TrimSuffix(metadataFiles[0], ".json") + ".corrupt.json"
	if err := SaveBackupMetadata(corruptMetadataPath, corruptMetadata); err != nil {
		t.Fatal(err)
	}
	if output, err := runScript(t, restore, "--root", root, "--backup", corruptMetadataPath, "--test-safe-prefix", safePrefix); err == nil || !strings.Contains(output, "backup checksum mismatch") {
		t.Fatalf("corrupt backup result: %v\n%s", err, output)
	}
	unchanged, err := os.ReadFile(controlPlaneData)
	if err != nil || string(unchanged) != "after\n" {
		t.Fatalf("corrupt restore changed data: %q %v", unchanged, err)
	}
	if output, err := runScript(t, restore, "--root", root, "--backup", metadataFiles[0], "--test-safe-prefix", safePrefix); err != nil {
		t.Fatalf("restore: %v\n%s", err, output)
	}
	restored, err := os.ReadFile(controlPlaneData)
	if err != nil || string(restored) != "before\n" {
		t.Fatalf("restored data: %q %v", restored, err)
	}

	v2 := writeScriptBundle(t, directory, "1.1.0", "release-1.1.0", AgentProtocolVersion, []byte("server-v2\n"))
	health := filepath.Join(directory, "health-fail.sh")
	if err := os.WriteFile(health, []byte("#!/usr/bin/env bash\nexit 42\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	upgradeArgs := []string{"--root", root, "--bundle", v2, "--offline", "--health-command", health, "--test-safe-prefix", safePrefix}
	if output, err := runScript(t, upgrade, upgradeArgs...); err == nil || !strings.Contains(output, "rolling back") {
		t.Fatalf("failed upgrade rollback: %v\n%s", err, output)
	}
	if got, err := os.Readlink(filepath.Join(root, "opt/open-card/current")); err != nil || got != "releases/release-1.0.0" {
		t.Fatalf("rollback pointer: %q %v", got, err)
	}
	if output, err := runScript(t, upgrade, "--root", root, "--bundle", v2, "--offline", "--health-command", "/usr/bin/true", "--test-safe-prefix", safePrefix); err != nil {
		t.Fatalf("successful upgrade: %v\n%s", err, output)
	}
	if got, err := os.Readlink(filepath.Join(root, "opt/open-card/current")); err != nil || got != "releases/release-1.1.0" {
		t.Fatalf("successful upgrade pointer: %q %v", got, err)
	}

	t.Run("uninstall preserves data and purge requires token", func(t *testing.T) {
		if output, err := runScript(t, uninstall, "--root", root, "--test-safe-prefix", safePrefix); err != nil {
			t.Fatalf("uninstall preserve: %v\n%s", err, output)
		}
		if _, err := os.Stat(controlPlaneData); err != nil {
			t.Fatalf("data was not preserved: %v", err)
		}
		if output, err := runScript(t, uninstall, "--root", root, "--purge", "--test-safe-prefix", safePrefix); err == nil || !strings.Contains(output, "OPEN-CARD-PURGE") {
			t.Fatalf("purge confirmation: %v\n%s", err, output)
		}
		if output, err := runScript(t, uninstall, "--root", root, "--purge", "--confirm", "OPEN-CARD-PURGE", "--test-safe-prefix", safePrefix); err != nil {
			t.Fatalf("purge: %v\n%s", err, output)
		}
		if _, err := os.Stat(filepath.Join(root, "var/lib/open-card")); !os.IsNotExist(err) {
			t.Fatalf("purge left data: %v", err)
		}
	})
}

func TestG7ScriptPathSafety(t *testing.T) {
	directory := t.TempDir()
	bundle := writeScriptBundle(t, directory, "1.0.0", "safe-release", AgentProtocolVersion, []byte("server\n"))
	script := filepath.Join(scriptRoot(t), "scripts", "mvp", "install.sh")
	if output, err := runScriptEnv(t, []string{"OPEN_CARD_ALLOW_SYSTEM_ROOT=", "OPEN_CARD_SYSTEM_ROOT_CONFIRMATION="}, script, "--root", "/", "--bundle", bundle); err == nil || !strings.Contains(output, "--root / requires") {
		t.Fatalf("root path safety: %v\n%s", err, output)
	}
	escapeTarget := filepath.Join(directory, "outside")
	if err := os.MkdirAll(escapeTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	symlinkRoot := filepath.Join(directory, "open-card-g7-link")
	if err := os.Symlink(escapeTarget, symlinkRoot); err != nil {
		t.Fatal(err)
	}
	if output, err := runScript(t, script, "--root", symlinkRoot, "--bundle", bundle, "--test-safe-prefix", directory); err == nil || !strings.Contains(output, "symlink") {
		t.Fatalf("symlink path safety: %v\n%s", err, output)
	}
	if err := os.WriteFile(filepath.Join(bundle, "unlisted-executable"), []byte("not covered by the manifest"), 0o755); err != nil {
		t.Fatal(err)
	}
	if output, err := runScript(t, script, "--root", filepath.Join(directory, "unlisted-root"), "--bundle", bundle, "--test-safe-prefix", directory); err == nil || !strings.Contains(output, "file set mismatch") {
		t.Fatalf("unlisted bundle file: %v\n%s", err, output)
	}
	if output, err := runScript(t, script, "--root", filepath.Join(directory, "online-root"), "--url", "http://example.invalid/open-card.tar.gz", "--test-safe-prefix", directory); err == nil || !strings.Contains(output, "https://") {
		t.Fatalf("insecure online URL: %v\n%s", err, output)
	}
	maliciousArchive := filepath.Join(directory, "symlink-bundle.tar.gz")
	archiveFile, err := os.Create(maliciousArchive)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(archiveFile)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "escape", Typeflag: tar.TypeSymlink, Linkname: "/tmp", Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := archiveFile.Close(); err != nil {
		t.Fatal(err)
	}
	if output, err := runScript(t, script, "--root", filepath.Join(directory, "archive-root"), "--bundle", maliciousArchive, "--test-safe-prefix", directory); err == nil || !strings.Contains(output, "archive validation") {
		t.Fatalf("symlink archive: %v\n%s", err, output)
	}
}

func TestG7SystemRootRequiresCleanWorkerAuthorization(t *testing.T) {
	directory := t.TempDir()
	bundle := writeScriptBundle(t, directory, "1.0.0", "root-gate", AgentProtocolVersion, []byte("server\n"))
	scripts := filepath.Join(scriptRoot(t), "scripts", "mvp")
	noAuthorization := []string{"OPEN_CARD_ALLOW_SYSTEM_ROOT=", "OPEN_CARD_SYSTEM_ROOT_CONFIRMATION="}
	tests := []struct {
		name   string
		script string
		args   []string
	}{
		{"install", "install.sh", []string{"--root", "/", "--bundle", bundle}},
		{"upgrade", "upgrade.sh", []string{"--root", "/", "--bundle", bundle}},
		{"uninstall", "uninstall.sh", []string{"--root", "/"}},
		{"backup", "backup-control-plane.sh", []string{"--root", "/"}},
		{"restore", "restore-control-plane.sh", []string{"--root", "/", "--backup", filepath.Join(directory, "missing.tar.gz")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := runScriptEnv(t, noAuthorization, filepath.Join(scripts, test.script), test.args...)
			if err == nil || !strings.Contains(output, "--root / requires") {
				t.Fatalf("ordinary root was accepted: %v\n%s", err, output)
			}
		})
	}
}

func TestG7BackupRequiresConsistentDatabaseDump(t *testing.T) {
	directory := t.TempDir()
	root := filepath.Join(directory, "root")
	scripts := filepath.Join(scriptRoot(t), "scripts", "mvp")
	backup := filepath.Join(scripts, "backup-control-plane.sh")
	metadataPattern := filepath.Join(root, "var/lib/open-card/backups", "*.json")
	args := []string{"--root", root, "--test-safe-prefix", directory}
	if output, err := runScriptEnv(t, []string{"OPEN_CARD_DATABASE_URL=postgres://fixture.invalid/db"}, backup, args...); err == nil || !strings.Contains(output, "consistent backup") {
		t.Fatalf("database consistency gate: %v\n%s", err, output)
	}
	dumpCommand := filepath.Join(directory, "pg-dump-fixture.sh")
	if err := os.WriteFile(dumpCommand, []byte("#!/usr/bin/env bash\nprintf 'fixture dump\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if output, err := runScriptEnv(t, []string{"OPEN_CARD_DATABASE_URL=postgres://fixture.invalid/db"}, backup, append(args, "--database-dump-command", dumpCommand)...); err != nil {
		t.Fatalf("database dump backup: %v\n%s", err, output)
	}
	metadataFiles, err := filepath.Glob(metadataPattern)
	if err != nil || len(metadataFiles) != 1 {
		t.Fatalf("database backup metadata: %v %v", metadataFiles, err)
	}
	metadata, err := LoadBackupMetadata(metadataFiles[0])
	if err != nil || metadata.Consistency != "pg-dump" || metadata.DatabaseDumpSHA256 == "" {
		t.Fatalf("database backup metadata: %#v %v", metadata, err)
	}
}

func TestG7ScriptsAreBashSyntaxValid(t *testing.T) {
	for _, name := range []string{"install.sh", "upgrade.sh", "uninstall.sh", "backup-control-plane.sh", "restore-control-plane.sh"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(scriptRoot(t), "scripts", "mvp", name)
			if output, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
				t.Fatalf("bash -n: %v\n%s", err, output)
			}
		})
	}
}

func TestG5BProductionBackupRestoreDelegateOnlyToFixedV2Helper(t *testing.T) {
	root := scriptRoot(t)
	backupRaw, err := os.ReadFile(filepath.Join(root, "scripts", "mvp", "backup-control-plane.sh"))
	if err != nil {
		t.Fatal(err)
	}
	restoreRaw, err := os.ReadFile(filepath.Join(root, "scripts", "mvp", "restore-control-plane.sh"))
	if err != nil {
		t.Fatal(err)
	}
	backup, restore := string(backupRaw), string(restoreRaw)
	for name, text := range map[string]string{"backup": backup, "restore": restore} {
		for _, required := range []string{
			"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
			"/opt/open-card/upgrade-tools/open-card-upgrade",
			"--confirm-installation-id",
			"unset OPEN_CARD_DATABASE_URL DATABASE_URL",
		} {
			if !strings.Contains(text, required) {
				t.Fatalf("%s production boundary is missing %q", name, required)
			}
		}
	}
	backupProduction := strings.Index(backup, "# Production backups are V2 database receipts")
	legacyDatabase := strings.Index(backup, "database_url=${OPEN_CARD_DATABASE_URL")
	if !strings.Contains(backup, "exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C \"$helper\" backup-create --backup-id \"$backup_id\" --reason \"$reason\"") || backupProduction < 0 || legacyDatabase < backupProduction || strings.Index(backup, "tar -czf") < legacyDatabase {
		t.Fatal("production backup can reach ambient database or archive path")
	}
	for _, forbidden := range []string{"--database-dump-command", "release, migration, and database dump overrides"} {
		if !strings.Contains(backup, forbidden) {
			t.Fatalf("production backup does not reject %q", forbidden)
		}
	}
	restoreProduction := strings.Index(restore, "# System-root restore is intentionally a journaled V2 database operation")
	legacyArchive := strings.Index(restore, "if [[ \"$backup\" = *.json ]]")
	if !strings.Contains(restore, "restore-preflight --transaction-id \"$transaction_id\" --backup-id \"$backup_id\"") || !strings.Contains(restore, "exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C \"$helper\" restore-run --transaction-id \"$transaction_id\" --backup-id \"$backup_id\"") || restoreProduction < 0 || legacyArchive < restoreProduction || strings.Index(restore, "rm -rf --") < legacyArchive || strings.Index(restore, "mv -- \"$data_dir\"") < legacyArchive {
		t.Fatal("production restore can reach legacy archive mutation path")
	}
	for _, forbidden := range []string{"--database-restore-command", "--root / requires a V2 backup id or exact backup.json path"} {
		if !strings.Contains(restore, forbidden) {
			t.Fatalf("production restore does not reject %q", forbidden)
		}
	}
	installRaw, err := os.ReadFile(filepath.Join(root, "scripts", "mvp", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(installRaw), "prepare_upgrade_layout_directory \"$data_dir/backups\" \"$expected_owner\" 700") {
		t.Fatal("upgrade substrate does not provision the fixed V2 backup root")
	}
}

func TestG5BRecoverySubstrateStaysStageOnlyAndBootDisabled(t *testing.T) {
	root := scriptRoot(t)
	installBytes, err := os.ReadFile(filepath.Join(root, "scripts", "mvp", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	hostBytes, err := os.ReadFile(filepath.Join(root, "scripts", "mvp", "install-host.sh"))
	if err != nil {
		t.Fatal(err)
	}
	install := string(installBytes)
	host := string(hostBytes)
	for _, required := range []string{
		"--stage-upgrade-substrate",
		"--validate-activation-intent",
		"prepare_upgrade_substrate",
		"existing production installation requires upgrade.sh or --stage-upgrade-substrate",
		"0.8.0-rc.1 system-root activation requires native bootstrap activation support",
		"durable_sync_file_and_parent",
		"durable_sync_directory_and_parent",
		"prepare_upgrade_data_root",
		"system lock path must be root-owned mode 1777",
		"install -d -m 0711 -o root -g root /var/lib/open-card",
		"chmod 0755 \"$prefix\" \"$releases\"",
		"chmod 0755 \"$stage_dir\"",
		"chmod 0711 \"$config_dir\"",
		"chmod 0700 \"$backups\" \"$evidence\"",
		"open-card-upgrade-safe.target",
		"open-card-upgrade-finalize.service",
		"open-card-edge.service.d/10-upgrade-marker.conf",
	} {
		if !strings.Contains(install, required) {
			t.Fatalf("install substrate contract is missing %q", required)
		}
	}
	for _, unit := range []string{"open-card-upgrade-recover.service", "open-card-upgrade-safe.target", "open-card-upgrade-finalize.service"} {
		if strings.Contains(install, "enable "+unit) || strings.Contains(install, "start "+unit) {
			t.Fatalf("installer enables or starts %s before the boot-safe gate", unit)
		}
	}
	stage := strings.Index(install, "if (( stage_upgrade_substrate )); then\n  if (( dry_run ))")
	units := strings.Index(install, "units=(open-card-server.service")
	stageExit := strings.Index(install, "say \"staged verified upgrade recovery substrate for $release_name\"\n  exit 0")
	releaseBranch := strings.Index(install, "if [[ -d \"$release_dir\" ]]")
	runtimeModes := strings.Index(install, "chmod 0755 \"$prefix\" \"$releases\" \"$release_dir\"")
	if stage < 0 || units < 0 || stageExit < stage || stageExit > units {
		t.Fatal("stage-only substrate path does not return before ordinary unit staging")
	}
	if releaseBranch < 0 || runtimeModes < releaseBranch || runtimeModes > stage {
		t.Fatal("runtime traversal modes are not reconciled after existing and new release branches")
	}
	if !strings.Contains(host, "install -d -m 0711 -o root -g root /var/lib/open-card") || strings.Index(host, "\"${installer[@]}\"") > strings.Index(host, "installation_id=/var/lib/open-card/installation-id") {
		t.Fatal("host installer does not establish a root-owned data parent before creating an installation id")
	}
	if !strings.Contains(host, "install -d -m 0711 -o root -g root /etc/open-card") || !strings.Contains(host, "install -d -m 0700 -o root -g root /var/lib/open-card/evidence") {
		t.Fatal("host installer does not separate runtime traversal from root-only evidence")
	}
	for _, required := range []string{"newuidmap newgidmap", "util-linux uidmap apparmor", "require_command \"$command_name\""} {
		if !strings.Contains(host, required) {
			t.Fatalf("host installer does not enforce rootless uidmap prerequisite %q", required)
		}
	}
	for _, required := range []string{"/usr/lib/postgresql/16/bin/psql", "/usr/lib/postgresql/16/bin/pg_dump", "/usr/lib/postgresql/16/bin/pg_restore"} {
		if !strings.Contains(host, required) {
			t.Fatalf("host installer does not pin PostgreSQL 16 tool %q", required)
		}
	}
	skipBranch := strings.Index(host, "if (( ! skip_prerequisites )); then")
	runtimeVerification := strings.LastIndex(host, "for command_name in docker psql runuser newuidmap newgidmap")
	installerCall := strings.Index(host, "\"$"+"{installer[@]}\"")
	if skipBranch < 0 || runtimeVerification < skipBranch || installerCall < runtimeVerification {
		t.Fatal("skip-prerequisites can bypass required runtime command verification")
	}
	if preflight := strings.Index(host, "--validate-activation-intent"); preflight < 0 || preflight > strings.Index(host, "require_command()") {
		t.Fatal("host activation-intent preflight does not precede mutable prerequisites")
	}
}

func TestG5BSystemRootUpgradeUsesOnlyVerifiedEngineDelegation(t *testing.T) {
	root := scriptRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "scripts", "mvp", "upgrade.sh"))
	if err != nil {
		t.Fatal(err)
	}
	upgrade := string(raw)
	for _, required := range []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"--root / requires --activate",
		"--root / requires --expected-manifest-sha256",
		"--root / refuses --health-command, --database-dump-command, --database-restore-command, --migration-command, and --migration-dir",
		"--root / refuses --allow-downgrade",
		"--stage-upgrade-substrate",
		"OPEN_CARD_INSTALL_CONFIRMATION=OPEN-CARD-INSTALL",
		"run_upgrade_helper prepare-control",
		"/usr/bin/systemctl enable --now open-card-upgrade-safe.target",
		"is-enabled --quiet open-card-upgrade-safe.target",
		"is-active --quiet open-card-upgrade-safe.target",
		"upgrade-safe target RequiredBy link is missing",
		"upgrade-safe target RequiredBy link owner is unsafe",
		"upgrade-safe target RequiredBy link is unsafe",
		"verified_production_program /usr/bin/python3",
		"/proc/sys/kernel/random/uuid",
		"--expect-layout rc0-legacy",
		"candidate manifest identity is ambiguous",
	} {
		if !strings.Contains(upgrade, required) {
			t.Fatalf("system-root delegation contract is missing %q", required)
		}
	}
	if strings.Contains(upgrade, "production upgrade is blocked") {
		t.Fatal("obsolete production hard refusal remains")
	}
	rootBranch := strings.Index(upgrade, "if [[ \"$root\" = \"/\" ]]; then\n  (( activate ))")
	legacyBackup := strings.Index(upgrade, "backup_args=(--root \"$root\"")
	productionExit := strings.Index(upgrade, "  exit 0\nfi\n\n# First ask the installer")
	if rootBranch < 0 || legacyBackup < 0 || productionExit < rootBranch || productionExit > legacyBackup {
		t.Fatal("system-root branch can reach legacy backup/migration flow")
	}
}

func TestG5BSystemRootUpgradeResetsCallerPATHBeforeAnyCommandLookup(t *testing.T) {
	directory := t.TempDir()
	canary := filepath.Join(directory, "caller-path-canary")
	for _, name := range []string{"cat", "dirname", "env", "python3", "readlink", "stat", "systemctl", "tr"} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("#!/usr/bin/env bash\nprintf hijacked >> \"$CANARY\"\nexit 97\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(scriptRoot(t), "scripts", "mvp", "upgrade.sh")
	output, err := runScriptEnv(t, []string{"PATH=" + directory, "CANARY=" + canary, "OPEN_CARD_ALLOW_SYSTEM_ROOT="}, script, "--root", "/", "--bundle", filepath.Join(directory, "missing"))
	if err == nil || !strings.Contains(output, "--root / requires") {
		t.Fatalf("root wrapper did not reach its authorization boundary: %v\n%s", err, output)
	}
	if _, statErr := os.Stat(canary); !os.IsNotExist(statErr) {
		t.Fatalf("caller PATH command ran before wrapper verification: %v", statErr)
	}
}

func TestG7SystemdUnitsKeepPrivilegeAndSocketBoundaries(t *testing.T) {
	serverBytes, err := os.ReadFile(filepath.Join(scriptRoot(t), "deploy", "systemd", "open-card-server.service"))
	if err != nil {
		t.Fatal(err)
	}
	agentBytes, err := os.ReadFile(filepath.Join(scriptRoot(t), "deploy", "systemd", "open-card-agent.service"))
	if err != nil {
		t.Fatal(err)
	}
	buildkitBytes, err := os.ReadFile(filepath.Join(scriptRoot(t), "deploy", "systemd", "open-card-buildkit.service"))
	if err != nil {
		t.Fatal(err)
	}
	caddyBytes, err := os.ReadFile(filepath.Join(scriptRoot(t), "deploy", "systemd", "open-card-caddy.service"))
	if err != nil {
		t.Fatal(err)
	}
	server := string(serverBytes)
	agent := string(agentBytes)
	buildkit := string(buildkitBytes)
	caddy := string(caddyBytes)
	for _, required := range []string{"User=opencard\n", "ExecStart=/opt/open-card/current/bin/open-card-server\n", "NoNewPrivileges=yes\n", "ProtectSystem=strict\n", "CapabilityBoundingSet=\n", "UMask=0077\n"} {
		if !strings.Contains(server, required) {
			t.Errorf("server unit is missing %q", required)
		}
	}
	if strings.Contains(server, "docker.sock") || strings.Contains(server, "SupplementaryGroups=docker") {
		t.Error("server unit must not receive Docker socket access")
	}
	for _, required := range []string{"User=opencard-agent\n", "SupplementaryGroups=docker opencard\n", "Environment=OPEN_CARD_DOCKER_SOCKET=/var/run/docker.sock\n", "BindPaths=/var/run/docker.sock\n", "ReadOnlyPaths=/var/lib/open-card/oci\n", "ExecStart=/opt/open-card/current/bin/open-card-agent\n", "NoNewPrivileges=yes\n", "ProtectSystem=strict\n", "UMask=0077\n"} {
		if !strings.Contains(agent, required) {
			t.Errorf("agent unit is missing %q", required)
		}
	}
	for _, required := range []string{"User=opencard-buildkit\n", "Environment=HOME=/var/lib/open-card-buildkit\n", "Environment=PATH=/opt/open-card/current/bin:", "ExecStart=/opt/open-card/current/bin/rootlesskit ", "--net=none ", "/opt/open-card/current/bin/buildkitd ", "NoNewPrivileges=no\n", "Delegate=yes\n", "MemoryMax=512M\n", "CPUQuota=50%\n", "UMask=0077\n"} {
		if !strings.Contains(buildkit, required) {
			t.Errorf("buildkit unit is missing %q", required)
		}
	}
	if strings.Contains(strings.ToLower(buildkit), "docker.sock") || strings.Contains(buildkit, "BindPaths=") || strings.Contains(buildkit, "BindReadOnlyPaths=") {
		t.Error("rootless BuildKit unit must not receive a Docker socket or host bind mount")
	}
	if strings.Contains(buildkit, "CapabilityBoundingSet=") || strings.Contains(buildkit, "AmbientCapabilities=") {
		t.Error("rootless BuildKit service must not grant capabilities to the daemon; the guest-local setuid uidmap helper retains its packaged boundary")
	}
	for _, required := range []string{"User=opencard-caddy\n", "OPEN_CARD_CADDY_LISTEN=127.0.0.1:8080\n", "ExecStartPre=/usr/bin/grep -Eq ", "ExecStart=/opt/open-card/current/bin/caddy run ", "IPAddressDeny=any\n", "IPAddressAllow=127.0.0.0/8\n", "IPAddressAllow=::1/128\n", "NoNewPrivileges=yes\n", "ProtectSystem=strict\n", "CapabilityBoundingSet=\n", "UMask=0077\n"} {
		if !strings.Contains(caddy, required) {
			t.Errorf("caddy unit is missing %q", required)
		}
	}
	if strings.Contains(strings.ToLower(caddy), "docker.sock") || strings.Contains(caddy, "BindPaths=") || strings.Contains(caddy, "BindReadOnlyPaths=") {
		t.Error("Caddy unit must not receive a Docker socket or host bind mount")
	}
}
