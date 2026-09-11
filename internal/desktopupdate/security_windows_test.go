//go:build windows

package desktopupdate

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestWindowsObjectSecurityReal executes on real native Windows environments.
// It verifies:
// 1. Regular valid payload passing security checks.
// 2. Paths with Chinese characters and spaces/quotes without command injection.
// 3. Rejection of untrusted owners or wide write permissions.
func TestWindowsObjectSecurityReal(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Valid regular directory and file created by current user
	t.Run("valid_current_user_file", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "valid_payload.bin")
		if err := os.WriteFile(testFile, []byte("valid"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := checkWindowsObjectSecurity(context.Background(), testFile); err != nil {
			t.Fatalf("expected valid file to pass security check: %v", err)
		}
	})

	// 2. Paths with Chinese characters, spaces, and quote-like names
	t.Run("unicode_spaces_and_special_paths", func(t *testing.T) {
		unicodeDir := filepath.Join(tempDir, "更新 目录 '测试'")
		if err := os.Mkdir(unicodeDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := secureNewStageDirectory(context.Background(), unicodeDir); err != nil {
			t.Fatalf("secureNewStageDirectory failed on unicode path: %v", err)
		}

		specialFile := filepath.Join(unicodeDir, "测试载荷 (1).bin")
		if err := os.WriteFile(specialFile, []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}

		if err := verifyStagedFileSecurity(context.Background(), unicodeDir, specialFile); err != nil {
			t.Fatalf("verifyStagedFileSecurity failed on unicode path: %v", err)
		}
	})

	// 3. Reject directory with wide write permissions (Everyone allowed Write)
	t.Run("reject_wide_write_acl", func(t *testing.T) {
		insecureDir := filepath.Join(tempDir, "insecure_dir")
		if err := os.Mkdir(insecureDir, 0700); err != nil {
			t.Fatal(err)
		}

		psPath, err := getSystemPowerShellPath()
		if err != nil {
			t.Fatal(err)
		}

		// Use fixed JSON stdin script without command line string injection
		grantScript := `
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$rawInput = [Console]::In.ReadToEnd()
$data = $rawInput | ConvertFrom-Json
$p = $data.path

$acl = Get-Acl -LiteralPath $p
$everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($everyone, "Write", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $p -AclObject $acl
`
		cmd := exec.Command(psPath, "-NoProfile", "-NonInteractive", "-Command", grantScript)
		inputData, err := json.Marshal(map[string]string{"path": insecureDir})
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdin = strings.NewReader(string(inputData))
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("failed to grant wide ACL for test: %v, out: %s", err, out)
		}

		di, err := os.Lstat(insecureDir)
		if err != nil {
			t.Fatal(err)
		}
		err = checkParentDirectoryPermissions(context.Background(), di, insecureDir)
		if err == nil || !strings.Contains(err.Error(), "unauthorized SID S-1-1-0") {
			t.Fatalf("expected rejection of wide write ACL, got: %v", err)
		}
	})
}
