//go:build windows

package desktopupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	modkernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetSystemDirectoryW = modkernel32.NewProc("GetSystemDirectoryW")
)

const windowsHelperTimeout = 15 * time.Second

func withWindowsTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, windowsHelperTimeout)
}

// getSystemPowerShellPath locates powershell.exe using the official Windows API GetSystemDirectoryW,
// checking buffer bounds and expanding dynamically, never relying on PATH environment variables.
func getSystemPowerShellPath() (string, error) {
	buf := make([]uint16, 260)
	for {
		r, _, err := procGetSystemDirectoryW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if r == 0 {
			return "", fmt.Errorf("GetSystemDirectoryW failed: %v", err)
		}
		if r >= uintptr(len(buf)) {
			buf = make([]uint16, r+1)
			continue
		}
		sysDir := syscall.UTF16ToString(buf[:r])
		psPath := filepath.Join(sysDir, "WindowsPowerShell", "v1.0", "powershell.exe")
		if _, err := os.Stat(psPath); err != nil {
			return "", fmt.Errorf("system powershell not found at %s: %v", psPath, err)
		}
		return psPath, nil
	}
}

type windowsSecurityResult struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// checkWindowsObjectSecurity verifies owner and DACL for a file or directory:
// 1. Owner must be Current User, SYSTEM, or Built-in Administrators.
// 2. No other SID may have Write, Delete, ChangePermissions, or TakeOwnership rights.
func checkWindowsObjectSecurity(ctx context.Context, path string) error {
	callCtx, cancel := withWindowsTimeout(ctx)
	defer cancel()

	psPath, err := getSystemPowerShellPath()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidParentDir, err)
	}

	script := `
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$rawInput = [Console]::In.ReadToEnd()
$data = $rawInput | ConvertFrom-Json
$path = $data.path

$acl = Get-Acl -LiteralPath $path
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$adminGroup = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Value
$systemGroup = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")).Value

# Verify Owner
$ownerSid = $acl.Owner
try {
    $ownerSid = (New-Object System.Security.Principal.NTAccount($acl.Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value
} catch {}

if ($ownerSid -ne $currentUser -and $ownerSid -ne $adminGroup -and $ownerSid -ne $systemGroup) {
    [PSCustomObject]@{ allowed = $false; reason = ("untrusted owner " + $acl.Owner) } | ConvertTo-Json -Compress
    exit 0
}

# Accurate dangerous access mask: WriteData/CreateFiles, AppendData/CreateDirectories, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership
$dangerousRights = [System.Security.AccessControl.FileSystemRights]"Write, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership"

foreach ($access in $acl.Access) {
    if ($access.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
        continue
    }
    $sid = $access.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($sid -ne $currentUser -and $sid -ne $adminGroup -and $sid -ne $systemGroup) {
        if ($access.FileSystemRights -band $dangerousRights) {
            [PSCustomObject]@{ allowed = $false; reason = ("unauthorized SID $sid has rights " + $access.FileSystemRights) } | ConvertTo-Json -Compress
            exit 0
        }
    }
}
[PSCustomObject]@{ allowed = $true; reason = "" } | ConvertTo-Json -Compress
`
	cmd := exec.CommandContext(callCtx, psPath, "-NoProfile", "-NonInteractive", "-Command", script)
	inputData, err := json.Marshal(map[string]string{"path": path})
	if err != nil {
		return fmt.Errorf("%w: marshal input: %v", ErrInvalidParentDir, err)
	}
	cmd.Stdin = strings.NewReader(string(inputData))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("%w: acl check failed: %v", ErrInvalidParentDir, err)
	}
	var res windowsSecurityResult
	if err := json.Unmarshal(out, &res); err != nil {
		return fmt.Errorf("%w: parse acl output: %v", ErrInvalidParentDir, err)
	}
	if !res.Allowed {
		return fmt.Errorf("%w: security check rejected (%s): %s", ErrInvalidParentDir, path, res.Reason)
	}
	return nil
}

// checkParentDirectoryPermissions validates that parent is an actual directory and satisfies Windows security checks.
func checkParentDirectoryPermissions(ctx context.Context, info os.FileInfo, path string) error {
	if !info.IsDir() {
		return fmt.Errorf("%w: parent is not a directory", ErrInvalidParentDir)
	}
	return checkWindowsObjectSecurity(ctx, path)
}

// secureNewStageDirectory constructs a brand new protected DACL for the new staging directory,
// granting exclusive FullControl to Current User, SYSTEM, Administrators, with inheritance disabled.
func secureNewStageDirectory(ctx context.Context, stageDirPath string) error {
	callCtx, cancel := withWindowsTimeout(ctx)
	defer cancel()

	psPath, err := getSystemPowerShellPath()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDownloadFailed, err)
	}

	script := `
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$rawInput = [Console]::In.ReadToEnd()
$data = $rawInput | ConvertFrom-Json
$path = $data.path

# Construct brand new DirectorySecurity object without inheriting or copying stale parent rules
$dacl = New-Object System.Security.AccessControl.DirectorySecurity
$dacl.SetAccessRuleProtection($true, $false)

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$adminGroup = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$systemGroup = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")

$ruleUser = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$ruleAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule($adminGroup, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule($systemGroup, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")

$dacl.AddAccessRule($ruleUser)
$dacl.AddAccessRule($ruleAdmin)
$dacl.AddAccessRule($ruleSystem)

Set-Acl -LiteralPath $path -AclObject $dacl
[PSCustomObject]@{ allowed = $true; reason = "" } | ConvertTo-Json -Compress
`
	cmd := exec.CommandContext(callCtx, psPath, "-NoProfile", "-NonInteractive", "-Command", script)
	inputData, err := json.Marshal(map[string]string{"path": stageDirPath})
	if err != nil {
		return fmt.Errorf("%w: marshal input: %v", ErrDownloadFailed, err)
	}
	cmd.Stdin = strings.NewReader(string(inputData))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("%w: set stage dacl failed: %v", ErrDownloadFailed, err)
	}
	var res windowsSecurityResult
	if err := json.Unmarshal(out, &res); err != nil {
		return fmt.Errorf("%w: parse acl output: %v", ErrDownloadFailed, err)
	}
	return nil
}

func verifyStagedFileSecurity(ctx context.Context, stageDirPath, filePath string) error {
	fi, err := os.Lstat(filePath)
	if err != nil {
		return fmt.Errorf("%w: stat payload failed: %v", ErrDownloadFailed, err)
	}
	if !fi.Mode().IsRegular() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: payload must be a regular file", ErrDownloadFailed)
	}
	// Check payload file DACL & Owner (using regular file check, not directory check)
	if err := checkWindowsObjectSecurity(ctx, filePath); err != nil {
		return fmt.Errorf("%w: payload file permission check failed: %v", ErrDownloadFailed, err)
	}

	di, err := os.Lstat(stageDirPath)
	if err != nil {
		return fmt.Errorf("%w: stat stage dir failed: %v", ErrDownloadFailed, err)
	}
	if !di.IsDir() || di.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: stage path must be a directory", ErrDownloadFailed)
	}
	if err := checkWindowsObjectSecurity(ctx, stageDirPath); err != nil {
		return fmt.Errorf("%w: stage dir permission check failed: %v", ErrDownloadFailed, err)
	}
	return nil
}

// Note on Windows directory synchronization:
// Windows directories do not support FlushFileBuffers; file payload is explicitly synced via File.Sync().
// Staging provides an atomic, re-downloadable asset; final activation transaction validates integrity independently.
func syncDirectory(dirPath string) error {
	return nil
}
