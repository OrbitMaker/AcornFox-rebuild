//go:build !darwin && !linux

package source

import "os/exec"

// Non-Unix platforms retain the parent-only fallback until a Windows Job
// Object implementation is supplied. Open Card's production installer targets
// Linux, where the process-group implementation above is always selected.
func startGitProcessGroup(command *exec.Cmd) {}

func stopGitProcessGroup(command *exec.Cmd) {
	if command != nil && command.Process != nil {
		_ = command.Process.Kill()
	}
}
