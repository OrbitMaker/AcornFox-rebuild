//go:build !darwin && !linux

package source

func workspaceFilesystemAvailabilityForRoot(string) (workspaceFilesystemAvailability, error) {
	return workspaceFilesystemAvailability{}, errWorkspaceUnavailable
}
