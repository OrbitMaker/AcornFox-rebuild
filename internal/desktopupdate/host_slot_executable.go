package desktopupdate

import (
	"context"
	"io"
	"os"
)

// HostSlotExecutableIdentity represents the verified signed identity of a slot
// executable (SHA256 digest and byte size) as declared in the host bundle manifest.
type HostSlotExecutableIdentity struct {
	SHA256 string
	Size   int64
}

// WithLauncherFD verifies and opens the launcher executable within the slot view,
// passes the live file descriptor and its signed identity to callback, and closes
// the descriptor upon callback return.
//
// The descriptor is opened through the pinned slot root (v.root) and checked against
// asset requirements (regular file, current user ownership, exact permissions, no
// hard links or symlinks, and matching CPU architecture). It is valid only for
// the duration of the callback and must not be retained.
func (v HostSlotView) WithLauncherFD(
	ctx context.Context,
	callback func(*os.File, HostSlotExecutableIdentity) error,
) error {
	if callback == nil || ctx == nil {
		return ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.root == nil || v.id == "" || v.launcherRel == "" || v.launcherFile.Path == "" {
		return ErrHostConflict
	}

	f, err := v.root.Open(v.launcherRel)
	if err != nil {
		return ErrHostConflict
	}
	defer f.Close()

	if err := ctx.Err(); err != nil {
		return err
	}

	// Verify asset checks (mode, owner, nlink, symlink, same file as v.launcher)
	if err := slotCheckAsset(f, v.launcher, v.launcherFile.Mode, !v.external); err != nil {
		return ErrHostConflict
	}

	// Verify SHA256 and size against the signed bundle record
	if err := slotHashFile(f, v.launcherFile); err != nil {
		return ErrHostConflict
	}

	// Verify target CPU architecture and Mach-O/ELF/PE headers
	if err := slotCPU(f, v.osName, v.arch); err != nil {
		return ErrHostConflict
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	identity := HostSlotExecutableIdentity{
		SHA256: v.launcherFile.SHA256,
		Size:   v.launcherFile.Size,
	}

	return callback(f, identity)
}
