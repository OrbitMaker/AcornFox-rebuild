//go:build linux

package hostprovision

import "github.com/open-card/open-card/internal/desktopupdate"

func defaultTransport() desktopupdate.GuestTransport {
	return desktopupdate.NewPrivilegedLocalGuestTransport()
}
