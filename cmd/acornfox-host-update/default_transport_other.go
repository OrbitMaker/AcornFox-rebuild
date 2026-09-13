//go:build !linux

package main

import "github.com/open-card/open-card/internal/desktopupdate"

func defaultGuestTransport() desktopupdate.GuestTransport {
	return nil
}
