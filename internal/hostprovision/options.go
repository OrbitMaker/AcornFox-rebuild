package hostprovision

import (
	"path/filepath"

	"github.com/open-card/open-card/internal/desktopupdate"
	"github.com/open-card/open-card/internal/hostconfig"
	"github.com/open-card/open-card/internal/hostoverlay"
)

// DefaultGuestInstancePath is the fixed path to the guest instance descriptor.
const DefaultGuestInstancePath = "/etc/acornfox-host/guest-instance.json"

// ProvisionPaths defines the target file and directory paths for host provisioning.
type ProvisionPaths struct {
	BootstrapExecutable string // Target path for stable bootstrap binary (/usr/local/libexec/acornfox-host-bootstrap)
	BootstrapRoot       string // Root for external C0 tree (/usr/local/lib/acornfox-host/bootstrap)
	LauncherPath        string // Launcher executable path (.../bootstrap/launcher/acornfox-host-launcher)
	ControllerPath      string // Controller executable path (.../bootstrap/controller/acornfox-host-update)
	ConfigPath          string // Target path for host-runtime.json (/etc/acornfox-host/host-runtime.json)
	GuestInstancePath   string // Path to guest-instance.json (/etc/acornfox-host/guest-instance.json)
	SlotsRoot           string // Root for HostSlots (/var/lib/acornfox-host/slots)
	SlotsLock           string // Precreated slot lockfile (/var/lib/acornfox-host/slots/lock)
	ControllerRoot      string // Root for HostController (/var/lib/acornfox-host/controller)
	UnitPath            string // Canonical host bootstrap unit file (/etc/systemd/system/acornfox-host-bootstrap.service)
	EnableLinkPath      string // Canonical enable symlink (/etc/systemd/system/multi-user.target.wants/acornfox-host-bootstrap.service)
}

// provisionOptions configures internal execution. It is unexported to eliminate
// the test bypass surface from the production API.
type provisionOptions struct {
	allowNonRoot      bool
	paths             ProvisionPaths
	guestTransport    desktopupdate.GuestTransport
	beforePublishHook func() error
	ancestorHook      func(phase string, targetPath string) error
}

// DefaultProductionPaths returns the fixed production paths.
func DefaultProductionPaths() ProvisionPaths {
	return ProvisionPaths{
		BootstrapExecutable: hostconfig.DefaultBootstrapExecutablePath,
		BootstrapRoot:       hostconfig.DefaultBootstrapRoot,
		LauncherPath:        filepath.Join(hostconfig.DefaultBootstrapRoot, "launcher", "acornfox-host-launcher"),
		ControllerPath:      filepath.Join(hostconfig.DefaultBootstrapRoot, "controller", "acornfox-host-update"),
		ConfigPath:          hostconfig.DefaultHostRuntimeConfigPath,
		GuestInstancePath:   DefaultGuestInstancePath,
		SlotsRoot:           hostconfig.DefaultSlotsRoot,
		SlotsLock:           filepath.Join(hostconfig.DefaultSlotsRoot, "lock"),
		ControllerRoot:      hostconfig.DefaultControllerRoot,
		UnitPath:            hostoverlay.BootstrapUnitPath,
		EnableLinkPath:      hostoverlay.BootstrapEnableLinkPath,
	}
}

// defaultProductionOptions returns the internal options for production runs.
func defaultProductionOptions() provisionOptions {
	return provisionOptions{
		allowNonRoot:   false,
		paths:          DefaultProductionPaths(),
		guestTransport: defaultTransport(),
	}
}
