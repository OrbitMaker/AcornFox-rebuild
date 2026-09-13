package main

import (
	"github.com/open-card/open-card/internal/desktopupdate"
	"github.com/open-card/open-card/internal/hostconfig"
)

func convertBootstrapSpec(c hostconfig.HostBootstrapSpecConfig) desktopupdate.HostBootstrapSpec {
	files := make([]desktopupdate.HostBundleFile, len(c.Files))
	for i, f := range c.Files {
		files[i] = desktopupdate.HostBundleFile{
			Path:   f.Path,
			SHA256: f.SHA256,
			Size:   f.Size,
			Mode:   f.Mode,
		}
	}
	return desktopupdate.HostBootstrapSpec{
		Root:               c.Root,
		OS:                 c.OS,
		Architecture:       c.Architecture,
		Version:            c.Version,
		Launcher:           c.Launcher,
		Controller:         c.Controller,
		ControllerProtocol: c.ControllerProtocol,
		InstanceProtocol:   c.InstanceProtocol,
		BackendAPIProtocol: c.BackendAPIProtocol,
		Files:              files,
	}
}
