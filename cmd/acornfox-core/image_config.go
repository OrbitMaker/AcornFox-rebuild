package main

import (
	"log"
	"os"
	"time"

	"github.com/open-card/open-card/internal/imageexecution"
)

// CoreImageConfig holds parameters for the image execution worker and role connection.
type CoreImageConfig struct {
	Enabled       bool
	Binding       *imageexecution.RuntimePeerBinding
	PollInterval  time.Duration
	LeaseDuration time.Duration
	MaxAttempts   int
}

func loadCoreImageConfig(bindingPath string) CoreImageConfig {
	if bindingPath == "" {
		bindingPath = os.Getenv("ACORNFOX_CONTAINER_BINDING")
	}

	binding, err := imageexecution.LoadProtectedRuntimePeerBinding(bindingPath)
	if err != nil {
		log.Printf("load container runtime peer binding failed: %v", err)
		return CoreImageConfig{Enabled: false}
	}
	if binding == nil {
		// Binding file absent or unconfigured -> execution worker disabled, auth remains available
		return CoreImageConfig{Enabled: false}
	}

	return CoreImageConfig{
		Enabled:       true,
		Binding:       binding,
		PollInterval:  500 * time.Millisecond,
		LeaseDuration: 2 * time.Minute,
		MaxAttempts:   3,
	}
}
