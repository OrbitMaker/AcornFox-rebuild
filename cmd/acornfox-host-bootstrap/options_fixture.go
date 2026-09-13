//go:build fixture

package main

import (
	"os"
	"path/filepath"
	"time"
)

func getProductionBootstrapOptions() BootstrapOptions {
	fixtureDir := os.Getenv("ACORNFOX_FIXTURE_DIR")
	if fixtureDir == "" {
		fixtureDir = "/tmp/acornfox-fixture"
	}
	return BootstrapOptions{
		ConfigPath:     filepath.Join(fixtureDir, "host-runtime.json"),
		BootstrapRoot:  filepath.Join(fixtureDir, "bootstrap"),
		SlotsRoot:      filepath.Join(fixtureDir, "slots"),
		InvocationLock: filepath.Join(fixtureDir, "invocation.lock"),
		AllowNonRoot:   true,
		OutcomeTimeout: 30 * time.Second,
	}
}

func getChildEnvironment() []string {
	env := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	for _, k := range []string{"TEST_CHILD_BEHAVIOR", "ACORNFOX_FIXTURE_DIR", "ACORNFOX_FIXTURE_SERVER", "ACORNFOX_FIXTURE_ALLOW_NONROOT"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}
