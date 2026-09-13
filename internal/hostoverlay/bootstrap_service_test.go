package hostoverlay_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"go/build"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/hostoverlay"
)

func TestBootstrapServiceConstants(t *testing.T) {
	if hostoverlay.BootstrapServiceName != "acornfox-host-bootstrap.service" {
		t.Fatalf("unexpected service name: %q", hostoverlay.BootstrapServiceName)
	}
	if hostoverlay.BootstrapUnitPath != "/etc/systemd/system/acornfox-host-bootstrap.service" {
		t.Fatalf("unexpected unit path: %q", hostoverlay.BootstrapUnitPath)
	}
	if hostoverlay.BootstrapUnitRelativePath != "etc/systemd/system/acornfox-host-bootstrap.service" {
		t.Fatalf("unexpected unit relative path: %q", hostoverlay.BootstrapUnitRelativePath)
	}
	if hostoverlay.BootstrapEnableLinkPath != "/etc/systemd/system/multi-user.target.wants/acornfox-host-bootstrap.service" {
		t.Fatalf("unexpected enable link path: %q", hostoverlay.BootstrapEnableLinkPath)
	}
	if hostoverlay.BootstrapEnableLinkRelativePath != "etc/systemd/system/multi-user.target.wants/acornfox-host-bootstrap.service" {
		t.Fatalf("unexpected enable link relative path: %q", hostoverlay.BootstrapEnableLinkRelativePath)
	}
	if hostoverlay.BootstrapEnableLinkTarget != "../acornfox-host-bootstrap.service" {
		t.Fatalf("unexpected enable link target: %q", hostoverlay.BootstrapEnableLinkTarget)
	}
	if hostoverlay.BootstrapUnitFileMode != 0o644 {
		t.Fatalf("unexpected unit file mode: %v", hostoverlay.BootstrapUnitFileMode)
	}
}

func TestBootstrapUnitContentAndDirectives(t *testing.T) {
	raw := hostoverlay.BootstrapUnitBytes()
	const expectedLength = 382
	if len(raw) != expectedLength {
		t.Fatalf("bootstrap unit length mismatch: got %d, want %d", len(raw), expectedLength)
	}
	if !strings.HasSuffix(string(raw), "\n") {
		t.Fatal("bootstrap unit text must end with newline")
	}

	const expectedSHA = "3911f5535455c902d848d0a0da38a62245f47d4560d21eb1350613087608e7c9"
	digest := sha256.Sum256(raw)
	computedSHA := hex.EncodeToString(digest[:])
	if computedSHA != expectedSHA {
		t.Fatalf("sha mismatch: got %s, want %s", computedSHA, expectedSHA)
	}
	if hostoverlay.BootstrapUnitSHA256() != expectedSHA {
		t.Fatalf("BootstrapUnitSHA256 mismatch: got %s, want %s", hostoverlay.BootstrapUnitSHA256(), expectedSHA)
	}

	text := hostoverlay.BootstrapUnitText
	requiredDirectives := []string{
		"[Unit]",
		"After=network-online.target docker.service postgresql.service acornfox-upgrade-safe.target",
		"Wants=network-online.target",
		"Requires=acornfox-upgrade-safe.target",
		"[Service]",
		"Type=oneshot",
		"RuntimeDirectory=acornfox-host",
		"RuntimeDirectoryMode=0700",
		"ExecStart=/usr/local/libexec/acornfox-host-bootstrap start",
		"RemainAfterExit=yes",
		"TimeoutStartSec=300",
		"[Install]",
		"WantedBy=multi-user.target",
	}

	for _, directive := range requiredDirectives {
		if !strings.Contains(text, directive) {
			t.Fatalf("missing required directive: %q", directive)
		}
	}

	// Defensive copy verification
	b1 := hostoverlay.BootstrapUnitBytes()
	b1[0] = '^'
	b2 := hostoverlay.BootstrapUnitBytes()
	if bytes.Equal(b1, b2) {
		t.Fatal("BootstrapUnitBytes must return a defensive copy")
	}
}

func TestHostOverlayPackageIsolation(t *testing.T) {
	pkg, err := build.Import("github.com/open-card/open-card/internal/hostoverlay", ".", build.FindOnly)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := build.Default.ImportDir(pkg.Dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	forbiddenPrefixes := []string{
		"github.com/open-card/open-card/internal/install",
		"github.com/open-card/open-card/internal/desktopupdate",
		"github.com/open-card/open-card/internal/hostprovision",
	}
	for _, imp := range loaded.Imports {
		for _, forbidden := range forbiddenPrefixes {
			if strings.HasPrefix(imp, forbidden) {
				t.Fatalf("leaf package hostoverlay must not import %q (found %q)", forbidden, imp)
			}
		}
	}
}
