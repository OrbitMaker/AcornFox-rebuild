package install

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-card/open-card/internal/hostoverlay"
)

func writeTestCanonicalBootstrapUnit(t *testing.T, f acornFoxProductionScopeFixture) string {
	t.Helper()
	unitPath := filepath.Join(f.host, filepath.FromSlash(hostoverlay.BootstrapUnitRelativePath))
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, hostoverlay.BootstrapUnitBytes(), hostoverlay.BootstrapUnitFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unitPath, hostoverlay.BootstrapUnitFileMode); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	f.owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{}
	return unitPath
}

func ensureTestWantsDir(t *testing.T, f acornFoxProductionScopeFixture) string {
	t.Helper()
	wantsDir := filepath.Join(f.host, "etc", "systemd", "system", "multi-user.target.wants")
	if err := os.MkdirAll(wantsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(wantsDir)
	if err != nil {
		t.Fatal(err)
	}
	f.owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{}
	return wantsDir
}

func createTestCanonicalBootstrapEnableLink(t *testing.T, f acornFoxProductionScopeFixture) string {
	t.Helper()
	wantsDir := ensureTestWantsDir(t, f)
	linkPath := filepath.Join(wantsDir, hostoverlay.BootstrapServiceName)
	if err := os.Symlink(hostoverlay.BootstrapEnableLinkTarget, linkPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	f.owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{}
	return linkPath
}

func runTestScopeValidation(t *testing.T, f acornFoxProductionScopeFixture) error {
	t.Helper()
	root, err := f.store.openHostRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	return acornFoxValidateProductionManagedScope(root, f.store, f.entries)
}

func TestAcornFoxHostOverlayAcceptedStates(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, acornFoxProductionScopeFixture)
	}{
		{
			name: "state-none-neither-exists",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				// Neither unit nor link created
			},
		},
		{
			name: "state-exact-unit-only-wants-absent",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
			},
		},
		{
			name: "state-exact-unit-only-wants-present-link-absent",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				ensureTestWantsDir(t, f)
			},
		},
		{
			name: "state-exact-unit-and-enable-link",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				createTestCanonicalBootstrapEnableLink(t, f)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newAcornFoxProductionScopeFixture(t)
			test.setup(t, f)
			if err := runTestScopeValidation(t, f); err != nil {
				t.Fatalf("expected accepted state %s to pass scope check, got: %v", test.name, err)
			}
		})
	}
}

func TestAcornFoxHostOverlayParentValidation(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, acornFoxProductionScopeFixture)
		want error
	}{
		{
			name: "wants-parent-relative-symlink-to-otherdir-with-canonical-link",
			run: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				// Create redirected-wants directory (0755, root-owned)
				redirected := filepath.Join(f.host, "etc", "systemd", "system", "redirected-wants")
				if err := os.MkdirAll(redirected, 0o755); err != nil {
					t.Fatal(err)
				}
				redInfo, err := os.Lstat(redirected)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, redInfo)] = acornFoxInstallPrincipal{}

				// Put canonical link in redirected-wants pointing to "../acornfox-host-bootstrap.service"
				redLink := filepath.Join(redirected, hostoverlay.BootstrapServiceName)
				if err := os.Symlink(hostoverlay.BootstrapEnableLinkTarget, redLink); err != nil {
					t.Fatal(err)
				}
				redLinkInfo, err := os.Lstat(redLink)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, redLinkInfo)] = acornFoxInstallPrincipal{}

				// Symlink multi-user.target.wants -> redirected-wants
				wantsPath := filepath.Join(f.host, "etc", "systemd", "system", "multi-user.target.wants")
				if err := os.Symlink("redirected-wants", wantsPath); err != nil {
					t.Fatal(err)
				}
				wantsSymInfo, err := os.Lstat(wantsPath)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, wantsSymInfo)] = acornFoxInstallPrincipal{}
			},
			want: ErrAcornFoxLiveConflict,
		},
		{
			name: "wants-parent-escaping-relative-symlink",
			run: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				wantsPath := filepath.Join(f.host, "etc", "systemd", "system", "multi-user.target.wants")
				if err := os.Symlink("../../other", wantsPath); err != nil {
					t.Fatal(err)
				}
				wantsSymInfo, err := os.Lstat(wantsPath)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, wantsSymInfo)] = acornFoxInstallPrincipal{}
			},
			want: ErrAcornFoxLiveConflict,
		},
		{
			name: "wants-parent-regular-file",
			run: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				wantsPath := filepath.Join(f.host, "etc", "systemd", "system", "multi-user.target.wants")
				if err := os.WriteFile(wantsPath, []byte("regular-file"), 0o644); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(wantsPath)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{}
			},
			want: ErrAcornFoxLiveConflict,
		},
		{
			name: "wants-parent-mode-0700",
			run: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				wantsPath := filepath.Join(f.host, "etc", "systemd", "system", "multi-user.target.wants")
				if err := os.MkdirAll(wantsPath, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(wantsPath, 0o700); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(wantsPath)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{}
			},
			want: ErrAcornFoxLiveConflict,
		},
		{
			name: "wants-parent-mode-0775",
			run: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				wantsPath := filepath.Join(f.host, "etc", "systemd", "system", "multi-user.target.wants")
				if err := os.MkdirAll(wantsPath, 0o775); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(wantsPath, 0o775); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(wantsPath)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{}
			},
			want: ErrAcornFoxLiveConflict,
		},
		{
			name: "wants-parent-owner-non-root",
			run: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				wantsPath := filepath.Join(f.host, "etc", "systemd", "system", "multi-user.target.wants")
				if err := os.MkdirAll(wantsPath, 0o755); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(wantsPath)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{uid: 1001, gid: 1001}
			},
			want: ErrAcornFoxLiveConflict,
		},
		{
			name: "wants-parent-absent-staging-accepted",
			run: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				wantsPath := filepath.Join(f.host, "etc", "systemd", "system", "multi-user.target.wants")
				_ = os.RemoveAll(wantsPath)
			},
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newAcornFoxProductionScopeFixture(t)
			test.run(t, f)
			err := runTestScopeValidation(t, f)
			if !errors.Is(err, test.want) {
				t.Fatalf("%s: err=%v, want=%v", test.name, err, test.want)
			}
		})
	}
}

func TestAcornFoxHostOverlayNegativeClasses(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, acornFoxProductionScopeFixture)
	}{
		{
			name: "link-only-unit-absent",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				createTestCanonicalBootstrapEnableLink(t, f)
			},
		},
		{
			name: "unit-content-mismatch-corrupted",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				unitPath := writeTestCanonicalBootstrapUnit(t, f)
				bad := []byte(hostoverlay.BootstrapUnitText + "# foreign comment\n")
				if err := os.WriteFile(unitPath, bad, hostoverlay.BootstrapUnitFileMode); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unit-content-mismatch-truncated",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				unitPath := writeTestCanonicalBootstrapUnit(t, f)
				bad := []byte("[Unit]\nAfter=network-online.target\n")
				if err := os.WriteFile(unitPath, bad, hostoverlay.BootstrapUnitFileMode); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unit-content-mismatch-empty",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				unitPath := writeTestCanonicalBootstrapUnit(t, f)
				if err := os.WriteFile(unitPath, []byte{}, hostoverlay.BootstrapUnitFileMode); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unit-mode-mismatch-0755",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				unitPath := writeTestCanonicalBootstrapUnit(t, f)
				if err := os.Chmod(unitPath, 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unit-mode-mismatch-0600",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				unitPath := writeTestCanonicalBootstrapUnit(t, f)
				if err := os.Chmod(unitPath, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unit-mode-mismatch-0666",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				unitPath := writeTestCanonicalBootstrapUnit(t, f)
				if err := os.Chmod(unitPath, 0o666); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unit-owner-mismatch-non-root",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				unitPath := writeTestCanonicalBootstrapUnit(t, f)
				info, err := os.Lstat(unitPath)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{uid: 1001, gid: 1001}
			},
		},
		{
			name: "unit-linkcount-mismatch-hardlink",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				unitPath := writeTestCanonicalBootstrapUnit(t, f)
				if err := os.Link(unitPath, unitPath+".hardlink"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unit-type-mismatch-symlink",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				unitPath := filepath.Join(f.host, filepath.FromSlash(hostoverlay.BootstrapUnitRelativePath))
				if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
					t.Fatal(err)
				}
				targetPath := filepath.Join(f.host, "etc", "actual-unit")
				if err := os.WriteFile(targetPath, hostoverlay.BootstrapUnitBytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(targetPath, unitPath); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(unitPath)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{}
			},
		},
		{
			name: "unit-type-mismatch-directory",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				unitPath := filepath.Join(f.host, filepath.FromSlash(hostoverlay.BootstrapUnitRelativePath))
				if err := os.MkdirAll(unitPath, 0o755); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(unitPath)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{}
			},
		},
		{
			name: "enable-link-target-mismatch-absolute",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				wantsDir := ensureTestWantsDir(t, f)
				linkPath := filepath.Join(wantsDir, hostoverlay.BootstrapServiceName)
				if err := os.Symlink("/etc/systemd/system/acornfox-host-bootstrap.service", linkPath); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(linkPath)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{}
			},
		},
		{
			name: "enable-link-target-mismatch-wrong-relative",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				wantsDir := ensureTestWantsDir(t, f)
				linkPath := filepath.Join(wantsDir, hostoverlay.BootstrapServiceName)
				if err := os.Symlink("../other.service", linkPath); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(linkPath)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{}
			},
		},
		{
			name: "enable-link-target-mismatch-bare-filename",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				wantsDir := ensureTestWantsDir(t, f)
				linkPath := filepath.Join(wantsDir, hostoverlay.BootstrapServiceName)
				if err := os.Symlink(hostoverlay.BootstrapServiceName, linkPath); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(linkPath)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{}
			},
		},
		{
			name: "enable-link-owner-mismatch-non-root",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				linkPath := createTestCanonicalBootstrapEnableLink(t, f)
				info, err := os.Lstat(linkPath)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{uid: 1001, gid: 1001}
			},
		},
		{
			name: "enable-link-type-mismatch-regular-file",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				wantsDir := ensureTestWantsDir(t, f)
				linkPath := filepath.Join(wantsDir, hostoverlay.BootstrapServiceName)
				if err := os.WriteFile(linkPath, []byte("not-a-symlink"), 0o644); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(linkPath)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{}
			},
		},
		{
			name: "enable-link-type-mismatch-directory",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				wantsDir := ensureTestWantsDir(t, f)
				linkPath := filepath.Join(wantsDir, hostoverlay.BootstrapServiceName)
				if err := os.MkdirAll(linkPath, 0o755); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(linkPath)
				if err != nil {
					t.Fatal(err)
				}
				f.owners[acornFoxTestInfoKey(t, info)] = acornFoxInstallPrincipal{}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newAcornFoxProductionScopeFixture(t)
			test.setup(t, f)
			err := runTestScopeValidation(t, f)
			if !errors.Is(err, ErrAcornFoxLiveConflict) {
				t.Fatalf("expected negative class %s to fail with ErrAcornFoxLiveConflict, got: %v", test.name, err)
			}
		})
	}
}

func TestAcornFoxHostOverlayForeignUnitRejectionPreserved(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, acornFoxProductionScopeFixture)
	}{
		{
			name: "foreign-extra-acornfox-unit",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				createTestCanonicalBootstrapEnableLink(t, f)
				path := filepath.Join(f.host, "etc", "systemd", "system", "acornfox-extra.service")
				if err := os.WriteFile(path, []byte("[Unit]\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "foreign-acornfox-similar-prefix",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				path := filepath.Join(f.host, "etc", "systemd", "system", "acornfox-host-bootstrap-worker.service")
				if err := os.WriteFile(path, []byte("[Unit]\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "foreign-acornfox-dropin-directory",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				path := filepath.Join(f.host, "etc", "systemd", "system", "acornfox-host-bootstrap.service.d")
				if err := os.MkdirAll(path, 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "foreign-acornfox-requires-directory",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				path := filepath.Join(f.host, "etc", "systemd", "system", "acornfox-host-bootstrap.service.requires")
				if err := os.MkdirAll(path, 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newAcornFoxProductionScopeFixture(t)
			test.setup(t, f)
			err := runTestScopeValidation(t, f)
			if !errors.Is(err, ErrAcornFoxLiveConflict) {
				t.Fatalf("expected foreign unit %s to fail with ErrAcornFoxLiveConflict, got: %v", test.name, err)
			}
		})
	}
}

func TestAcornFoxHostOverlayUnrelatedEntriesPreserved(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, acornFoxProductionScopeFixture)
	}{
		{
			name: "unrelated-systemd-service-with-overlay",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				createTestCanonicalBootstrapEnableLink(t, f)
				unrelated := filepath.Join(f.host, "etc", "systemd", "system", "other.service")
				if err := os.WriteFile(unrelated, []byte("[Unit]\nDescription=Other\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unrelated-wants-entry-with-overlay",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				createTestCanonicalBootstrapEnableLink(t, f)
				wantsDir := filepath.Join(f.host, "etc", "systemd", "system", "multi-user.target.wants")
				if err := os.Symlink("../other.service", filepath.Join(wantsDir, "other.service")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unrelated-wants-entry-unit-only",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				writeTestCanonicalBootstrapUnit(t, f)
				wantsDir := ensureTestWantsDir(t, f)
				if err := os.Symlink("/lib/systemd/system/docker.service", filepath.Join(wantsDir, "docker.service")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unrelated-wants-entry-none-state",
			setup: func(t *testing.T, f acornFoxProductionScopeFixture) {
				wantsDir := ensureTestWantsDir(t, f)
				if err := os.Symlink("../nginx.service", filepath.Join(wantsDir, "nginx.service")); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newAcornFoxProductionScopeFixture(t)
			test.setup(t, f)
			if err := runTestScopeValidation(t, f); err != nil {
				t.Fatalf("expected unrelated entry %s to pass scope check, got: %v", test.name, err)
			}
		})
	}
}
