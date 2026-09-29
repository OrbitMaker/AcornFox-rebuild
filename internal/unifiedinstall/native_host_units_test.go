package unifiedinstall

import (
	"strings"
	"testing"
)

func TestNativeHostUnitsArePreparedAndScoped(t *testing.T) {
	ids := nativeHostIDs{IPC: 1901, CoreGID: 1001, CaddyUID: 1006, BuildkitUID: 1007}
	files, err := nativeHostFiles("/var/lib/acornfox/unified-install/ready-0123456789abcdef0123456789abcdef", "release-1.0.0", ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(nativeHostOwnedFilePaths()) {
		t.Fatalf("owned file count=%d", len(files))
	}
	byPath := map[string]string{}
	for _, file := range files {
		if _, duplicate := byPath[file.path]; duplicate {
			t.Fatalf("duplicate owned file %s", file.path)
		}
		byPath[file.path] = string(file.data)
	}
	core := byPath["/etc/systemd/system/acornfox-core.service"]
	if !strings.Contains(core, "native-core-launch --stage /var/lib/acornfox/unified-install/ready-") || !strings.Contains(core, "LoadCredential=acornfox-setup-token:/etc/acornfox/trust/acornfox-setup-token") || strings.Contains(core, "Requires=acornfox-gateway") || strings.Contains(core, "Requires=acornfox-source") || strings.Contains(core, "Requires=docker") || !strings.Contains(core, "User=root") {
		t.Fatal("Core root launcher unit gained business-role prerequisites or lost its fixed stage")
	}
	for _, name := range []string{"acornfox-container", "acornfox-source-build", "acornfox-gateway"} {
		unit := byPath["/etc/systemd/system/"+name+".service"]
		if strings.Contains(unit, "RuntimeDirectory=") || !strings.Contains(unit, "--socket-gid 1901") {
			t.Fatalf("%s may reset its publisher-owned IPC directory or lacks fixed group", name)
		}
	}
	source := byPath["/etc/systemd/system/acornfox-source-build.service"]
	if !strings.Contains(source, "SupplementaryGroups=acornfox-ipc acornfox-buildkit\n") || strings.Contains(source, " docker") || strings.Contains(source, " sudo") || strings.Contains(source, "CAP_NET_ADMIN") {
		t.Fatal("Source adapter lacks its exact IPC/BuildKit groups or gained elevated authority")
	}
	if !strings.Contains(byPath["/etc/systemd/system/acornfox-buildkit.service"], "--group 0\n") {
		t.Fatal("rootless BuildKit socket group must stay namespace GID 0")
	}
	if !strings.Contains(byPath["/etc/systemd/system/acornfox-buildkit.service"], "/embedded/bin/buildkitd") || !strings.Contains(byPath["/etc/systemd/system/acornfox-caddy.service"], "/embedded/bin/caddy") {
		t.Fatal("independent dependency worker does not consume embedded release bytes")
	}
	if !strings.Contains(byPath["/etc/acornfox/native-caddy.json"], "/run/acornfox/edge-admin/admin.sock") || !strings.Contains(byPath["/etc/acornfox/native-caddy.json"], "/var/lib/acornfox/edge/data") || !strings.Contains(byPath["/etc/acornfox/rootlesskit.apparmor"], "/embedded/bin/rootlesskit") {
		t.Fatal("fixed Caddy Admin or Native rootless profile differs")
	}
}
