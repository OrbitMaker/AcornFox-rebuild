package install

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type acornFoxUnitSections map[string]map[string][]string

var acornFoxSystemdFiles = []string{
	"acornfox-server.service",
	"acornfox-agent.service",
	"acornfox-buildkit.service",
	"acornfox-caddy.service",
	"acornfox-edge.service",
	"acornfox-healthcheck.service",
	"acornfox-healthcheck.timer",
	"acornfox-upgrade-recover.service",
	"acornfox-upgrade-safe.target",
	"acornfox-upgrade-finalize.service",
	"acornfox-edge.service.d/10-upgrade-marker.conf",
}

func acornFoxDeployRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "deploy")
}

func readAcornFoxUnit(t *testing.T, name string) (string, acornFoxUnitSections) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(acornFoxDeployRoot(t), "systemd", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw), parseAcornFoxUnit(t, string(raw))
}

func parseAcornFoxUnit(t *testing.T, raw string) acornFoxUnitSections {
	t.Helper()
	sections := acornFoxUnitSections{}
	section := ""
	for lineNumber, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			if sections[section] == nil {
				sections[section] = map[string][]string{}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if section == "" || !ok || key == "" {
			t.Fatalf("invalid unit line %d: %q", lineNumber+1, line)
		}
		sections[section][key] = append(sections[section][key], value)
	}
	return sections
}

func requireAcornFoxDirective(t *testing.T, sections acornFoxUnitSections, section, key, want string) {
	t.Helper()
	for _, value := range sections[section][key] {
		if value == want {
			return
		}
	}
	t.Fatalf("%s.%s=%q not found in %#v", section, key, want, sections[section][key])
}

func requireAcornFoxDirectiveContains(t *testing.T, sections acornFoxUnitSections, section, key, want string) {
	t.Helper()
	for _, value := range sections[section][key] {
		if strings.Contains(value, want) {
			return
		}
	}
	t.Fatalf("%s.%s containing %q not found in %#v", section, key, want, sections[section][key])
}

func TestAcornFoxSystemdInventoryMatchesPackageContract(t *testing.T) {
	want := append([]string(nil), acornFoxSystemdFiles...)
	sort.Strings(want)
	got := make([]string, 0, len(want))
	for _, file := range AcornFoxV1RequiredFiles() {
		if name, ok := strings.CutPrefix(file.Path, "systemd/"); ok {
			if file.Mode != 0o644 {
				t.Fatalf("%s mode = %o, want 0644", file.Path, file.Mode)
			}
			got = append(got, name)
		}
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("systemd package files = %#v, want %#v", got, want)
	}
	for _, name := range want {
		if _, err := os.Stat(filepath.Join(acornFoxDeployRoot(t), "systemd", name)); err != nil {
			t.Fatalf("package unit %s: %v", name, err)
		}
	}
}

func TestAcornFoxSystemdNamesPathsAndEnvironmentContract(t *testing.T) {
	for _, name := range acornFoxSystemdFiles {
		raw, sections := readAcornFoxUnit(t, name)
		for _, forbidden := range []string{"Open Card", "open-card", "open_card", "opencard", "OPEN_CARD_"} {
			if strings.Contains(raw, forbidden) {
				t.Fatalf("%s contains forbidden legacy name %q", name, forbidden)
			}
		}
		for _, value := range sections["Service"]["Environment"] {
			if !strings.HasPrefix(value, "ACORNFOX_") {
				t.Fatalf("%s has non-AcornFox Environment=%q", name, value)
			}
		}
		for _, value := range sections["Service"]["EnvironmentFile"] {
			if !strings.HasPrefix(strings.TrimPrefix(value, "-"), "/etc/acornfox/") && !strings.HasPrefix(strings.TrimPrefix(value, "-"), "/opt/acornfox/") {
				t.Fatalf("%s has non-AcornFox EnvironmentFile=%q", name, value)
			}
		}
		for key, values := range sections["Service"] {
			if !strings.HasPrefix(key, "Exec") {
				continue
			}
			for _, value := range values {
				command := strings.Fields(value)
				if len(command) == 0 {
					t.Fatalf("%s has empty %s", name, key)
				}
				if strings.HasPrefix(command[0], "/opt/acornfox/current/bin/") || strings.HasPrefix(command[0], "/opt/acornfox/upgrade-tools/") || command[0] == "/usr/bin/test" || command[0] == "/usr/bin/grep" || command[0] == "/bin/sh" {
					continue
				}
				t.Fatalf("%s has unauthorized %s command %q", name, key, command[0])
			}
		}
	}

	_, server := readAcornFoxUnit(t, "acornfox-server.service")
	requireAcornFoxDirective(t, server, "Service", "User", "acornfox")
	requireAcornFoxDirective(t, server, "Service", "Group", "acornfox")
	requireAcornFoxDirective(t, server, "Service", "WorkingDirectory", "/opt/acornfox/current")
	requireAcornFoxDirective(t, server, "Service", "Environment", "ACORNFOX_RUNTIME_MODE=clean")
	requireAcornFoxDirective(t, server, "Service", "EnvironmentFile", "-/etc/acornfox/server.env")
	requireAcornFoxDirective(t, server, "Service", "EnvironmentFile", "/opt/acornfox/active/database.env")
	requireAcornFoxDirective(t, server, "Service", "ExecStart", "/opt/acornfox/current/bin/acornfox-server")
	// The database environment stays outside the unit; this is the fixed key it
	// must provide when the immutable active file is selected above.
	if key := "ACORNFOX_DATABASE_URL"; !strings.HasPrefix(key, "ACORNFOX_") {
		t.Fatal("database environment contract lost its AcornFox namespace")
	}

	for _, check := range []struct {
		unit, user, execStart string
	}{
		{"acornfox-agent.service", "acornfox-agent", "/opt/acornfox/current/bin/acornfox-agent"},
		{"acornfox-caddy.service", "acornfox-caddy", "/opt/acornfox/current/bin/caddy run --environ --config /etc/acornfox/Caddyfile --adapter caddyfile"},
		{"acornfox-edge.service", "acornfox-edge", "/opt/acornfox/current/bin/caddy run --environ --config /etc/acornfox/acornfox-edge.Caddyfile --adapter caddyfile"},
	} {
		_, sections := readAcornFoxUnit(t, check.unit)
		requireAcornFoxDirective(t, sections, "Service", "User", check.user)
		requireAcornFoxDirective(t, sections, "Service", "Group", check.user)
		requireAcornFoxDirective(t, sections, "Service", "ExecStart", check.execStart)
	}
	_, buildkit := readAcornFoxUnit(t, "acornfox-buildkit.service")
	requireAcornFoxDirectiveContains(t, buildkit, "Service", "ExecStart", "/opt/acornfox/current/bin/rootlesskit")
	requireAcornFoxDirectiveContains(t, buildkit, "Service", "ExecStart", "/opt/acornfox/current/bin/buildkitd")
	requireAcornFoxDirectiveContains(t, buildkit, "Service", "ExecStart", "--addr unix:///run/acornfox-buildkit/buildkitd.sock")

	_, edge := readAcornFoxUnit(t, "acornfox-edge.service")
	requireAcornFoxDirective(t, edge, "Service", "EnvironmentFile", "/etc/acornfox/acornfox-edge.env")
	for key, values := range edge["Service"] {
		if strings.HasPrefix(key, "Exec") {
			for _, value := range values {
				if !strings.Contains(value, "/etc/acornfox/acornfox-edge.Caddyfile") {
					t.Fatalf("edge %s uses a config outside its fixed path: %q", key, value)
				}
			}
		}
	}
}

func TestAcornFoxSystemdBootDagAndHardening(t *testing.T) {
	_, recoverUnit := readAcornFoxUnit(t, "acornfox-upgrade-recover.service")
	_, safeTarget := readAcornFoxUnit(t, "acornfox-upgrade-safe.target")
	_, finalizeUnit := readAcornFoxUnit(t, "acornfox-upgrade-finalize.service")
	_, edgeMarker := readAcornFoxUnit(t, "acornfox-edge.service.d/10-upgrade-marker.conf")
	requireAcornFoxDirectiveContains(t, recoverUnit, "Unit", "Before", "acornfox-upgrade-safe.target")
	requireAcornFoxDirective(t, safeTarget, "Unit", "Requires", "acornfox-upgrade-recover.service")
	requireAcornFoxDirectiveContains(t, safeTarget, "Unit", "After", "acornfox-upgrade-recover.service")
	for _, unit := range []string{"acornfox-buildkit.service", "acornfox-caddy.service", "acornfox-server.service", "acornfox-agent.service", "acornfox-edge.service"} {
		requireAcornFoxDirectiveContains(t, safeTarget, "Unit", "Before", unit)
		_, sections := readAcornFoxUnit(t, unit)
		requireAcornFoxDirectiveContains(t, sections, "Unit", "Requires", "acornfox-upgrade-safe.target")
		requireAcornFoxDirectiveContains(t, sections, "Unit", "After", "acornfox-upgrade-safe.target")
	}
	requireAcornFoxDirectiveContains(t, finalizeUnit, "Unit", "After", "acornfox-upgrade-safe.target")
	requireAcornFoxDirective(t, finalizeUnit, "Unit", "ConditionPathExists", "/var/lib/acornfox/upgrade-in-progress")
	requireAcornFoxDirective(t, edgeMarker, "Unit", "ConditionPathExists", "!/var/lib/acornfox/upgrade-in-progress")

	for _, unit := range []string{"acornfox-server.service", "acornfox-agent.service", "acornfox-caddy.service", "acornfox-edge.service"} {
		_, sections := readAcornFoxUnit(t, unit)
		for key, want := range map[string]string{
			"NoNewPrivileges":         "yes",
			"PrivateTmp":              "yes",
			"PrivateDevices":          "yes",
			"ProtectSystem":           "strict",
			"ProtectHome":             "yes",
			"CapabilityBoundingSet":   "",
			"AmbientCapabilities":     "",
			"RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
			"SystemCallArchitectures": "native",
			"SystemCallFilter":        "@system-service",
		} {
			requireAcornFoxDirective(t, sections, "Service", key, want)
		}
	}
	_, buildkit := readAcornFoxUnit(t, "acornfox-buildkit.service")
	requireAcornFoxDirective(t, buildkit, "Service", "NoNewPrivileges", "no")
	requireAcornFoxDirective(t, buildkit, "Service", "Delegate", "yes")
	requireAcornFoxDirective(t, buildkit, "Service", "RestrictAddressFamilies", "AF_UNIX AF_NETLINK")
	requireAcornFoxDirective(t, buildkit, "Service", "SystemCallFilter", "@system-service @mount")
	requireAcornFoxDirective(t, buildkit, "Service", "ReadWritePaths", "/var/lib/acornfox /run/acornfox-buildkit")
}

func TestAcornFoxInitialEdgeIsLoopbackOnly(t *testing.T) {
	caddyRoot := filepath.Join(acornFoxDeployRoot(t), "caddy")
	config, err := os.ReadFile(filepath.Join(caddyRoot, "acornfox-edge.Caddyfile.example"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := os.ReadFile(filepath.Join(caddyRoot, "acornfox-edge.env.example"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(config)
	for _, forbidden := range []string{"Open Card", "open-card", "open_card", "opencard", "OPEN_CARD_", ":80", ":443"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("edge Caddy example contains forbidden value %q", forbidden)
		}
	}
	if !strings.Contains(text, "admin 127.0.0.1:2019") || !strings.Contains(text, "{$ACORNFOX_EDGE_BIND:127.0.0.1:18482}") || !strings.Contains(text, "auto_https off") {
		t.Fatalf("edge Caddy example is not a fixed loopback-only bootstrap: %s", text)
	}
	if strings.TrimSpace(string(env)) != "# This local-only listener is required until a separately approved edge route exists.\nACORNFOX_EDGE_BIND=127.0.0.1:18482" {
		t.Fatalf("edge environment example = %q", env)
	}
}
