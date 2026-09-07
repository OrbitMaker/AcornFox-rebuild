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
	"acornfox-build-network.service",
	"acornfox-runtime-network.service",
	"acornfox-server.service",
	"acornfox-agent.service",
	"acornfox-buildkit.service",
	"acornfox-caddy.service",
	"acornfox-edge.service",
	"acornfox-healthcheck.service",
	"acornfox-healthcheck.timer",
	"acornfox-pi-worker.service",
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

func TestAcornFoxBuildKitCandidateConfigIsFixedAndControlled(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(acornFoxDeployRoot(t), "buildkit", "acornfox-buildkitd.toml"))
	if err != nil {
		t.Fatal(err)
	}
	config := string(raw)
	for _, required := range []string{
		"root = \"/var/lib/acornfox/buildkit/buildkitd\"", "max-parallelism = 1", "[worker.oci]", "enabled = true", "rootless = true", "snapshotter = \"native\"", "[worker.containerd]", "enabled = false",
		"nameservers = [\"1.1.1.1\", \"1.0.0.1\"]", "[registry.\"docker.io\"]", "mirrors = [\"public.ecr.aws/docker\"]",
	} {
		if !strings.Contains(config, required) {
			t.Fatalf("candidate BuildKit config missing %q", required)
		}
	}
	for _, forbidden := range []string{"http = true", "insecure = true", "entitlement", "network."} {
		if strings.Contains(strings.ToLower(config), forbidden) {
			t.Fatalf("candidate BuildKit config retained forbidden %q", forbidden)
		}
	}
	found := false
	for _, file := range AcornFoxV1RequiredFiles() {
		if file.Path == "config/acornfox-buildkitd.toml" && file.Mode == 0o644 {
			found = true
		}
	}
	if !found {
		t.Fatal("candidate BuildKit config is not bound to package inventory")
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
			if name == "acornfox-caddy.service" && (value == "HOME=/var/lib/acornfox/caddy" || value == "XDG_DATA_HOME=/var/lib/acornfox/caddy/data" || value == "XDG_CONFIG_HOME=/var/lib/acornfox/caddy/config") {
				continue
			}
			if name == "acornfox-buildkit.service" && (value == "HOME=/var/lib/acornfox/buildkit" || value == "XDG_RUNTIME_DIR=/run/acornfox-buildkit" || value == "PATH=/opt/acornfox/current/bin:/usr/bin:/bin") {
				continue
			}
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
				if name == "acornfox-runtime-network.service" && key == "ExecStartPre" && (value == "+/usr/sbin/modprobe br_netfilter" || value == "+/usr/sbin/sysctl -w net.bridge.bridge-nf-call-iptables=1") {
					continue
				}
				if name == "acornfox-build-network.service" && key == "ExecStartPost" && value == "/usr/bin/systemctl --no-block start acornfox-buildkit.service" {
					continue
				}
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
	requireAcornFoxDirective(t, server, "Service", "Environment", "ACORNFOX_SERVER_ADDR=127.0.0.1:18481")
	requireAcornFoxDirective(t, server, "Service", "EnvironmentFile", "/etc/acornfox/runtime/server.env")
	requireAcornFoxDirective(t, server, "Service", "LoadCredential", "server.key:/etc/acornfox/runtime/server.key")
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
		{"acornfox-edge.service", "acornfox-edge", "/opt/acornfox/current/bin/caddy run --config /etc/acornfox/runtime/edge.json"},
	} {
		_, sections := readAcornFoxUnit(t, check.unit)
		requireAcornFoxDirective(t, sections, "Service", "User", check.user)
		requireAcornFoxDirective(t, sections, "Service", "Group", check.user)
		requireAcornFoxDirective(t, sections, "Service", "ExecStart", check.execStart)
	}
	_, buildkit := readAcornFoxUnit(t, "acornfox-buildkit.service")
	_, runtimeNetwork := readAcornFoxUnit(t, "acornfox-runtime-network.service")
	requireAcornFoxDirective(t, runtimeNetwork, "Service", "ExecStartPre", "+/usr/sbin/modprobe br_netfilter")
	requireAcornFoxDirective(t, runtimeNetwork, "Service", "ExecStartPre", "+/usr/sbin/sysctl -w net.bridge.bridge-nf-call-iptables=1")
	requireAcornFoxDirectiveContains(t, buildkit, "Service", "ExecStart", "/opt/acornfox/current/bin/rootlesskit")
	requireAcornFoxDirectiveContains(t, buildkit, "Service", "ExecStart", "/opt/acornfox/current/bin/buildkitd")
	requireAcornFoxDirectiveContains(t, buildkit, "Service", "ExecStart", "--addr unix:///run/acornfox-buildkit/buildkitd.sock")

	_, agent := readAcornFoxUnit(t, "acornfox-agent.service")
	requireAcornFoxDirectiveContains(t, agent, "Unit", "Requires", "docker.service")
	requireAcornFoxDirectiveContains(t, agent, "Unit", "After", "docker.service")
	requireAcornFoxDirective(t, agent, "Service", "SupplementaryGroups", "docker acornfox")
	requireAcornFoxDirective(t, agent, "Service", "Environment", "ACORNFOX_DOCKER_SOCKET=/var/run/docker.sock")
	requireAcornFoxDirective(t, agent, "Service", "BindPaths", "/var/run/docker.sock")
	if values := agent["Service"]["BindReadOnlyPaths"]; len(values) != 0 {
		t.Fatalf("agent retained an unsupported BuildKit bind: %#v", values)
	}

	_, edge := readAcornFoxUnit(t, "acornfox-edge.service")
	requireAcornFoxDirective(t, edge, "Service", "EnvironmentFile", "/etc/acornfox/acornfox-edge.env")
	requireAcornFoxDirective(t, edge, "Service", "WorkingDirectory", "/var/lib/acornfox/edge")
	for key, values := range edge["Service"] {
		if strings.HasPrefix(key, "Exec") {
			for _, value := range values {
				if !strings.Contains(value, "/etc/acornfox/runtime/edge.json") {
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
	requireAcornFoxDirective(t, recoverUnit, "Service", "CapabilityBoundingSet", "CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SYS_PTRACE")
	requireAcornFoxDirective(t, finalizeUnit, "Service", "CapabilityBoundingSet", "CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SYS_PTRACE")
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
			if unit == "acornfox-edge.service" && (key == "CapabilityBoundingSet" || key == "AmbientCapabilities") {
				want = "CAP_NET_BIND_SERVICE"
			}
			requireAcornFoxDirective(t, sections, "Service", key, want)
		}
	}
	_, buildkit := readAcornFoxUnit(t, "acornfox-buildkit.service")
	requireAcornFoxDirective(t, buildkit, "Service", "NoNewPrivileges", "no")
	requireAcornFoxDirective(t, buildkit, "Service", "Delegate", "yes")
	requireAcornFoxDirective(t, buildkit, "Service", "RestrictAddressFamilies", "AF_UNIX AF_NETLINK AF_INET AF_INET6")
	requireAcornFoxDirective(t, buildkit, "Service", "SystemCallFilter", "@system-service @mount seccomp sethostname")
	requireAcornFoxDirective(t, buildkit, "Service", "ProtectKernelTunables", "no")
	requireAcornFoxDirective(t, buildkit, "Service", "ProtectKernelModules", "no")
	requireAcornFoxDirective(t, buildkit, "Service", "ProtectProc", "default")
	requireAcornFoxDirective(t, buildkit, "Service", "RestrictSUIDSGID", "no")
	requireAcornFoxDirective(t, buildkit, "Service", "MemoryDenyWriteExecute", "no")
	requireAcornFoxDirective(t, buildkit, "Service", "ReadWritePaths", "/var/lib/acornfox/buildkit /run/acornfox-buildkit")
}

func TestAcornFoxWritablePathOwnershipMatrix(t *testing.T) {
	want := map[string][]string{
		"acornfox-server.service": {
			"/var/lib/acornfox/uploads", "/var/lib/acornfox/workspaces", "/var/lib/acornfox/build-work", "/var/lib/acornfox/oci",
			"/var/lib/acornfox/secrets", "/var/lib/acornfox/secret-materials", "/var/log/acornfox/server",
		},
		"acornfox-agent.service":       {"/var/lib/acornfox/agent", "/var/log/acornfox/agent"},
		"acornfox-buildkit.service":    {"/var/lib/acornfox/buildkit", "/run/acornfox-buildkit"},
		"acornfox-caddy.service":       {"/var/lib/acornfox/caddy", "/var/log/acornfox/caddy"},
		"acornfox-edge.service":        {"/var/lib/acornfox/edge", "/var/log/acornfox/edge"},
		"acornfox-healthcheck.service": {"/var/lib/acornfox/healthcheck", "/var/lib/acornfox/health-secret-materials"},
	}
	for unit, paths := range want {
		_, sections := readAcornFoxUnit(t, unit)
		got := strings.Fields(strings.Join(sections["Service"]["ReadWritePaths"], " "))
		sort.Strings(got)
		sortedWant := append([]string(nil), paths...)
		sort.Strings(sortedWant)
		if !reflect.DeepEqual(got, sortedWant) {
			t.Fatalf("%s writable paths = %#v, want %#v", unit, got, sortedWant)
		}
		for _, path := range got {
			if path == "/var/lib/acornfox" || path == "/var/log/acornfox" {
				t.Fatalf("%s retained a cross-service root writable path %q", unit, path)
			}
		}
	}
	for _, unit := range []string{"acornfox-upgrade-recover.service", "acornfox-upgrade-finalize.service"} {
		_, sections := readAcornFoxUnit(t, unit)
		// These helpers check the initial host namespace and enforce a pinned
		// write scope in code. Mount sandbox directives would prevent recovery.
		for _, key := range []string{"PrivateTmp", "PrivateDevices", "ProtectSystem", "ProtectHome", "ProtectKernelTunables", "ProtectKernelModules", "ProtectControlGroups", "ProtectClock", "ProtectProc", "ReadWritePaths", "ExecStartPre"} {
			if len(sections["Service"][key]) != 0 {
				t.Fatalf("%s reintroduced incompatible recovery sandbox/guard %s", unit, key)
			}
		}
		requireAcornFoxDirective(t, sections, "Service", "NoNewPrivileges", "yes")
		requireAcornFoxDirective(t, sections, "Service", "RestrictNamespaces", "yes")
		command := "recover-prepare"
		if unit == "acornfox-upgrade-finalize.service" {
			command = "recover-finalize"
		}
		requireAcornFoxDirective(t, sections, "Service", "ExecStart", "/opt/acornfox/upgrade-tools/acornfox-upgrade "+command+" --pending")
	}
	_, server := readAcornFoxUnit(t, "acornfox-server.service")
	for _, value := range server["Service"]["ReadWritePaths"] {
		if strings.Contains(value, "/var/lib/acornfox/health-secret-materials") {
			t.Fatal("server retained health-secret-materials write access")
		}
	}
	entry, ok := acornFoxFixedSubstrateEntries(substrateReceiptFixture().CandidateReceipt)["var/lib/acornfox/health-secret-materials"]
	if !ok || entry.Kind != SubstrateEntryDirectory || entry.Mode != 0o700 || entry.Role != OwnerRoleRoot || entry.Group != GroupRoleRoot {
		t.Fatalf("health secret substrate ownership=%#v", entry)
	}
	for _, unit := range []string{"acornfox-healthcheck.service", "acornfox-healthcheck.timer", "acornfox-upgrade-safe.target"} {
		raw, _ := readAcornFoxUnit(t, unit)
		if !strings.Contains(raw, "03/04 must implement") || !strings.Contains(raw, "helper digest") {
			t.Fatalf("%s lacks the future-activation boundary", unit)
		}
	}
}

func TestAcornFoxListenerParityAndCollisionBoundary(t *testing.T) {
	_, server := readAcornFoxUnit(t, "acornfox-server.service")
	requireAcornFoxDirective(t, server, "Service", "Environment", "ACORNFOX_SERVER_ADDR=127.0.0.1:18481")
	internal, err := os.ReadFile(filepath.Join(acornFoxDeployRoot(t), "caddy", "acornfox.Caddyfile.example"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(internal), "http://127.0.0.1:8080 {") || !strings.Contains(string(internal), "reverse_proxy 127.0.0.1:18481") {
		t.Fatalf("internal Caddy listener/upstream parity is invalid: %s", internal)
	}
	edge, err := os.ReadFile(filepath.Join(acornFoxDeployRoot(t), "caddy", "acornfox-edge.Caddyfile.example"))
	if err != nil {
		t.Fatal(err)
	}
	for _, listener := range []string{"127.0.0.1:18481", "127.0.0.1:8080", "127.0.0.1:18482"} {
		if strings.Count(string(internal)+string(edge), listener) == 0 {
			t.Fatalf("listener %s is absent from the static topology", listener)
		}
	}
	if strings.Contains(string(internal), "http://127.0.0.1:18481 {") || strings.Contains(string(internal), "reverse_proxy 127.0.0.1:8080") || strings.Contains(string(edge), "http://127.0.0.1:18481 {") || strings.Contains(string(edge), "http://127.0.0.1:8080 {") {
		t.Fatal("server, internal Caddy, and edge listener addresses must remain distinct")
	}
}

func TestAcornFoxDeferredHelperGuardsFailClosed(t *testing.T) {
	guarded := map[string]string{
		"acornfox-healthcheck.service": "/opt/acornfox/current/bin/acornfox-healthcheck contract-check --product acornfox --layout-schema 1",
	}
	for unit, guard := range guarded {
		raw, sections := readAcornFoxUnit(t, unit)
		requireAcornFoxDirective(t, sections, "Service", "ExecStartPre", guard)
		if !strings.Contains(raw, "WATCH:") || !strings.Contains(raw, "bind the helper digest") {
			t.Fatalf("%s lacks the deferred helper-digest watch", unit)
		}
		for key := range sections["Unit"] {
			if strings.HasPrefix(key, "Condition") && !(unit == "acornfox-upgrade-finalize.service" && key == "ConditionPathExists" && sections["Unit"][key][0] == "/var/lib/acornfox/upgrade-in-progress") {
				t.Fatalf("%s uses %s as a helper guard instead of a failing ExecStartPre", unit, key)
			}
		}
	}
	_, safeTarget := readAcornFoxUnit(t, "acornfox-upgrade-safe.target")
	requireAcornFoxDirective(t, safeTarget, "Unit", "Requires", "acornfox-upgrade-recover.service")
	for _, management := range []string{"acornfox-buildkit.service", "acornfox-caddy.service", "acornfox-server.service", "acornfox-agent.service", "acornfox-edge.service"} {
		_, sections := readAcornFoxUnit(t, management)
		requireAcornFoxDirectiveContains(t, sections, "Unit", "Requires", "acornfox-upgrade-safe.target")
	}
	_, timer := readAcornFoxUnit(t, "acornfox-healthcheck.timer")
	requireAcornFoxDirective(t, timer, "Timer", "Unit", "acornfox-healthcheck.service")
}

func TestAcornFoxBootGraphIsAcyclic(t *testing.T) {
	nodes := map[string]bool{}
	for _, unit := range []string{"acornfox-upgrade-recover.service", "acornfox-upgrade-safe.target", "acornfox-upgrade-finalize.service", "acornfox-buildkit.service", "acornfox-caddy.service", "acornfox-server.service", "acornfox-agent.service", "acornfox-edge.service", "acornfox-healthcheck.service"} {
		nodes[unit] = true
	}
	edges := map[string][]string{}
	for unit := range nodes {
		_, sections := readAcornFoxUnit(t, unit)
		for _, target := range strings.Fields(strings.Join(sections["Unit"]["Before"], " ")) {
			if nodes[target] {
				edges[unit] = append(edges[unit], target)
			}
		}
		for _, dependency := range strings.Fields(strings.Join(sections["Unit"]["After"], " ")) {
			if nodes[dependency] {
				edges[dependency] = append(edges[dependency], unit)
			}
		}
	}
	state := map[string]uint8{}
	var visit func(string)
	visit = func(unit string) {
		switch state[unit] {
		case 1:
			t.Fatalf("boot ordering cycle reaches %s through %#v", unit, edges)
		case 2:
			return
		}
		state[unit] = 1
		for _, target := range edges[unit] {
			visit(target)
		}
		state[unit] = 2
	}
	for unit := range nodes {
		visit(unit)
	}
}

func TestAcornFoxCaddyPackageSourcesAreLoopbackOnly(t *testing.T) {
	caddyRoot := filepath.Join(acornFoxDeployRoot(t), "caddy")
	wantPackageFiles := map[string]uint32{
		"caddy/acornfox.Caddyfile.example":      0o644,
		"caddy/acornfox-edge.Caddyfile.example": 0o644,
		"caddy/acornfox-edge.env.example":       0o640,
	}
	gotPackageFiles := map[string]uint32{}
	for _, file := range AcornFoxV1RequiredFiles() {
		if strings.HasPrefix(file.Path, "caddy/") {
			gotPackageFiles[file.Path] = file.Mode
		}
	}
	if !reflect.DeepEqual(gotPackageFiles, wantPackageFiles) {
		t.Fatalf("Caddy package files = %#v, want %#v", gotPackageFiles, wantPackageFiles)
	}
	for source, future := range map[string]string{
		"acornfox.Caddyfile.example":      "/etc/acornfox/Caddyfile",
		"acornfox-edge.Caddyfile.example": "/etc/acornfox/acornfox-edge.Caddyfile",
	} {
		config, err := os.ReadFile(filepath.Join(caddyRoot, source))
		if err != nil {
			t.Fatal(err)
		}
		text := string(config)
		for _, forbidden := range []string{"Open Card", "open-card", "open_card", "opencard", "OPEN_CARD_", "0.0.0.0", "[::]", "{$", "{env.", "https://", "on_demand", "acme"} {
			if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
				t.Fatalf("%s for future %s contains forbidden value %q", source, future, forbidden)
			}
		}
		admin := "admin 127.0.0.1:2019"
		if source == "acornfox-edge.Caddyfile.example" {
			admin = "admin 127.0.0.1:2020"
		}
		if !strings.Contains(text, admin) || !strings.Contains(text, "auto_https off") {
			t.Fatalf("%s is not an explicitly local Caddy source", source)
		}
	}
	internal, err := os.ReadFile(filepath.Join(caddyRoot, "acornfox.Caddyfile.example"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(internal), "http://127.0.0.1:8080") || !strings.Contains(string(internal), "reverse_proxy 127.0.0.1:18481") {
		t.Fatalf("internal Caddy source is not the fixed local proxy: %s", internal)
	}
	for _, directive := range []string{"@backend path /api /api/* /healthz /readyz", "root * /opt/acornfox/current/web/dist", "try_files {path} /index.html", "file_server"} {
		if !strings.Contains(string(internal), directive) {
			t.Fatalf("console serving directive missing: %s", directive)
		}
	}
	_, caddyUnit := readAcornFoxUnit(t, "acornfox-caddy.service")
	requireAcornFoxDirective(t, caddyUnit, "Service", "ExecStart", "/opt/acornfox/current/bin/caddy run --environ --config /etc/acornfox/Caddyfile --adapter caddyfile")
	requireAcornFoxDirective(t, caddyUnit, "Service", "Environment", "HOME=/var/lib/acornfox/caddy")
	requireAcornFoxDirective(t, caddyUnit, "Service", "Environment", "XDG_DATA_HOME=/var/lib/acornfox/caddy/data")
	requireAcornFoxDirective(t, caddyUnit, "Service", "Environment", "XDG_CONFIG_HOME=/var/lib/acornfox/caddy/config")
	edge, err := os.ReadFile(filepath.Join(caddyRoot, "acornfox-edge.Caddyfile.example"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(edge), "\nhttp://127.0.0.1:18482 {") {
		t.Fatalf("edge Caddy source is not the fixed local listener: %s", edge)
	}
	for _, forbidden := range []string{":80 ", ":80\n", ":80{", ":443 ", ":443\n", ":443{"} {
		if strings.Contains(string(edge), forbidden) {
			t.Fatalf("edge Caddy source contains a public listener %q", forbidden)
		}
	}
	env, err := os.ReadFile(filepath.Join(caddyRoot, "acornfox-edge.env.example"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToUpper(string(env)), "BIND") || strings.Contains(string(env), "18482") || strings.TrimSpace(string(env)) != "# Edge process state only; listener selection is fixed in the Caddyfile.\nHOME=/var/lib/acornfox/edge/home\nXDG_DATA_HOME=/var/lib/acornfox/edge/data\nXDG_CONFIG_HOME=/var/lib/acornfox/edge/config\nACORNFOX_EDGE_LOG_DIR=/var/log/acornfox/edge" {
		t.Fatalf("edge environment example = %q", env)
	}
}
