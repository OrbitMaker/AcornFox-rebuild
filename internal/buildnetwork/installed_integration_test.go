//go:build integration && linux

package buildnetwork

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This is a test-process entry point for exercising the actual production
// manager before a release candidate exists. It is never shipped as a daemon.
func TestInstalledManagerFixtureProcess(t *testing.T) {
	mode := os.Getenv("ACORNFOX_R1_MANAGER_FIXTURE")
	if mode == "" {
		t.Skip("explicit disposable integration fixture required")
	}
	if mode != "serve" && mode != "cleanup" {
		t.Fatal("invalid fixture mode")
	}
	host, _ := os.Hostname()
	uuid, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err != nil || (host != "acornfox-r1-activate-20260905" && host != "acornfox-beta-test-20260905") || strings.TrimSpace(string(uuid)) != os.Getenv("ACORNFOX_R1_VM_UUID") || os.Geteuid() != 0 {
		t.Fatal("wrong integration host")
	}
	manager, err := NewProductionManager()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if mode == "cleanup" {
		err = manager.Cleanup(ctx)
	} else {
		err = manager.Serve(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestInstalledWorkerAttestation(t *testing.T) {
	if os.Getenv("ACORNFOX_R1_LIVE_TEST") != "enabled" {
		t.Skip("explicit installed worker fixture required")
	}
	host, _ := os.Hostname()
	if (host != "acornfox-r1-activate-20260905" && host != "acornfox-beta-test-20260905") || os.Geteuid() != 0 {
		t.Fatal("wrong fixture")
	}
	_, digest, err := ReadInstalledPolicy()
	if err != nil {
		t.Fatal(err)
	}
	request := AttestationRequest{SchemaVersion: 1, PolicyDigest: digest, RequestFingerprint: strings.Repeat("a", 64)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := (Client{}).AttestWorkerPolicy(ctx, request); err != nil {
		manager := &Manager{digest: digest}
		if stateErr := manager.loadState(); stateErr != nil {
			t.Logf("state check: %v", stateErr)
		} else {
			dev, ino, e := namespaceIdentity()
			t.Logf("namespace got=%d:%d want=%d:%d error=%v", dev, ino, manager.state.NamespaceDevice, manager.state.NamespaceInode, e)
			link, e := hostLink(ctx)
			t.Logf("link got=%+v expectedIndex=%d aliasEqual=%v error=%v", link, manager.state.HostLinkIndex, link.Alias == manager.state.Token, e)
			for _, item := range []struct {
				ns                 bool
				family, name, want string
			}{{true, "inet", "acornfox_build", manager.state.WorkerRules}, {false, "inet", "acornfox_build_guard", manager.state.HostRules}, {false, "ip", "acornfox_build_nat", manager.state.NATRules}} {
				got, e := tableHash(ctx, item.ns, item.family, item.name)
				t.Logf("%s fingerprint equal=%v error=%v", item.name, got == item.want, e)
			}
			got, e := topologyHash(ctx)
			t.Logf("topology equal=%v error=%v", got == manager.state.Topology, e)
			t.Logf("kernel check: %v", manager.verifyKernel(ctx))
		}
		t.Fatalf("real installed attestation: %v", err)
	}
	policy, err := os.ReadFile(PolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.WriteFile(PolicyPath, policy, 0644)
	if err := os.WriteFile(PolicyPath, []byte("{}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := (Client{}).AttestWorkerPolicy(ctx, request); err == nil {
		t.Fatal("changed installed policy was accepted")
	}
	if err := os.WriteFile(PolicyPath, policy, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := (Client{}).AttestWorkerPolicy(ctx, request); err != nil {
		t.Fatalf("restored policy did not recover: %v", err)
	}
	code := `import socket,sys
s=socket.socket(socket.AF_UNIX)
try:s.connect("/run/acornfox-build-policy/attest.sock")
except PermissionError:sys.exit(0)
sys.exit(1)`
	if out, err := exec.Command("/usr/sbin/runuser", "-u", "acornfox-buildkit", "--", "/usr/bin/python3", "-c", code).CombinedOutput(); err != nil {
		t.Fatalf("untrusted build UID reached policy socket: %s %v", out, err)
	}
}
