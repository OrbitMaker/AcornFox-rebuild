//go:build integration && linux

package buildkit_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/application"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/foundation"
	"github.com/acornfox/acornfox/internal/importers/dockerfile"
	buildkit "github.com/acornfox/acornfox/internal/providers/buildkit"
	imageprovider "github.com/acornfox/acornfox/internal/providers/image"
)

// This task-only attestor observes the live kernel table, rather than echoing
// a configured digest. Its snapshot is made by the independent guest harness
// after checking the policy and before starting BuildKit. It grants no server
// privilege and is not a substitute for an installed worker's attestation API.
type liveTaskPolicyAttestor struct {
	policyDigest  string
	snapshot      []byte
	calls         int
	driftRefusals int
}

func normalizedTaskFirewall(ctx context.Context) ([]byte, error) {
	raw, err := exec.CommandContext(ctx, "/usr/sbin/nft", "-s", "-j", "list", "table", "inet", "acornfox_p0").Output()
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	var strip func(any)
	strip = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			delete(x, "handle")
			for _, child := range x {
				strip(child)
			}
		case []any:
			for _, child := range x {
				strip(child)
			}
		}
	}
	strip(value)
	return json.Marshal(value)
}

func (a *liveTaskPolicyAttestor) AttestWorkerPolicy(ctx context.Context, request buildkit.WorkerPolicyAttestationRequest) (buildkit.WorkerPolicyAttestationReceipt, error) {
	a.calls++
	observed, err := normalizedTaskFirewall(ctx)
	if err != nil {
		return buildkit.WorkerPolicyAttestationReceipt{}, err
	}
	if !bytes.Equal(observed, a.snapshot) {
		a.driftRefusals++
		return buildkit.WorkerPolicyAttestationReceipt{}, errors.New("task worker kernel policy differs")
	}
	if request.PolicyDigest != a.policyDigest {
		return buildkit.WorkerPolicyAttestationReceipt{}, errors.New("task worker kernel policy differs")
	}
	return buildkit.WorkerPolicyAttestationReceipt{SchemaVersion: 1, PolicyDigest: a.policyDigest, RequestFingerprint: request.RequestFingerprint}, nil
}

func TestAcornFoxRealControlledEgressBuildWorker(t *testing.T) {
	if os.Getenv("OPEN_CARD_AFB_CONTROLLED_WORKER_TEST") != "enabled" {
		t.Skip("explicit disposable controlled worker gate required")
	}
	host, err := os.Hostname()
	if err != nil || host != "acornfox-afb-build-03b-product-p2-20260905" || os.Geteuid() != 0 {
		t.Fatal("wrong disposable task worker identity")
	}
	inputs, err := os.ReadFile("/tmp/acornfox-product-build-inputs-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := os.ReadFile("/etc/acornfox/acornfox-controlled-egress-policy-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	policySum := sha256.Sum256(policy)
	policyDigest := "sha256:" + hex.EncodeToString(policySum[:])
	snapshot, err := normalizedTaskFirewall(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	attestor := &liveTaskPolicyAttestor{policyDigest: policyDigest, snapshot: snapshot}
	root := t.TempDir()
	store, err := imageprovider.New(imageprovider.Config{Root: filepath.Join(root, "oci")})
	if err != nil {
		t.Fatal(err)
	}
	workspaces := filepath.Join(root, "sources")
	if err := os.MkdirAll(workspaces, 0o700); err != nil {
		t.Fatal(err)
	}
	provider, err := buildkit.New(buildkit.Config{
		Command: "/opt/acornfox-build-proof/bin/buildctl", Builder: "acornfox-controlled-proof",
		Address: "unix:///run/open-card-buildkit/buildkitd.sock", WorkspaceRoot: workspaces,
		WorkRoot: filepath.Join(root, "work"), ImageStore: store, Capacity: acornFoxBuildCapacity{},
		LogSink: &acornFoxFileLogSink{root: filepath.Join(root, "logs")}, RequireLogSink: true,
		ControlledEgressInputsRaw: inputs, ControlledEgressPolicyRaw: policy, WorkerPolicyAttestor: attestor,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func(name, url string) contracts.BuildRequest {
		t.Helper()
		workspace := filepath.Join(workspaces, name)
		if err := os.Mkdir(workspace, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\nADD "+url+" /dependency.tgz\n"), 0o400); err != nil {
			t.Fatal(err)
		}
		digest, err := foundation.HashDirectory(workspace)
		if err != nil {
			t.Fatal(err)
		}
		source := domain.SourceRevision{ID: domain.ID("src_" + name), ApplicationID: "app_controlled_proof", Kind: domain.SourceUpload, Locator: "upload://controlled-proof", ContentDigest: "sha256:" + digest, WorkspaceRef: workspace, CreatedAt: time.Now().UTC(), Immutable: true}
		definition, err := dockerfile.Import(source)
		if err != nil || definition.Status != contracts.AcornFoxDockerfileReady {
			t.Fatalf("definition not ready: %v %v", definition.Status, err)
		}
		r, err := (application.AcornFoxBuildBinder{}).BindControlledEgress(definition, source, name, "acornfox.local/controlled-proof", name, policyDigest, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		r.Capacity = &contracts.CapacityLease{ID: "lease-controlled-proof", Scope: contracts.CapacityBuild, Resources: r.Resources, ExpiresAt: time.Now().Add(5 * time.Minute)}
		return r
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	positive := request("allowed", "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz")
	result, err := provider.Build(ctx, positive)
	if err != nil || result.Artifact == nil || result.LogRef == "" {
		t.Fatalf("real controlled build: result=%+v error=%v", result, err)
	}
	archive, _, err := store.OpenOCI(ctx, result.Artifact.Image, contracts.OperationContext{IdempotencyKey: "controlled-read-archive"})
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	assertDownloadedDependency(t, archive)
	if _, err := os.ReadFile(result.LogRef); err != nil {
		t.Fatal(err)
	}
	t.Logf("real OCI digest=%s; stored dependency bytes verified; live attestation calls=%d", result.Artifact.Image.Digest, attestor.calls)

	negative := request("metadata", "http://169.254.169.254/latest/meta-data/")
	short, stop := context.WithTimeout(ctx, 8*time.Second)
	blocked, err := provider.Build(short, negative)
	stop()
	if err == nil || blocked.Artifact != nil {
		t.Fatal("metadata ADD was not rejected")
	}

	// Introduce a real policy change, verify it is rejected before a build, then
	// remove exactly this test's rule. No unrelated rules or host resources move.
	if out, err := exec.Command("/usr/sbin/nft", "add", "rule", "inet", "acornfox_p0", "output", "counter", "drop", "comment", "attestation-drift-probe").CombinedOutput(); err != nil {
		t.Fatalf("drift fixture: %s %v", out, err)
	}
	drifted := request("drift", "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz")
	driftCtx, driftCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer driftCancel()
	beforeCalls, beforeRefusals := attestor.calls, attestor.driftRefusals
	blocked, err = provider.Build(driftCtx, drifted)
	if err == nil || blocked.Artifact != nil || attestor.calls != beforeCalls+1 || attestor.driftRefusals != beforeRefusals+1 {
		t.Fatal("changed live firewall accepted")
	}
	// The independent harness removes the task-only table after the test; its
	// final snapshot preserves the deliberate deny-only drift as negative proof.
	entries, err := os.ReadDir(filepath.Join(root, "work"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("transient provider work remains: %v %v", entries, err)
	}
}

func assertDownloadedDependency(t *testing.T, input io.Reader) {
	t.Helper()
	outer := tar.NewReader(input)
	for {
		header, err := outer.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(header.Name, "blobs/sha256/") || header.Size > 8<<20 {
			continue
		}
		raw, err := io.ReadAll(outer)
		if err != nil {
			t.Fatal(err)
		}
		gz, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			continue
		}
		layer := tar.NewReader(gz)
		for {
			entry, err := layer.Next()
			if err != nil {
				break
			}
			if strings.TrimPrefix(entry.Name, "./") == "dependency.tgz" {
				data, err := io.ReadAll(layer)
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(data)
				if hex.EncodeToString(sum[:]) != "7b75c1057198cf97696909a9bee176c9c5e9bcb5b03bf3ecef2f484defadd51e" {
					t.Fatal("downloaded public dependency differs from frozen bytes")
				}
				gz.Close()
				return
			}
		}
		gz.Close()
	}
	t.Fatal("downloaded dependency absent from OCI layers")
}
