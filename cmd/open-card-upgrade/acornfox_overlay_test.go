package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/desktopupdate"
	"github.com/open-card/open-card/internal/hostconfig"
	"github.com/open-card/open-card/internal/hostoverlay"
	"github.com/open-card/open-card/internal/hostprovision"
)

type testOverlayFixture struct {
	dir             string
	bundlePath      string
	envelopePath    string
	pubKeyHex       string
	privKey         ed25519.PrivateKey
	channel         string
	allowedHosts    string
	bindingSHA256   string
	version         string
	c0SHA256        string
	bootstrapSHA256 string
	hostPolicySHA   string
	guestWorkerSHA  string
	guestPolicySHA  string
	unitSHA         string
}

type testOverlayFixtureOpts struct {
	hostIndexURL      string
	backendMode       string
	bindingSHA256     string
	corruptEnvelope   bool
	corruptSignature  bool
	corruptBundle     bool
	corruptMember     string
	omitMember        string
	unequalC0         bool
	corruptUnitBytes  bool
	corruptHostPolicy bool
	corruptGuestPol   bool
	channel           string
	targetOS          string
	targetArch        string
	wrongPublicKey    bool
	allowedHosts      []string
}

func buildTestOverlayFixture(t *testing.T, opts testOverlayFixtureOpts) testOverlayFixture {
	t.Helper()
	dir := t.TempDir()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyHex := hex.EncodeToString(pub)

	channel := opts.channel
	if channel == "" {
		channel = "stable"
	}
	allowedHosts := opts.allowedHosts
	if len(allowedHosts) == 0 {
		allowedHosts = []string{"updates.acornfox.test"}
	}
	allowedHostsStr := strings.Join(allowedHosts, ",")

	targetOS := opts.targetOS
	if targetOS == "" {
		targetOS = "linux"
	}
	targetArch := opts.targetArch
	if targetArch == "" {
		targetArch = runtime.GOARCH
	}

	bindingSHA256 := opts.bindingSHA256
	if bindingSHA256 == "" {
		bindingSHA256 = strings.Repeat("a", 64)
	}

	backendMode := opts.backendMode
	if backendMode == "" {
		backendMode = "unchanged"
	}

	version := "1.0.0"

	// 1. Prepare member files
	bootstrapBytes := []byte("#!/bin/sh\n# stable bootstrap\nexit 0\n")
	c0Bytes := []byte("#!/bin/sh\n# C0 launcher and controller\nexit 0\n")
	launcherBytes := c0Bytes
	if opts.unequalC0 {
		launcherBytes = []byte("#!/bin/sh\n# unequal launcher bytes\nexit 0\n")
	}

	unitBytes := hostoverlay.BootstrapUnitBytes()
	if opts.corruptUnitBytes {
		unitBytes = append([]byte(nil), unitBytes...)
		unitBytes[0] = 'Z'
	}

	hostPol := hostconfig.ConfigPolicyFile{
		PublicKeyHex:    pubKeyHex,
		IndexURL:        "https://" + allowedHosts[0] + "/index.json",
		OS:              targetOS,
		Arch:            targetArch,
		Channel:         channel,
		AllowedHosts:    allowedHosts,
		MaxArtifactSize: 100 << 20,
	}
	if opts.hostIndexURL != "" {
		hostPol.IndexURL = opts.hostIndexURL
	}
	if opts.corruptHostPolicy {
		hostPol.Channel = "wrong-channel"
	}
	hostPolBytes, err := json.Marshal(hostPol)
	if err != nil {
		t.Fatal(err)
	}

	guestWorkerBytes := []byte("#!/bin/sh\n# guest worker\nexit 0\n")

	guestPol := overlayGuestPolicy{
		Schema:          1,
		PublicKey:       pub,
		HostOS:          targetOS,
		HostArch:        targetArch,
		Channel:         channel,
		AllowedHosts:    allowedHosts,
		MaxArtifactSize: 100 << 20,
	}
	if opts.corruptGuestPol {
		guestPol.HostOS = "wrong-os"
	}
	guestPolBytes, err := json.Marshal(guestPol)
	if err != nil {
		t.Fatal(err)
	}

	members := map[string][]byte{
		overlayMemberBootstrap:     bootstrapBytes,
		overlayMemberLauncher:      launcherBytes,
		overlayMemberController:    c0Bytes,
		overlayMemberHostPolicy:    hostPolBytes,
		overlayMemberGuestWorker:   guestWorkerBytes,
		overlayMemberGuestPolicy:   guestPolBytes,
		overlayMemberCanonicalUnit: unitBytes,
	}

	if opts.omitMember != "" {
		delete(members, opts.omitMember)
	}
	if opts.corruptMember != "" {
		if b, ok := members[opts.corruptMember]; ok {
			b = append([]byte(nil), b...)
			b[0] ^= 0xff
			members[opts.corruptMember] = b
		}
	}

	// 2. Build tar.gz bundle
	var bundleBuf bytes.Buffer
	gw := gzip.NewWriter(&bundleBuf)
	tw := tar.NewWriter(gw)

	var files []desktopupdate.HostBundleFile
	// Sort member names for determinism and alphabetical order in manifest
	memberNames := []string{
		overlayMemberBootstrap,
		overlayMemberLauncher,
		overlayMemberController,
		overlayMemberHostPolicy,
		overlayMemberGuestWorker,
		overlayMemberGuestPolicy,
		overlayMemberCanonicalUnit,
	}
	slices.Sort(memberNames)

	for _, name := range memberNames {
		data, exists := members[name]
		if !exists {
			continue
		}
		mode := int64(0755)
		if strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".service") {
			mode = 0644
		}
		digest := sha256.Sum256(data)
		files = append(files, desktopupdate.HostBundleFile{
			Path:   name,
			SHA256: hex.EncodeToString(digest[:]),
			Size:   int64(len(data)),
			Mode:   mode,
		})
	}

	// Build manifest.json
	fromBinding := bindingSHA256
	toBinding := bindingSHA256
	if backendMode == "candidate" {
		fromBinding = strings.Repeat("e", 64)
	}
	manifest := desktopupdate.HostBundleManifest{
		SchemaVersion:      1,
		Product:            "acornfox",
		Kind:               "host-update-v1",
		OS:                 targetOS,
		Architecture:       targetArch,
		Version:            version,
		ControllerProtocol: 1,
		InstanceProtocol:   1,
		Launcher:           overlayMemberLauncher,
		Controller:         overlayMemberController,
		Backend: desktopupdate.HostBackendPlan{
			Mode:         backendMode,
			FromBinding:  fromBinding,
			ToBinding:    toBinding,
			Architecture: targetArch,
			APIProtocol:  1,
		},
		Files: files,
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	// First file in tar MUST be bundle.json
	bh := &tar.Header{
		Name: "bundle.json",
		Mode: 0644,
		Size: int64(len(manifestRaw)),
	}
	if err := tw.WriteHeader(bh); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(manifestRaw); err != nil {
		t.Fatal(err)
	}

	// Next files are the member files
	for _, name := range memberNames {
		data, exists := members[name]
		if !exists {
			continue
		}
		mode := int64(0755)
		if strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".service") {
			mode = 0644
		}
		h := &tar.Header{
			Name: name,
			Mode: mode,
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	bundleBytes := bundleBuf.Bytes()
	if opts.corruptBundle {
		bundleBytes[len(bundleBytes)-1] ^= 0xff
	}

	bundlePath := filepath.Join(dir, "host-bundle.tar.gz")
	if err := os.WriteFile(bundlePath, bundleBytes, 0600); err != nil {
		t.Fatal(err)
	}

	bundleSHA := sha256.Sum256(bundleBytes)
	bundleSHAHex := hex.EncodeToString(bundleSHA[:])

	// 3. Build index payload and envelope
	indexPayload := desktopupdate.IndexPayload{
		Channel:   channel,
		Sequence:  1,
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		Version:   version,
		Artifacts: []desktopupdate.Artifact{
			{
				OS:             targetOS,
				Arch:           targetArch,
				URL:            "https://" + allowedHosts[0] + "/host-bundle.tar.gz",
				SHA256:         bundleSHAHex,
				Size:           int64(len(bundleBytes)),
				BackendBinding: toBinding,
			},
		},
	}
	payloadRaw, err := json.Marshal(indexPayload)
	if err != nil {
		t.Fatal(err)
	}
	payloadB64 := base64.StdEncoding.EncodeToString(payloadRaw)

	signingKey := priv
	if opts.wrongPublicKey {
		_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
		signingKey = otherPriv
	}
	sig := ed25519.Sign(signingKey, payloadRaw)
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	if opts.corruptSignature {
		sigB64 = base64.StdEncoding.EncodeToString([]byte("corrupted-sig-bytes-that-fail-ed25519-check!"))
	}
	if opts.corruptEnvelope {
		payloadB64 = "corrupted-payload"
	}

	envelope := desktopupdate.IndexEnvelope{
		SchemaVersion: 1,
		Payload:       payloadB64,
		Signature:     sigB64,
	}
	envelopeRaw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelopePath := filepath.Join(dir, "envelope.json")
	if err := os.WriteFile(envelopePath, envelopeRaw, 0600); err != nil {
		t.Fatal(err)
	}

	bSHA := sha256.Sum256(bootstrapBytes)
	c0SHA := sha256.Sum256(c0Bytes)
	hpSHA := sha256.Sum256(hostPolBytes)
	gwSHA := sha256.Sum256(guestWorkerBytes)
	gpSHA := sha256.Sum256(guestPolBytes)
	uSHA := sha256.Sum256(unitBytes)

	return testOverlayFixture{
		dir:             dir,
		bundlePath:      bundlePath,
		envelopePath:    envelopePath,
		pubKeyHex:       pubKeyHex,
		privKey:         priv,
		channel:         channel,
		allowedHosts:    allowedHostsStr,
		bindingSHA256:   bindingSHA256,
		version:         version,
		c0SHA256:        hex.EncodeToString(c0SHA[:]),
		bootstrapSHA256: hex.EncodeToString(bSHA[:]),
		hostPolicySHA:   hex.EncodeToString(hpSHA[:]),
		guestWorkerSHA:  hex.EncodeToString(gwSHA[:]),
		guestPolicySHA:  hex.EncodeToString(gpSHA[:]),
		unitSHA:         hex.EncodeToString(uSHA[:]),
	}
}

func TestInitialHostOverlayArguments(t *testing.T) {
	withAcornFoxIdentity(t)
	sha := strings.Repeat("a", 64)

	for _, cmd := range []string{"initial-host-overlay-preflight", "initial-host-overlay-apply"} {
		t.Run(cmd+"/MissingFlags", func(t *testing.T) {
			for _, args := range [][]string{
				{cmd},
				{cmd, "--host-bundle", "/bundle.tar.gz"},
				{cmd, "--host-bundle", "/bundle.tar.gz", "--envelope", "/env.json"},
				{cmd, "--host-bundle", "/bundle.tar.gz", "--envelope", "/env.json", "--public-key", sha},
				{cmd, "--host-bundle", "/bundle.tar.gz", "--envelope", "/env.json", "--public-key", sha, "--channel", "stable"},
				{cmd, "--host-bundle", "/bundle.tar.gz", "--envelope", "/env.json", "--public-key", sha, "--channel", "stable", "--allowed-hosts", "example.test"},
				// Duplicate flag
				{cmd, "--host-bundle", "/bundle.tar.gz", "--envelope", "/env.json", "--public-key", sha, "--channel", "stable", "--allowed-hosts", "example.test", "--binding-sha256", sha, "--channel", "stable"},
				// Unknown flag
				{cmd, "--host-bundle", "/bundle.tar.gz", "--envelope", "/env.json", "--public-key", sha, "--channel", "stable", "--allowed-hosts", "example.test", "--binding-sha256", sha, "--extra", "bad"},
				// Relative paths
				{cmd, "--host-bundle", "bundle.tar.gz", "--envelope", "/env.json", "--public-key", sha, "--channel", "stable", "--allowed-hosts", "example.test", "--binding-sha256", sha},
				{cmd, "--host-bundle", "/bundle.tar.gz", "--envelope", "env.json", "--public-key", sha, "--channel", "stable", "--allowed-hosts", "example.test", "--binding-sha256", sha},
				// Root path
				{cmd, "--host-bundle", "/", "--envelope", "/env.json", "--public-key", sha, "--channel", "stable", "--allowed-hosts", "example.test", "--binding-sha256", sha},
				// Bad hex
				{cmd, "--host-bundle", "/bundle.tar.gz", "--envelope", "/env.json", "--public-key", strings.Repeat("Z", 64), "--channel", "stable", "--allowed-hosts", "example.test", "--binding-sha256", sha},
				{cmd, "--host-bundle", "/bundle.tar.gz", "--envelope", "/env.json", "--public-key", sha, "--channel", "stable", "--allowed-hosts", "example.test", "--binding-sha256", strings.Repeat("Z", 64)},
				// Bad channel
				{cmd, "--host-bundle", "/bundle.tar.gz", "--envelope", "/env.json", "--public-key", sha, "--channel", "alpha", "--allowed-hosts", "example.test", "--binding-sha256", sha},
			} {
				var stdout, stderr bytes.Buffer
				code := runWithDependencies(context.Background(), args, &stdout, &stderr, upgradeDependencies{
					acornFoxClean: acornFoxCleanDependencies{
						euid: func() int { return 0 },
					},
				})
				if code != exitArgs {
					t.Fatalf("args=%q expected exitArgs(%d), got %d stdout=%q", args, exitArgs, code, stdout.String())
				}
				res := cleanJSON(t, stdout.Bytes())
				if res["code"] != "invalid_arguments" {
					t.Fatalf("args=%q expected invalid_arguments, got %v", args, res)
				}
			}
		})

		t.Run(cmd+"/NonRootRejection", func(t *testing.T) {
			fix := buildTestOverlayFixture(t, testOverlayFixtureOpts{})
			args := []string{
				cmd,
				"--host-bundle", fix.bundlePath,
				"--envelope", fix.envelopePath,
				"--public-key", fix.pubKeyHex,
				"--channel", fix.channel,
				"--allowed-hosts", fix.allowedHosts,
				"--binding-sha256", fix.bindingSHA256,
			}
			var stdout, stderr bytes.Buffer
			code := runWithDependencies(context.Background(), args, &stdout, &stderr, upgradeDependencies{
				acornFoxClean: acornFoxCleanDependencies{
					euid: func() int { return 1000 },
				},
			})
			if code != exitIneligible {
				t.Fatalf("expected exitIneligible, got %d", code)
			}
			res := cleanJSON(t, stdout.Bytes())
			if res["code"] != "root_ineligible" {
				t.Fatalf("expected root_ineligible, got %v", res)
			}
		})
	}
}

func TestInitialHostOverlayVerificationNegatives(t *testing.T) {
	withAcornFoxIdentity(t)

	for _, cmd := range []string{"initial-host-overlay-preflight", "initial-host-overlay-apply"} {
		wrongArch := "amd64"
		if runtime.GOARCH == "amd64" {
			wrongArch = "arm64"
		}

		cases := []struct {
			name string
			opts testOverlayFixtureOpts
		}{
			{"TamperedEnvelopeSignature", testOverlayFixtureOpts{corruptSignature: true}},
			{"TamperedEnvelopePayload", testOverlayFixtureOpts{corruptEnvelope: true}},
			{"WrongPublicKey", testOverlayFixtureOpts{wrongPublicKey: true}},
			{"TamperedBundleBytes", testOverlayFixtureOpts{corruptBundle: true}},
			{"CandidateBackendModeRejected", testOverlayFixtureOpts{backendMode: "candidate"}},
			{"BackendBindingSwapRejected", testOverlayFixtureOpts{bindingSHA256: strings.Repeat("b", 64)}},
			{"WrongOS", testOverlayFixtureOpts{targetOS: "darwin"}},
			{"WrongArch", testOverlayFixtureOpts{targetArch: wrongArch}},
			{"MissingCanonicalUnit", testOverlayFixtureOpts{omitMember: overlayMemberCanonicalUnit}},
			{"MissingGuestWorker", testOverlayFixtureOpts{omitMember: overlayMemberGuestWorker}},
			{"MissingHostPolicy", testOverlayFixtureOpts{omitMember: overlayMemberHostPolicy}},
			{"UnequalC0LauncherController", testOverlayFixtureOpts{unequalC0: true}},
			{"CorruptUnitBytes", testOverlayFixtureOpts{corruptUnitBytes: true}},
			{"CorruptHostPolicy", testOverlayFixtureOpts{corruptHostPolicy: true}},
			{"CorruptGuestPolicy", testOverlayFixtureOpts{corruptGuestPol: true}},
		}

		for _, tc := range cases {
			t.Run(cmd+"/"+tc.name, func(t *testing.T) {
				fix := buildTestOverlayFixture(t, tc.opts)
				guestCalled := 0
				hostCalled := 0
				deps := upgradeDependencies{
					acornFoxClean: acornFoxCleanDependencies{
						euid: func() int { return 0 },
						guestProvision: func(context.Context, overlayGuestProvisionRequest) (*overlayGuestProvisionReceipt, error) {
							guestCalled++
							return &overlayGuestProvisionReceipt{}, nil
						},
						hostProvision: func(context.Context, hostprovision.ProvisionRequest) (*hostprovision.ProvisionReceipt, error) {
							hostCalled++
							return &hostprovision.ProvisionReceipt{}, nil
						},
					},
				}

				expectedBinding := fix.bindingSHA256
				if tc.name == "BackendBindingSwapRejected" {
					expectedBinding = strings.Repeat("f", 64) // mismatch
				}

				args := []string{
					cmd,
					"--host-bundle", fix.bundlePath,
					"--envelope", fix.envelopePath,
					"--public-key", fix.pubKeyHex,
					"--channel", fix.channel,
					"--allowed-hosts", fix.allowedHosts,
					"--binding-sha256", expectedBinding,
				}

				var stdout, stderr bytes.Buffer
				code := runWithDependencies(context.Background(), args, &stdout, &stderr, deps)
				if code != exitIneligible {
					t.Fatalf("expected exitIneligible(%d), got %d, stdout=%s", exitIneligible, code, stdout.String())
				}
				res := cleanJSON(t, stdout.Bytes())
				if res["code"] != "overlay_ineligible" {
					t.Fatalf("expected overlay_ineligible, got %v", res)
				}
				if guestCalled != 0 || hostCalled != 0 {
					t.Fatalf("effects called before verification: guest=%d, host=%d", guestCalled, hostCalled)
				}
			})
		}
	}
}

func TestInitialHostOverlayPreflightReadOnly(t *testing.T) {
	withAcornFoxIdentity(t)
	fix := buildTestOverlayFixture(t, testOverlayFixtureOpts{})

	guestCalled := 0
	hostCalled := 0
	deps := upgradeDependencies{
		acornFoxClean: acornFoxCleanDependencies{
			euid: func() int { return 0 },
			guestProvision: func(context.Context, overlayGuestProvisionRequest) (*overlayGuestProvisionReceipt, error) {
				guestCalled++
				return &overlayGuestProvisionReceipt{}, nil
			},
			hostProvision: func(context.Context, hostprovision.ProvisionRequest) (*hostprovision.ProvisionReceipt, error) {
				hostCalled++
				return &hostprovision.ProvisionReceipt{}, nil
			},
		},
	}

	args := []string{
		"initial-host-overlay-preflight",
		"--host-bundle", fix.bundlePath,
		"--envelope", fix.envelopePath,
		"--public-key", fix.pubKeyHex,
		"--channel", fix.channel,
		"--allowed-hosts", fix.allowedHosts,
		"--binding-sha256", fix.bindingSHA256,
	}

	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(), args, &stdout, &stderr, deps)
	if code != exitOK {
		t.Fatalf("preflight failed: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if guestCalled != 0 || hostCalled != 0 {
		t.Fatalf("preflight must have zero effects: guest=%d, host=%d", guestCalled, hostCalled)
	}

	res := cleanJSON(t, stdout.Bytes())
	if res["ok"] != true || res["command"] != "initial-host-overlay-preflight" {
		t.Fatalf("unexpected preflight response: %v", res)
	}
	receipt, ok := res["receipt"].(map[string]any)
	if !ok {
		t.Fatalf("missing receipt in response: %v", res)
	}
	if receipt["binding_sha256"] != fix.bindingSHA256 {
		t.Fatalf("binding mismatch in receipt: %v", receipt)
	}
	if receipt["c0_sha256"] != fix.c0SHA256 {
		t.Fatalf("c0 sha mismatch in receipt: %v", receipt)
	}
	if receipt["unit_sha256"] != hostoverlay.BootstrapUnitSHA256() {
		t.Fatalf("unit sha mismatch in receipt: %v", receipt)
	}
}

func TestInitialHostOverlayApplyOrderAndStaging(t *testing.T) {
	withAcornFoxIdentity(t)
	fix := buildTestOverlayFixture(t, testOverlayFixtureOpts{})

	var callOrder []string
	var receivedGuestReq overlayGuestProvisionRequest
	var receivedHostReq hostprovision.ProvisionRequest

	deps := upgradeDependencies{
		acornFoxClean: acornFoxCleanDependencies{
			euid: func() int { return 0 },
			guestProvision: func(ctx context.Context, req overlayGuestProvisionRequest) (*overlayGuestProvisionReceipt, error) {
				callOrder = append(callOrder, "guest")
				receivedGuestReq = req

				// Verify staged guest worker exists and matches hash
				data, err := os.ReadFile(req.WorkerSourcePath)
				if err != nil {
					t.Fatalf("cannot read staged guest worker: %v", err)
				}
				actualSHA := sha256HexStr(data)
				if actualSHA != req.ExpectedWorkerSHA256 {
					t.Fatalf("staged worker SHA mismatch: got %s, want %s", actualSHA, req.ExpectedWorkerSHA256)
				}

				// Verify staged guest policy exists and matches hash
				pData, err := os.ReadFile(req.PolicySourcePath)
				if err != nil {
					t.Fatalf("cannot read staged guest policy: %v", err)
				}
				actualPolSHA := sha256HexStr(pData)
				if actualPolSHA != req.ExpectedPolicySHA256 {
					t.Fatalf("staged guest policy SHA mismatch: got %s, want %s", actualPolSHA, req.ExpectedPolicySHA256)
				}

				return &overlayGuestProvisionReceipt{
					Kind:                 "linux-local",
					InstanceID:           strings.Repeat("1", 64),
					NativeID:             strings.Repeat("2", 64),
					WorkerSHA256:         actualSHA,
					PolicySHA256:         actualPolSHA,
					BootstrapHostVersion: req.BootstrapHostVersion,
				}, nil
			},
			hostProvision: func(ctx context.Context, req hostprovision.ProvisionRequest) (*hostprovision.ProvisionReceipt, error) {
				callOrder = append(callOrder, "host")
				receivedHostReq = req

				// Verify staged bootstrap exists and matches hash
				bData, err := os.ReadFile(req.StableBootstrapSource)
				if err != nil {
					t.Fatalf("cannot read staged bootstrap: %v", err)
				}
				actualBSHA := sha256HexStr(bData)
				if actualBSHA != req.ExpectedBootstrapSHA256 {
					t.Fatalf("staged bootstrap SHA mismatch")
				}

				// Verify staged C0 exists and matches hash
				cData, err := os.ReadFile(req.ManagedC0Source)
				if err != nil {
					t.Fatalf("cannot read staged C0: %v", err)
				}
				actualC0SHA := sha256HexStr(cData)
				if actualC0SHA != req.ExpectedC0SHA256 {
					t.Fatalf("staged C0 SHA mismatch")
				}

				return &hostprovision.ProvisionReceipt{
					InstanceID:              strings.Repeat("1", 64),
					BootstrapID:             "bootstrap-id-1",
					BootstrapVersion:        req.BootstrapVersion,
					BootstrapBackendBinding: req.BootstrapBackendBinding,
					StableBootstrapSHA256:   req.ExpectedBootstrapSHA256,
					LauncherSHA256:          req.ExpectedC0SHA256,
					ControllerSHA256:        req.ExpectedC0SHA256,
					ConfigSHA256:            strings.Repeat("3", 64),
					PolicySHA256:            req.ExpectedPolicySHA256,
				}, nil
			},
		},
	}

	args := []string{
		"initial-host-overlay-apply",
		"--host-bundle", fix.bundlePath,
		"--envelope", fix.envelopePath,
		"--public-key", fix.pubKeyHex,
		"--channel", fix.channel,
		"--allowed-hosts", fix.allowedHosts,
		"--binding-sha256", fix.bindingSHA256,
	}

	var stdout, stderr bytes.Buffer
	code := runWithDependencies(context.Background(), args, &stdout, &stderr, deps)
	if code != exitOK {
		t.Fatalf("apply failed: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	// 1. Strict callback ordering: guest provision MUST precede host provision
	if len(callOrder) != 2 || callOrder[0] != "guest" || callOrder[1] != "host" {
		t.Fatalf("callback order violation: %v (must be [guest, host])", callOrder)
	}

	// 2. Verify guest provision request fields
	if receivedGuestReq.Kind != "linux-local" || receivedGuestReq.BootstrapHostVersion != fix.version {
		t.Fatalf("invalid guest provision request: %+v", receivedGuestReq)
	}
	if receivedGuestReq.ExpectedWorkerSHA256 != fix.guestWorkerSHA || receivedGuestReq.ExpectedPolicySHA256 != fix.guestPolicySHA {
		t.Fatalf("guest provision hash mismatch: %+v", receivedGuestReq)
	}

	// 3. Verify host provision request fields
	if receivedHostReq.BootstrapVersion != fix.version || receivedHostReq.BootstrapBackendBinding != fix.bindingSHA256 {
		t.Fatalf("invalid host provision request: %+v", receivedHostReq)
	}
	if receivedHostReq.ExpectedBootstrapSHA256 != fix.bootstrapSHA256 || receivedHostReq.ExpectedC0SHA256 != fix.c0SHA256 || receivedHostReq.ExpectedPolicySHA256 != fix.hostPolicySHA {
		t.Fatalf("host provision hash mismatch: %+v", receivedHostReq)
	}

	// 4. Verify receipt structure
	res := cleanJSON(t, stdout.Bytes())
	if res["ok"] != true {
		t.Fatalf("expected ok=true, got %v", res)
	}
	receipt := res["receipt"].(map[string]any)
	if receipt["instance_id"] != strings.Repeat("1", 64) || receipt["bootstrap_backend_binding"] != fix.bindingSHA256 {
		t.Fatalf("unexpected receipt: %v", receipt)
	}

	// 5. Test guest provision failure stops before host provision
	t.Run("GuestFailureStopsBeforeHost", func(t *testing.T) {
		hostRan := false
		failingDeps := upgradeDependencies{
			acornFoxClean: acornFoxCleanDependencies{
				euid: func() int { return 0 },
				guestProvision: func(context.Context, overlayGuestProvisionRequest) (*overlayGuestProvisionReceipt, error) {
					return nil, errors.New("simulated guest provision error")
				},
				hostProvision: func(context.Context, hostprovision.ProvisionRequest) (*hostprovision.ProvisionReceipt, error) {
					hostRan = true
					return nil, nil
				},
			},
		}

		var fStdout, fStderr bytes.Buffer
		fCode := runWithDependencies(context.Background(), args, &fStdout, &fStderr, failingDeps)
		if fCode != exitRecovery {
			t.Fatalf("expected exitRecovery, got %d", fCode)
		}
		if hostRan {
			t.Fatal("host provision must NOT run when guest provision fails")
		}
		fRes := cleanJSON(t, fStdout.Bytes())
		if fRes["code"] != "guest_provision_failed" {
			t.Fatalf("expected guest_provision_failed, got %v", fRes)
		}
	})
}

func sha256HexStr(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

func TestInitialHostOverlayRejectsIndexURLBeforeEffects(t *testing.T) {
	withAcornFoxIdentity(t)
	for _, indexURL := range []string{
		"http://updates.acornfox.test/index.json",
		"https://foreign.example/index.json",
		"https://user@updates.acornfox.test/index.json",
		"https://updates.acornfox.test/index.json#fragment",
		"https://updates.acornfox.test/index.json?query=1",
		"https://updates.acornfox.test:8443/index.json",
		"https://%invalid/index.json",
	} {
		t.Run(indexURL, func(t *testing.T) {
			fix := buildTestOverlayFixture(t, testOverlayFixtureOpts{hostIndexURL: indexURL})
			calls := 0
			deps := upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{
				euid: func() int { return 0 },
				guestProvision: func(context.Context, overlayGuestProvisionRequest) (*overlayGuestProvisionReceipt, error) {
					calls++
					return &overlayGuestProvisionReceipt{}, nil
				},
				hostProvision: func(context.Context, hostprovision.ProvisionRequest) (*hostprovision.ProvisionReceipt, error) {
					calls++
					return &hostprovision.ProvisionReceipt{}, nil
				},
			}}
			for _, command := range []string{"initial-host-overlay-preflight", "initial-host-overlay-apply"} {
				args := []string{command, "--host-bundle", fix.bundlePath, "--envelope", fix.envelopePath, "--public-key", fix.pubKeyHex, "--channel", fix.channel, "--allowed-hosts", fix.allowedHosts, "--binding-sha256", fix.bindingSHA256}
				var stdout, stderr bytes.Buffer
				code := runWithDependencies(context.Background(), args, &stdout, &stderr, deps)
				if code != exitIneligible || calls != 0 {
					t.Fatalf("command=%s code=%d effects=%d stdout=%s", command, code, calls, stdout.String())
				}
			}
		})
	}
}
