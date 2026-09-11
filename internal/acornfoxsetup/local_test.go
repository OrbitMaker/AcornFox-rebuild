package acornfoxsetup

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/acornfoxenv"
)

func localInputs() Inputs {
	return Inputs{
		Origin:            ExactLocalLoopbackOrigin,
		Version:           "v1.0.0-beta.1",
		ResolverEndpoints: nil, // empty resolvers permitted for local
		Now:               time.Date(2026, 9, 6, 12, 0, 0, 123456789, time.UTC),
	}
}

func TestGenerateLocalContract(t *testing.T) {
	in := localInputs()
	b, err := GenerateLocal(in, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateLocal failed: %v", err)
	}

	// 1. Validate exactly 7 files (no edge.json)
	if len(b.Files) != 7 {
		t.Fatalf("expected exactly 7 files in local bundle, got %d", len(b.Files))
	}
	if err := ValidateLocal(b, in); err != nil {
		t.Fatalf("ValidateLocal failed: %v", err)
	}

	// 2. File specs, ownership, and permission bits
	for _, f := range b.Files {
		if !strings.HasPrefix(f.Path, RuntimeDirectory+"/") {
			t.Fatalf("bundle file %q escapes runtime directory", f.Path)
		}
		if f.Owner != Root || f.Group != Root {
			t.Fatalf("file %q must be owned by root:root", f.Path)
		}
		if strings.HasSuffix(f.Path, ".key") {
			if f.Mode != 0600 {
				t.Fatalf("private key %q must be mode 0600, got %o", f.Path, f.Mode)
			}
		} else if f.Mode != 0644 {
			t.Fatalf("public file %q must be mode 0644, got %o", f.Path, f.Mode)
		}
	}

	// 3. Server environment validation
	// Notice: server.env intentionally does NOT contain DATABASE_URL, which is kept in separate
	// database-specific configuration. Here we verify that combining server.env with a realistic
	// DATABASE_URL parses cleanly and keeps DB separation intact.
	serverLines := envLines(t, file(b, ServerEnvironment))
	serverEnvMap, err := acornfoxenv.ResolveEnviron(acornfoxenv.ProcessServer, "acornfox", serverLines)
	if err != nil {
		t.Fatalf("acornfoxenv clean server rejected local server.env: %v", err)
	}
	if serverEnvMap.Get(acornfoxenv.ConsoleAccess) != "local_loopback" {
		t.Fatalf("expected CONSOLE_ACCESS=local_loopback, got %q", serverEnvMap.Get(acornfoxenv.ConsoleAccess))
	}
	if serverEnvMap.Get(acornfoxenv.AuthOrigin) != ExactLocalLoopbackOrigin {
		t.Fatalf("expected AUTH_ORIGIN=%s, got %q", ExactLocalLoopbackOrigin, serverEnvMap.Get(acornfoxenv.AuthOrigin))
	}
	if serverEnvMap.Get(acornfoxenv.PublicRoot) != "" {
		t.Fatalf("PUBLIC_ROOT must be empty in local_loopback, got %q", serverEnvMap.Get(acornfoxenv.PublicRoot))
	}
	if serverEnvMap.Get(acornfoxenv.DatabaseURL) != "" {
		t.Fatalf("DATABASE_URL must not be in server.env, got %q", serverEnvMap.Get(acornfoxenv.DatabaseURL))
	}

	// Combined parse test: server.env + separate ACORNFOX_DATABASE_URL
	dbVal := "postgres://acornfox:secret@127.0.0.1:5432/acornfox?sslmode=disable"
	combinedLines := append(append([]string(nil), serverLines...), "ACORNFOX_DATABASE_URL="+dbVal)
	combinedEnvMap, err := acornfoxenv.ResolveEnviron(acornfoxenv.ProcessServer, "acornfox", combinedLines)
	if err != nil {
		t.Fatalf("failed to resolve combined server env with DATABASE_URL: %v", err)
	}
	if combinedEnvMap.Get(acornfoxenv.DatabaseURL) != dbVal {
		t.Fatalf("expected resolved DATABASE_URL in combined env, got %q", combinedEnvMap.Get(acornfoxenv.DatabaseURL))
	}

	// 4. Agent environment validation (strictly server-only CONSOLE_ACCESS)
	agentLines := envLines(t, file(b, AgentEnvironment))
	for _, line := range agentLines {
		if strings.HasPrefix(line, "ACORNFOX_CONSOLE_ACCESS=") {
			t.Fatalf("agent.env must not contain CONSOLE_ACCESS: %s", line)
		}
	}
	agentEnvMap, err := acornfoxenv.ResolveEnviron(acornfoxenv.ProcessAgent, "acornfox", agentLines)
	if err != nil {
		t.Fatalf("acornfoxenv clean agent rejected local agent.env: %v", err)
	}
	if agentEnvMap.Get(acornfoxenv.RuntimeEnabled) != "true" {
		t.Fatalf("expected RUNTIME_ENABLED=true in agent.env")
	}

	// 5. Mutual TLS validation
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(file(b, RuntimeDirectory+"/ca.crt")) {
		t.Fatal("failed to append CA cert")
	}
	serverTLS, err := tls.X509KeyPair(file(b, RuntimeDirectory+"/server.crt"), file(b, RuntimeDirectory+"/server.key"))
	if err != nil {
		t.Fatalf("failed to load server keypair: %v", err)
	}
	agentTLS, err := tls.X509KeyPair(file(b, RuntimeDirectory+"/agent.crt"), file(b, RuntimeDirectory+"/agent.key"))
	if err != nil {
		t.Fatalf("failed to load agent keypair: %v", err)
	}

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTLS},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		ServerName:   GatewayName,
	}
	clientConfig := &tls.Config{
		Certificates: []tls.Certificate{agentTLS},
		RootCAs:      caPool,
		ServerName:   GatewayName,
	}

	testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	testServer.TLS = serverConfig
	testServer.StartTLS()
	defer testServer.Close()

	client := testServer.Client()
	client.Transport = &http.Transport{TLSClientConfig: clientConfig}

	resp, err := client.Get(testServer.URL)
	if err != nil {
		t.Fatalf("mTLS roundtrip failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestLocalInputsValidation(t *testing.T) {
	// 1. Rejects non-exact local origin
	badOrigins := []string{
		"",
		" ",
		"https://console.example.com",
		"http://localhost:8080",
		"http://127.0.0.1:8081",
		"http://127.0.0.1:8080/",
		"http://127.0.0.2:8080",
	}
	for _, origin := range badOrigins {
		in := localInputs()
		in.Origin = origin
		if err := ValidateLocalInputs(in); err == nil {
			t.Fatalf("ValidateLocalInputs accepted invalid origin: %q", origin)
		}
	}

	// 2. Accepts configured valid resolvers
	inWithResolvers := localInputs()
	inWithResolvers.ResolverEndpoints = []string{"1.1.1.1:53", "8.8.8.8:53"}
	if err := ValidateLocalInputs(inWithResolvers); err != nil {
		t.Fatalf("ValidateLocalInputs rejected valid resolvers: %v", err)
	}

	// 3. Rejects invalid resolver list (e.g. private IP or 1 resolver)
	inBadResolver := localInputs()
	inBadResolver.ResolverEndpoints = []string{"127.0.0.1:53"}
	if err := ValidateLocalInputs(inBadResolver); err == nil {
		t.Fatal("ValidateLocalInputs accepted loopback resolver")
	}

	// 4. ValidateLocal rejects public bundle with edge.json
	in := localInputs()
	b, err := GenerateLocal(in, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Append edge.json to local bundle -> should be rejected
	mutated := clone(b)
	mutated.Files = append(mutated.Files, File{
		Path:  EdgeConfiguration,
		Mode:  0644,
		Owner: Root,
		Group: Root,
		Data:  []byte("{}"),
	})
	if err := ValidateLocal(mutated, in); err == nil {
		t.Fatal("ValidateLocal accepted bundle with extra EdgeConfiguration")
	}

	// 5. ValidateLocal rejects modified server.env containing PUBLIC_ROOT
	mutatedEnv := clone(b)
	for i, f := range mutatedEnv.Files {
		if f.Path == ServerEnvironment {
			mutatedEnv.Files[i].Data = append(bytes.Clone(f.Data), []byte("ACORNFOX_PUBLIC_ROOT='example.com'\n")...)
		}
	}
	if err := ValidateLocal(mutatedEnv, in); err == nil {
		t.Fatal("ValidateLocal accepted server.env with PUBLIC_ROOT")
	}
}

func TestRebindLocalVersionContract(t *testing.T) {
	in := localInputs()
	b, err := GenerateLocal(in, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	nextVersion := "v1.0.1-beta.2"
	reboundBundle, reboundInput, err := RebindLocalVersion(b, in, nextVersion)
	if err != nil {
		t.Fatalf("RebindLocalVersion failed: %v", err)
	}
	if reboundInput.Version != nextVersion {
		t.Fatalf("expected next version %s, got %s", nextVersion, reboundInput.Version)
	}
	if len(reboundBundle.Files) != 7 {
		t.Fatalf("expected 7 files in rebound bundle, got %d", len(reboundBundle.Files))
	}
	if err := ValidateLocal(reboundBundle, reboundInput); err != nil {
		t.Fatalf("ValidateLocal failed on rebound bundle: %v", err)
	}

	// Verify keys, certs and CA are preserved byte-for-byte
	for _, path := range []string{
		RuntimeDirectory + "/ca.crt",
		RuntimeDirectory + "/server.crt",
		RuntimeDirectory + "/server.key",
		RuntimeDirectory + "/agent.crt",
		RuntimeDirectory + "/agent.key",
	} {
		if !bytes.Equal(file(b, path), file(reboundBundle, path)) {
			t.Fatalf("file %s was mutated during rebind", path)
		}
	}

	// Verify agent.env has nextVersion
	agentLines := envLines(t, file(reboundBundle, AgentEnvironment))
	agentEnvMap, err := acornfoxenv.ResolveEnviron(acornfoxenv.ProcessAgent, "acornfox", agentLines)
	if err != nil {
		t.Fatalf("resolve agent env failed: %v", err)
	}
	if agentEnvMap.Get(acornfoxenv.AgentVersion) != nextVersion {
		t.Fatalf("expected agent version %s, got %s", nextVersion, agentEnvMap.Get(acornfoxenv.AgentVersion))
	}

	// RebindLocalVersion must reject public bundles
	publicBundle := generate(t)
	if _, _, err := RebindLocalVersion(publicBundle, inputs(), nextVersion); err == nil {
		t.Fatal("RebindLocalVersion accepted public bundle")
	}

	// RebindVersion (public) must reject local bundles
	if _, _, err := RebindVersion(b, in, nextVersion); err == nil {
		t.Fatal("RebindVersion accepted local bundle")
	}

	// WithBoundedEdgeGrace on local bundle is no-op and preserves 7 files
	edgeGraceBundle, err := WithBoundedEdgeGrace(b, in)
	if err != nil {
		t.Fatalf("WithBoundedEdgeGrace failed on local bundle: %v", err)
	}
	if len(edgeGraceBundle.Files) != 7 {
		t.Fatalf("expected 7 files in edge grace local bundle, got %d", len(edgeGraceBundle.Files))
	}
	if err := ValidateLocal(edgeGraceBundle, in); err != nil {
		t.Fatalf("ValidateLocal failed after edge grace: %v", err)
	}
}
