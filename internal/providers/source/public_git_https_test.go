package source

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func TestPreparePublicGitHTTPSFixturePinsAuthorityAndReplaysWithoutClone(t *testing.T) {
	fixture := newHTTPSGitFixture(t, false)
	provider := fixture.provider(t)
	request := contracts.PrepareSourceRequest{ApplicationID: "app_git_fixture", Kind: domain.SourceGitHTTPS, Locator: fixture.URL("repo.git"), Ref: "main", Operation: contracts.OperationContext{IdempotencyKey: "fixture-git"}}
	first, err := provider.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision.Kind != domain.SourceGitHTTPS || first.Revision.Locator != request.Locator || first.Revision.Ref != "main" || len(first.Revision.Commit) != 40 || first.Revision.ContentDigest == "" {
		t.Fatalf("prepared Git revision=%+v", first.Revision)
	}
	if contents, err := os.ReadFile(filepath.Join(first.Revision.WorkspaceRef, "README.md")); err != nil || string(contents) != "fixture\n" {
		t.Fatalf("fixture workspace=%q err=%v", contents, err)
	}
	requests := fixture.requests.Load()
	second, err := provider.Prepare(context.Background(), request)
	if err != nil || second.Revision.ID != first.Revision.ID || fixture.requests.Load() != requests {
		t.Fatalf("Git idempotency replay=%+v err=%v requests=%d before=%d", second.Revision, err, fixture.requests.Load(), requests)
	}
}

func TestPreparePublicGitHTTPSFixtureRejectsUntrustedCertificate(t *testing.T) {
	fixture := newHTTPSGitFixture(t, false)
	provider := fixture.provider(t)
	provider.gitTLSCAFile = ""
	request := contracts.PrepareSourceRequest{ApplicationID: "app_git_untrusted", Kind: domain.SourceGitHTTPS, Locator: fixture.URL("repo.git"), Ref: "main", Operation: contracts.OperationContext{IdempotencyKey: "fixture-untrusted"}}
	if _, err := provider.Prepare(context.Background(), request); err == nil {
		t.Fatal("untrusted fixture certificate was accepted")
	}
	assertNoPublishedGitWorkspace(t, fixture.workspace)
}

func TestPreparePublicGitHTTPSFixtureRejectsRedirectAndTimeoutWithoutWorkspace(t *testing.T) {
	redirect := newHTTPSGitFixture(t, true)
	provider := redirect.provider(t)
	request := contracts.PrepareSourceRequest{ApplicationID: "app_git_redirect", Kind: domain.SourceGitHTTPS, Locator: redirect.URL("repo.git"), Ref: "main", Operation: contracts.OperationContext{IdempotencyKey: "fixture-redirect"}}
	if _, err := provider.Prepare(context.Background(), request); err == nil {
		t.Fatal("redirecting Git fixture was accepted")
	}
	assertNoPublishedGitWorkspace(t, redirect.workspace)

	timeout := newHTTPSGitFixture(t, false)
	timeout.delay.Store(true)
	timeoutProvider := timeout.provider(t)
	contextWithDeadline, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	request = contracts.PrepareSourceRequest{ApplicationID: "app_git_timeout", Kind: domain.SourceGitHTTPS, Locator: timeout.URL("repo.git"), Ref: "main", Operation: contracts.OperationContext{IdempotencyKey: "fixture-timeout"}}
	_, err := timeoutProvider.Prepare(contextWithDeadline, request)
	assertProviderCode(t, err, contracts.ErrTimeout)
	assertNoPublishedGitWorkspace(t, timeout.workspace)
}

type httpsGitFixture struct {
	server    *httptest.Server
	root      string
	workspace string
	caPath    string
	requests  atomic.Int64
	redirect  bool
	delay     atomic.Bool
}

func newHTTPSGitFixture(t *testing.T, redirect bool) *httpsGitFixture {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable")
	}
	root := t.TempDir()
	projects := filepath.Join(root, "projects")
	work := filepath.Join(root, "work")
	bare := filepath.Join(projects, "repo.git")
	for _, command := range [][]string{
		{"init", "-b", "main", work},
		{"-C", work, "config", "user.email", "fixture@example.test"},
		{"-C", work, "config", "user.name", "fixture"},
	} {
		runFixtureGit(t, command...)
	}
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, "-C", work, "add", "README.md")
	runFixtureGit(t, "-C", work, "commit", "-m", "fixture")
	if err := os.MkdirAll(projects, 0o700); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, "init", "--bare", bare)
	runFixtureGit(t, "-C", work, "remote", "add", "origin", bare)
	runFixtureGit(t, "-C", work, "push", "origin", "main")

	certificate, caPEM := fixtureTLSCertificate(t, "git.fixture.test")
	caPath := filepath.Join(root, "fixture-ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture := &httpsGitFixture{root: projects, workspace: filepath.Join(root, "workspaces"), caPath: caPath, redirect: redirect}
	server := httptest.NewUnstartedServer(http.HandlerFunc(fixture.serveHTTP))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	fixture.server = server
	t.Cleanup(server.Close)
	t.Cleanup(func() { makeTreeWritable(t, fixture.workspace) })
	return fixture
}

func (f *httpsGitFixture) URL(repository string) string {
	port := f.server.Listener.Addr().String()
	_, rawPort, err := net.SplitHostPort(port)
	if err != nil {
		panic(err)
	}
	return "https://git.fixture.test:" + rawPort + "/" + repository
}

func (f *httpsGitFixture) provider(t *testing.T) *Provider {
	t.Helper()
	provider, err := New(Config{UploadRoot: t.TempDir(), WorkspaceRoot: f.workspace})
	if err != nil {
		t.Fatal(err)
	}
	provider.testGitFixture = true
	provider.gitTLSCAFile = f.caPath
	provider.gitResolvers = []GitResolver{
		fixtureGitResolver{answers: map[string][]netip.Addr{"git.fixture.test": {netip.MustParseAddr("127.0.0.1")}}},
		fixtureGitResolver{answers: map[string][]netip.Addr{"git.fixture.test": {netip.MustParseAddr("127.0.0.1")}}},
	}
	return provider
}

func (f *httpsGitFixture) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	f.requests.Add(1)
	if f.delay.Load() {
		select {
		case <-request.Context().Done():
			return
		case <-time.After(time.Second):
		}
	}
	if f.redirect {
		writer.Header().Set("Location", "https://other.fixture.test/repo.git")
		writer.WriteHeader(http.StatusFound)
		return
	}
	command := exec.Command("git", "http-backend")
	contentLength := request.Header.Get("Content-Length")
	if contentLength == "" {
		contentLength = "0"
	}
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"GIT_PROJECT_ROOT=" + f.root,
		"GIT_HTTP_EXPORT_ALL=1",
		"REQUEST_METHOD=" + request.Method,
		"PATH_INFO=" + request.URL.Path,
		"QUERY_STRING=" + request.URL.RawQuery,
		"CONTENT_TYPE=" + request.Header.Get("Content-Type"),
		"CONTENT_LENGTH=" + contentLength,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
	}
	command.Stdin = request.Body
	payload, err := command.Output()
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	header, body, found := strings.Cut(string(payload), "\r\n\r\n")
	if !found {
		header, body, found = strings.Cut(string(payload), "\n\n")
	}
	if !found {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	status := http.StatusOK
	for _, line := range strings.Split(header, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, hasValue := strings.Cut(line, ":")
		if !hasValue {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(name), "Status") {
			if fields := strings.Fields(value); len(fields) > 0 {
				if parsedStatus, parseErr := strconv.Atoi(fields[0]); parseErr == nil {
					status = parsedStatus
				}
			}
			continue
		}
		writer.Header().Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, body)
}

func fixtureTLSCertificate(t *testing.T, hostname string) (tls.Certificate, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Open Card fixture CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{serverDER, caDER}, PrivateKey: serverKey}
	return certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func runFixtureGit(t *testing.T, arguments ...string) {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fixture git %v: %v (%s)", arguments, err, output)
	}
}

func assertNoPublishedGitWorkspace(t *testing.T, workspace string) {
	t.Helper()
	entries, err := os.ReadDir(workspace)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed Git source published workspace entries: %#v", entries)
	}
}
