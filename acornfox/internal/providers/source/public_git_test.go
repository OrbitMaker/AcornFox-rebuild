package source

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/foundation"
)

type fixtureGitResolver struct {
	answers map[string][]netip.Addr
	err     error
}

func (r fixtureGitResolver) LookupNetIP(_ context.Context, host string) ([]netip.Addr, error) {
	if r.err != nil {
		return nil, r.err
	}
	return append([]netip.Addr(nil), r.answers[host]...), nil
}

func TestResolveGitAuthorityRequiresExplicitPublicResolvers(t *testing.T) {
	provider := newTestProvider(t, t.TempDir(), t.TempDir())
	address := netip.MustParseAddr("8.8.8.8")
	provider.gitResolvers = []GitResolver{
		fixtureGitResolver{answers: map[string][]netip.Addr{"git.public.org": {address}}},
		fixtureGitResolver{answers: map[string][]netip.Addr{"git.public.org": {address}}},
	}
	git, err := foundation.NormalizeGitSource("https://git.public.org/project/repo.git", "main")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := provider.resolveGitAuthority(context.Background(), git)
	if err != nil || authority.host != "git.public.org" || authority.port != 443 || len(authority.addresses) != 1 || authority.addresses[0] != address {
		t.Fatalf("authority=%+v err=%v", authority, err)
	}
}

func TestResolveGitAuthorityFailsClosedForInvalidTargets(t *testing.T) {
	for _, locator := range []string{
		"http://git.public.org/repo.git",
		"https://127.0.0.1/repo.git",
		"https://2130706433/repo.git",
		"https://0177.0.0.1/repo.git",
		"https://0x7f.1/repo.git",
		"https://user@git.public.org/repo.git",
		"https://git.public.org:8443/repo.git",
		"https://localhost/repo.git",
		"https://git.example.test/repo.git",
	} {
		provider := newTestProvider(t, t.TempDir(), t.TempDir())
		provider.gitResolvers = []GitResolver{
			fixtureGitResolver{answers: map[string][]netip.Addr{"git.public.org": {netip.MustParseAddr("8.8.8.8")}}},
			fixtureGitResolver{answers: map[string][]netip.Addr{"git.public.org": {netip.MustParseAddr("8.8.8.8")}}},
		}
		git, err := provider.normalizeGitSource(locator, "main")
		if err == nil {
			_, err = provider.resolveGitAuthority(context.Background(), git)
		}
		if err == nil {
			t.Fatalf("unsafe locator accepted: %s", locator)
		}
	}
	provider := newTestProvider(t, t.TempDir(), t.TempDir())
	provider.gitResolvers = []GitResolver{
		fixtureGitResolver{answers: map[string][]netip.Addr{"git.public.org": {netip.MustParseAddr("8.8.8.8")}}},
		fixtureGitResolver{answers: map[string][]netip.Addr{"git.public.org": {netip.MustParseAddr("1.1.1.1")}}},
	}
	git, _ := foundation.NormalizeGitSource("https://git.public.org/repo.git", "main")
	if authority, err := provider.resolveGitAuthority(context.Background(), git); err != nil || len(authority.addresses) != 2 {
		t.Fatalf("regional public answers authority=%+v error=%v", authority, err)
	}
	provider.gitResolvers = nil
	if _, err := provider.resolveGitAuthority(context.Background(), git); !errors.Is(err, errGitPolicyUnavailable) {
		t.Fatalf("missing resolver error=%v", err)
	}
	git.Ref = "--upload-pack=unexpected"
	provider.gitResolvers = []GitResolver{
		fixtureGitResolver{answers: map[string][]netip.Addr{"git.public.org": {netip.MustParseAddr("8.8.8.8")}}},
		fixtureGitResolver{answers: map[string][]netip.Addr{"git.public.org": {netip.MustParseAddr("8.8.8.8")}}},
	}
	if _, err := provider.resolveGitAuthority(context.Background(), git); !errors.Is(err, errGitRejected) {
		t.Fatalf("option-like ref error=%v", err)
	}
}

func TestPreparePublicGitNeverFallsBackToSystemResolver(t *testing.T) {
	workspace := t.TempDir() + "/workspaces"
	provider := newTestProvider(t, t.TempDir(), workspace)
	request := contracts.PrepareSourceRequest{ApplicationID: "app_no_resolver", Kind: domain.SourceGitHTTPS, Locator: "https://git.public.org/repo.git", Ref: "main", Operation: contracts.OperationContext{IdempotencyKey: "no-system-resolver"}}
	_, err := provider.Prepare(context.Background(), request)
	assertProviderCode(t, err, contracts.ErrUnavailable)
	assertNoPublishedGitWorkspace(t, workspace)
}

func TestPinnedGitCommandDisablesRedirectsCredentialsAndOtherProtocols(t *testing.T) {
	provider := newTestProvider(t, t.TempDir(), t.TempDir())
	arguments := t.TempDir() + "/arguments"
	script := t.TempDir() + "/git-wrapper"
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >"+arguments+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	provider.gitBinary = script
	_, err := provider.gitOutputPinned(context.Background(), "", gitAuthority{host: "git.public.org", port: 443, addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}, "ls-remote", "https://git.public.org/repo.git", "main")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(arguments)
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, expected := range []string{"http.followRedirects=false", "http.curloptResolve=git.public.org:443:8.8.8.8", "credential.helper=", "protocol.http.allow=never", "protocol.file.allow=never", "protocol.ssh.allow=never", "fetch.recurseSubmodules=false"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("pinned Git command omitted %q: %s", expected, text)
		}
	}
}

func TestBoundedGitObjectDirectoryRejectsOversizedOrExcessFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(root+"/one", []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := boundedGitObjectDirectory(root, foundation.ArchiveLimits{MaxFiles: 2, MaxUnpackedBytes: 4}); !errors.Is(err, errGitTooLarge) {
		t.Fatalf("oversized object directory error=%v", err)
	}
	if err := os.WriteFile(root+"/one", []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"/two", []byte("2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := boundedGitObjectDirectory(root, foundation.ArchiveLimits{MaxFiles: 1, MaxUnpackedBytes: 4}); !errors.Is(err, errGitTooLarge) {
		t.Fatalf("excess object count error=%v", err)
	}
}

func TestPublicGitAddressRejectsIPv6SpecialPurposeRanges(t *testing.T) {
	for _, value := range []string{
		"64:ff9b::0a00:1", "64:ff9b:1::1", "100::1", "2001::1", "2002::1",
		"2620:4f:8000::1", "3fff::1", "5f00::1", "fc00::1", "fe80::1", "2001:db8::1",
	} {
		if isPublicGitAddress(netip.MustParseAddr(value)) {
			t.Fatalf("special IPv6 target accepted: %s", value)
		}
	}
	if !isPublicGitAddress(netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Fatal("ordinary global IPv6 target was rejected")
	}
}

func TestConfiguredGitResolversRequireDistinctPublicEndpoints(t *testing.T) {
	root, workspace := t.TempDir(), t.TempDir()
	if _, err := New(Config{UploadRoot: root, WorkspaceRoot: workspace, GitResolverEndpoints: []string{"127.0.0.1:53", "8.8.8.8:53"}}); err == nil {
		t.Fatal("private recursive resolver endpoint was accepted")
	}
	if _, err := New(Config{UploadRoot: root, WorkspaceRoot: workspace, GitResolverEndpoints: []string{"8.8.8.8:53"}}); err == nil {
		t.Fatal("single recursive resolver endpoint was accepted")
	}
	provider, err := New(Config{UploadRoot: root, WorkspaceRoot: workspace, GitResolverEndpoints: []string{"8.8.8.8:53", "1.1.1.1:53"}})
	if err != nil || len(provider.gitResolvers) != 2 {
		t.Fatalf("public recursive resolvers provider=%v err=%v", provider, err)
	}
}

func TestBoundedGitOutputRejectsOversizedReferenceAdvertisement(t *testing.T) {
	output := boundedGitOutput{limit: 4}
	if _, err := output.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("5")); !errors.Is(err, errGitTooLarge) || !output.exceeded || output.String() != "1234" {
		t.Fatalf("bounded advertisement err=%v exceeded=%v output=%q", err, output.exceeded, output.String())
	}
}
