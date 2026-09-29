package source

import (
	"context"
	"errors"
	"github.com/acornfox/acornfox/internal/foundation"
	"net/netip"
	"strings"
	"testing"
)

func TestResolveGitAuthorityAcceptsRegionalPublicAnswers(t *testing.T) {
	p := newTestProvider(t, t.TempDir(), t.TempDir())
	first := netip.MustParseAddr("172.182.252.133")
	second := netip.MustParseAddr("140.82.116.3")
	p.gitResolvers = []GitResolver{fixtureGitResolver{answers: map[string][]netip.Addr{"github.com": {first, first}}}, fixtureGitResolver{answers: map[string][]netip.Addr{"github.com": {second}}}}
	git, err := foundation.NormalizeGitSource("https://github.com/example/project.git", "main")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := p.resolveGitAuthority(context.Background(), git)
	if err != nil || len(authority.addresses) != 2 || authority.addresses[0] != second || authority.addresses[1] != first {
		t.Fatalf("authority=%+v err=%v", authority, err)
	}
	config := strings.Join(p.pinnedGitConfig(authority), "\n")
	for _, required := range []string{"http.sslVerify=true", "http.followRedirects=false", "protocol.http.allow=never", "protocol.ssh.allow=never", "http.curloptResolve=github.com:443:140.82.116.3,172.182.252.133"} {
		if !strings.Contains(config, required) {
			t.Fatalf("missing retained restriction: %s", required)
		}
	}
}

func TestResolveGitAuthorityRejectsAnyNonPublicAnswer(t *testing.T) {
	for _, invalid := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "198.18.0.120", "::ffff:127.0.0.1", "fd00::1", "64:ff9b::a00:1"} {
		t.Run(invalid, func(t *testing.T) {
			p := newTestProvider(t, t.TempDir(), t.TempDir())
			public := netip.MustParseAddr("172.182.252.133")
			p.gitResolvers = []GitResolver{fixtureGitResolver{answers: map[string][]netip.Addr{"github.com": {public}}}, fixtureGitResolver{answers: map[string][]netip.Addr{"github.com": {public, netip.MustParseAddr(invalid)}}}}
			git, _ := foundation.NormalizeGitSource("https://github.com/example/project.git", "main")
			if _, err := p.resolveGitAuthority(context.Background(), git); !errors.Is(err, errGitRejected) {
				t.Fatalf("mixed unsafe response accepted: %v", err)
			}
		})
	}
}
