package acornfoxsetup

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/acornfoxenv"
	"github.com/open-card/open-card/internal/providers/source"
)

func inputs() Inputs {
	return Inputs{Origin: "https://console.example.com", Version: "v1.0.0-beta.1", ResolverEndpoints: []string{"1.1.1.1:53", "8.8.8.8:53"}, Now: time.Date(2026, 9, 6, 12, 0, 0, 123456789, time.UTC)}
}
func generate(t *testing.T) Bundle {
	t.Helper()
	b, err := Generate(inputs(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func clone(b Bundle) Bundle {
	out := Bundle{Files: append([]File(nil), b.Files...)}
	for i := range out.Files {
		out.Files[i].Data = bytes.Clone(out.Files[i].Data)
	}
	return out
}
func file(b Bundle, path string) []byte {
	for _, f := range b.Files {
		if f.Path == path {
			return f.Data
		}
	}
	return nil
}
func envLines(t *testing.T, data []byte) []string {
	t.Helper()
	var lines []string
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || len(v) < 2 || v[0] != '\'' || v[len(v)-1] != '\'' || strings.Contains(v[1:len(v)-1], "'") {
			t.Fatal("invalid EnvironmentFile quoting")
		}
		lines = append(lines, k+"="+v[1:len(v)-1])
	}
	return lines
}

func TestGenerateRuntimeContract(t *testing.T) {
	b := generate(t)
	if err := Validate(b, inputs()); err != nil {
		t.Fatal(err)
	}
	if len(b.Files) != len(fileSpecs()) {
		t.Fatal("file closure changed")
	}
	if ServerEnvironment != "/etc/acornfox/runtime/server.env" || AgentEnvironment != "/etc/acornfox/runtime/agent.env" {
		t.Fatal("environment files must share the atomic runtime directory")
	}
	for _, f := range b.Files {
		if !strings.HasPrefix(f.Path, RuntimeDirectory+"/") {
			t.Fatal("bundle escapes the atomic runtime directory")
		}
		if f.Owner != Root {
			t.Fatal("owner")
		}
		if strings.HasSuffix(f.Path, ".key") {
			if f.Mode != 0600 || f.Group != Root {
				t.Fatal("private key access")
			}
		} else if f.Mode != 0644 || f.Group != Root {
			t.Fatal("public file access")
		}
	}
	for _, item := range []struct {
		path    string
		process acornfoxenv.Process
	}{{ServerEnvironment, acornfoxenv.ProcessServer}, {AgentEnvironment, acornfoxenv.ProcessAgent}} {
		lines := envLines(t, file(b, item.path))
		e, err := acornfoxenv.ResolveEnviron(item.process, "acornfox", lines)
		if err != nil || !e.Clean() {
			t.Fatalf("environment incompatibility: %v", err)
		}
		for _, k := range []acornfoxenv.Key{acornfoxenv.M2Enabled, acornfoxenv.M3Enabled, acornfoxenv.M4Enabled, acornfoxenv.M4RolloutEnabled, acornfoxenv.M5Enabled, acornfoxenv.M6Enabled, acornfoxenv.DatabaseURL} {
			if e.Get(k) != "" {
				t.Fatal("unexpected feature or database credential")
			}
		}
		if item.process == acornfoxenv.ProcessServer {
			if e.Get(acornfoxenv.ServerAgentTLSKey) != "/run/credentials/acornfox-server.service/server.key" {
				t.Fatal("server key must use the server credential directory")
			}
			if e.Get(acornfoxenv.AuthOrigin) != inputs().Origin || e.Get(acornfoxenv.M1Enabled) != "true" || e.Get(acornfoxenv.AgentGatewayAddr) != "127.0.0.1:8092" {
				t.Fatal("server contract")
			}
			if e.Get(acornfoxenv.BuildkitAddress) != "unix:///run/acornfox-buildkit/buildkitd.sock" || e.Get(acornfoxenv.BuildkitWorker) != "acornfox-installed" {
				t.Fatal("builder contract")
			}
			var identities []struct {
				CertificateID string `json:"certificate_id"`
				InstanceID    string `json:"instance_id"`
				NodeID        string `json:"node_id"`
			}
			if err := json.Unmarshal([]byte(e.Get(acornfoxenv.AgentIdentitiesJSON)), &identities); err != nil {
				t.Fatal(err)
			}
			cert, err := parseCertificate(file(b, RuntimeDirectory+"/agent.crt"))
			if err != nil {
				t.Fatal(err)
			}
			if len(identities) != 1 || identities[0].CertificateID != cert.SerialNumber.String() || identities[0].InstanceID != InstanceID || identities[0].NodeID != NodeID {
				t.Fatal("identity binding")
			}
			if e.Get(acornfoxenv.AgentDispatchInstanceID) != InstanceID || e.Get(acornfoxenv.AgentDispatchNodeID) != NodeID {
				t.Fatal("dispatch binding")
			}
			if _, err := source.New(source.Config{UploadRoot: t.TempDir(), WorkspaceRoot: t.TempDir(), GitResolverEndpoints: strings.Split(e.Get(acornfoxenv.SourceGitResolvers), ",")}); err != nil {
				t.Fatalf("source configuration: %v", err)
			}
		} else {
			if e.Get(acornfoxenv.AgentTLSKey) != "/run/credentials/acornfox-agent.service/agent.key" {
				t.Fatal("agent key must use the agent credential directory")
			}
			if e.Get(acornfoxenv.ControlPlaneServerName) != GatewayName || e.Get(acornfoxenv.ControlPlaneURL) != "https://127.0.0.1:8092" || e.Get(acornfoxenv.InstanceID) != InstanceID || e.Get(acornfoxenv.NodeID) != NodeID || e.Get(acornfoxenv.AgentVersion) != inputs().Version || e.Get(acornfoxenv.RuntimeEnabled) != "true" {
				t.Fatal("agent contract")
			}
		}
	}
}

func TestGeneratedCertificatesMutualTLS(t *testing.T) {
	b := generate(t)
	ca, err := parseCertificate(file(b, RuntimeDirectory+"/ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	serverPair, err := tls.X509KeyPair(file(b, RuntimeDirectory+"/server.crt"), file(b, RuntimeDirectory+"/server.key"))
	if err != nil {
		t.Fatal(err)
	}
	agentPair, err := tls.X509KeyPair(file(b, RuntimeDirectory+"/agent.crt"), file(b, RuntimeDirectory+"/agent.key"))
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return inputs().Now }
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) != 1 || r.TLS.PeerCertificates[0].SerialNumber.Cmp(agentPair.Leaf.SerialNumber) != 0 {
			t.Error("client certificate was not verified")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverPair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, Time: clock}
	s.StartTLS()
	defer s.Close()
	for _, name := range []string{GatewayName, "127.0.0.1"} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{agentPair}, ServerName: name, Time: clock}}
		client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
		res, err := client.Get(s.URL)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		tr.CloseIdleConnections()
		if res.StatusCode != http.StatusNoContent {
			t.Fatal("mTLS request failed")
		}
	}
	// Verify both usage boundaries, hostname, and expiry independently of setup's profile comparison.
	for _, tc := range []struct {
		cert  *x509.Certificate
		usage x509.ExtKeyUsage
		name  string
		now   time.Time
		ok    bool
	}{
		{serverPair.Leaf, x509.ExtKeyUsageServerAuth, GatewayName, inputs().Now, true},
		{agentPair.Leaf, x509.ExtKeyUsageClientAuth, "", inputs().Now, true},
		{serverPair.Leaf, x509.ExtKeyUsageClientAuth, "", inputs().Now, false},
		{agentPair.Leaf, x509.ExtKeyUsageServerAuth, GatewayName, inputs().Now, false},
		{serverPair.Leaf, x509.ExtKeyUsageServerAuth, "wrong-host", inputs().Now, false},
		{serverPair.Leaf, x509.ExtKeyUsageServerAuth, GatewayName, inputs().Now.Add(366 * 24 * time.Hour), false},
	} {
		_, err := tc.cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: tc.now, DNSName: tc.name, KeyUsages: []x509.ExtKeyUsage{tc.usage}})
		if (err == nil) != tc.ok {
			t.Fatal("certificate usage/time/name boundary")
		}
	}
}

func TestRejectBundleMutation(t *testing.T) {
	base := generate(t)
	other := generate(t)
	mutations := map[string]func(*Bundle){
		"missing": func(b *Bundle) { b.Files = b.Files[:6] },
		"extra": func(b *Bundle) {
			b.Files = append(b.Files, File{Path: RuntimeDirectory + "/ca.key", Data: []byte("extra")})
		},
		"duplicate":               func(b *Bundle) { b.Files[6] = b.Files[5] },
		"path":                    func(b *Bundle) { b.Files[4].Path = "/tmp/server.key" },
		"old-server-env-path":     func(b *Bundle) { b.Files[0].Path = "/etc/acornfox/server.env" },
		"old-agent-env-path":      func(b *Bundle) { b.Files[1].Path = "/etc/acornfox/agent.env" },
		"mode":                    func(b *Bundle) { b.Files[4].Mode = 0644 },
		"owner":                   func(b *Bundle) { b.Files[4].Owner = Server },
		"group":                   func(b *Bundle) { b.Files[4].Group = Agent },
		"server-shared-group-key": func(b *Bundle) { b.Files[4].Mode = 0640; b.Files[4].Group = Server },
		"agent-group-key":         func(b *Bundle) { b.Files[6].Mode = 0640; b.Files[6].Group = Agent },
		"server-source-key-path": func(b *Bundle) {
			b.Files[0].Data = bytes.ReplaceAll(b.Files[0].Data, []byte("/run/credentials/acornfox-server.service/server.key"), []byte(RuntimeDirectory+"/server.key"))
		},
		"agent-source-key-path": func(b *Bundle) {
			b.Files[1].Data = bytes.ReplaceAll(b.Files[1].Data, []byte("/run/credentials/acornfox-agent.service/agent.key"), []byte(RuntimeDirectory+"/agent.key"))
		},
		"agent-server-credential": func(b *Bundle) {
			b.Files[1].Data = bytes.ReplaceAll(b.Files[1].Data, []byte("/run/credentials/acornfox-agent.service/agent.key"), []byte("/run/credentials/acornfox-server.service/server.key"))
		},
		"nil":        func(b *Bundle) { b.Files[4].Data = nil },
		"wrong-key":  func(b *Bundle) { b.Files[4].Data = other.Files[4].Data },
		"wrong-ca":   func(b *Bundle) { b.Files[2].Data = other.Files[2].Data },
		"wrong-cert": func(b *Bundle) { b.Files[5].Data = other.Files[5].Data },
		"swapped-cert": func(b *Bundle) {
			b.Files[3], b.Files[5] = File{Path: b.Files[3].Path, Mode: 0644, Owner: Root, Group: Root, Data: b.Files[5].Data}, File{Path: b.Files[5].Path, Mode: 0644, Owner: Root, Group: Root, Data: b.Files[3].Data}
		},
		"pem-leading":  func(b *Bundle) { b.Files[2].Data = append([]byte("garbage\n"), b.Files[2].Data...) },
		"pem-trailing": func(b *Bundle) { b.Files[4].Data = append(b.Files[4].Data, '\n') },
		"pem-multiple": func(b *Bundle) { b.Files[3].Data = append(b.Files[3].Data, b.Files[2].Data...) },
		"pem-header": func(b *Bundle) {
			p, _ := pem.Decode(b.Files[4].Data)
			p.Headers = map[string]string{"Comment": "extra"}
			b.Files[4].Data = pem.EncodeToMemory(p)
		},
		"env-extra": func(b *Bundle) { b.Files[0].Data = append(b.Files[0].Data, []byte("ACORNFOX_M2_ENABLED='true'\n")...) },
		"env-serial": func(b *Bundle) {
			b.Files[0].Data = bytes.Replace(b.Files[0].Data, []byte(`"certificate_id":"`), []byte(`"certificate_id":"9`), 1)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			b := clone(base)
			mutate(&b)
			if Validate(b, inputs()) == nil {
				t.Fatal("mutation accepted")
			}
		})
	}
	// Every env assignment is part of the closed contract, including settings
	// whose names are recognized by the process but not enabled by this profile.
	for _, index := range []int{0, 1} {
		for _, line := range strings.Split(strings.TrimSuffix(string(base.Files[index].Data), "\n"), "\n") {
			k, _, _ := strings.Cut(line, "=")
			t.Run(k, func(t *testing.T) {
				b := clone(base)
				b.Files[index].Data = bytes.Replace(b.Files[index].Data, []byte(line), []byte(k+"='changed'"), 1)
				if Validate(b, inputs()) == nil {
					t.Fatal("changed env accepted")
				}
			})
		}
	}
	for _, mutate := range []func(*Inputs){func(i *Inputs) { i.Origin = "https://another.example.com" }, func(i *Inputs) { i.Version = "v2" }, func(i *Inputs) { i.Now = i.Now.Add(time.Second) }, func(i *Inputs) { i.ResolverEndpoints = []string{"8.8.8.8:53", "1.1.1.1:53"} }} {
		in := inputs()
		mutate(&in)
		if Validate(base, in) == nil {
			t.Fatal("wrong intent accepted")
		}
	}
	// A filesystem-neutral bundle need not preserve the generator's list order.
	reordered := clone(base)
	reordered.Files[0], reordered.Files[1] = reordered.Files[1], reordered.Files[0]
	if err := Validate(reordered, inputs()); err != nil {
		t.Fatal(err)
	}
}

func TestRejectSignedCertificateProfileDrift(t *testing.T) {
	ca, key, err := generateCertificate(inputs().Now, "ca", nil, nil, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*x509.Certificate){
		"extra-san":     func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "extra") },
		"long-life":     func(c *x509.Certificate) { c.NotAfter = c.NotAfter.Add(time.Second) },
		"extra-subject": func(c *x509.Certificate) { c.Subject.Organization = []string{"extra"} },
		"extra-usage":   func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth) },
		"is-ca":         func(c *x509.Certificate) { c.IsCA = true },
	} {
		t.Run(name, func(t *testing.T) {
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			c := template(inputs().Now, "server", big.NewInt(123))
			mutate(c)
			der, err := x509.CreateCertificate(rand.Reader, c, ca, pub, key)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.CheckSignatureFrom(ca) != nil {
				t.Fatal("fixture signature")
			}
			if validProfile(parsed, ca, "server", inputs().Now) {
				t.Fatal("signed profile drift accepted")
			}
		})
	}
}

func TestInputBoundaries(t *testing.T) {
	for _, origin := range []string{"", "http://example.com", "https://example.com/", "https://user@example.com", "https://example.com?", "https://example.com#", "https://example.com/path", "https://EXAMPLE.com", "https://example.com:0", "https://example.com:65536", "https://example.com:", "https://example.com:0443", "https://example.com\nEVIL=true", "https://example.com'", "https://[example.com]", "https://[1.1.1.1]", "https://[fe80::1%25en0]", "https://bad_name", "https://-example.com"} {
		in := inputs()
		in.Origin = origin
		if _, err := Generate(in, rand.Reader); err == nil {
			t.Errorf("origin accepted: %q", origin)
		}
	}
	for _, origin := range []string{"https://example.com", "https://example.com:443"} {
		in := inputs()
		in.Origin = origin
		if _, err := Generate(in, rand.Reader); err != nil {
			t.Errorf("valid origin rejected: %v", err)
		}
	}
	for _, endpoint := range []string{"localhost:53", "1.1.1.1", "1.1.1.1:54", "1.1.1.1:053", "1.1.1.1:53 ", "127.0.0.1:53", "10.1.2.3:53", "169.254.169.254:53", "100.64.0.1:53", "192.0.2.1:53", "198.18.0.1:53", "224.0.0.1:53", "0.0.0.0:53", "[::1]:53", "[fc00::1]:53", "[fe80::1%en0]:53", "[::ffff:8.8.8.8]:53", "[2001:db8::1]:53", "[2002::1]:53", "[3fff::1]:53", "8.8.8.8:53"} {
		in := inputs()
		in.ResolverEndpoints = []string{endpoint, "8.8.8.8:53"}
		if _, err := Generate(in, rand.Reader); err == nil {
			t.Errorf("endpoint accepted: %q", endpoint)
		}
	}
	for _, endpoints := range [][]string{nil, {"1.1.1.1:53"}, {"1.1.1.1:53", "1.1.1.1:53"}} {
		in := inputs()
		in.ResolverEndpoints = endpoints
		if _, err := Generate(in, rand.Reader); err == nil {
			t.Fatal("resolver count/dup accepted")
		}
	}
	in := inputs()
	in.ResolverEndpoints = []string{"[2001:4860:4860::8888]:53", "[2606:4700:4700::1111]:53"}
	if _, err := Generate(in, rand.Reader); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"", "v1\nX=y", "v1'", "v1;echo", "$(secret)", strings.Repeat("v", 129)} {
		in := inputs()
		in.Version = v
		if _, err := Generate(in, rand.Reader); err == nil {
			t.Fatal("unsafe version accepted")
		}
	}
	in = inputs()
	in.Now = time.Time{}
	if _, err := Generate(in, rand.Reader); err == nil {
		t.Fatal("zero generation time accepted")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("sensitive random source failure")
}
func TestNoAccidentalSecretDisclosure(t *testing.T) {
	b := generate(t)
	for _, value := range []any{b, &b, b.Files, &b.Files, b.Files[4], &b.Files[4], struct{ Bundle Bundle }{b}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			out := fmt.Sprintf(verb, value)
			if strings.Contains(out, "PRIVATE KEY") || strings.Contains(out, "Data:") {
				t.Fatal("fmt disclosed data")
			}
		}
		out, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "Data") || strings.Contains(string(out), "PRIVATE KEY") {
			t.Fatal("json disclosed data")
		}
	}
	for _, random := range []io.Reader{nil, failingReader{}, bytes.NewReader(nil)} {
		b, err := Generate(inputs(), random)
		if err == nil || len(b.Files) != 0 || strings.Contains(err.Error(), "sensitive") {
			t.Fatal("generation failure disclosed material")
		}
	}
}
