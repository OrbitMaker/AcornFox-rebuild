package acornfoxsetup

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/providers/acornfoxroute"
)

func TestHTTPSBundleContainsExactlyEightBoundFiles(t *testing.T) {
	b := generate(t)
	if len(b.Files) != 8 {
		t.Fatal("expected eight fixed setup files")
	}
	var raw, env []byte
	for _, file := range b.Files {
		if file.Path == EdgeConfiguration {
			if file.Mode != 0644 || file.Owner != Root || file.Group != Root {
				t.Fatal("unsafe edge config ownership")
			}
			raw = file.Data
		}
		if file.Path == ServerEnvironment {
			env = file.Data
		}
	}
	if !bytes.Contains(env, []byte("ACORNFOX_PUBLIC_ROOT='console.example.com'")) {
		t.Fatalf("root is not the exact origin subtree: %s", env)
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("invalid edge JSON")
	}
	admin := doc["admin"].(map[string]any)
	if admin["listen"] != "127.0.0.1:2020" {
		t.Fatal("public admin")
	}
	apps := doc["apps"].(map[string]any)
	tls := apps["tls"].(map[string]any)
	if tls["certificates"].(map[string]any)["automate"].([]any)[0] != "console.example.com" {
		t.Fatal("wrong static certificate")
	}
	permission := tls["automation"].(map[string]any)["on_demand"].(map[string]any)["permission"].(map[string]any)
	if permission["module"] != "http" || permission["endpoint"] != acornfoxroute.PermissionURL {
		t.Fatal("unbounded certificate permission")
	}
	for _, required := range []string{"127.0.0.1:18482", "127.0.0.1:8080", `"listen":[":443"]`, `"@id":"acornfox-app-routes"`, `"delete":["X-Open-Card-*"]`, `/api/v1/acornfox/*`} {
		if !bytes.Contains(raw, []byte(required)) {
			t.Fatal("missing HTTPS boundary", required)
		}
	}
	if bytes.Contains(raw, []byte("*.")) || bytes.Contains(raw, []byte("private_key")) {
		t.Fatal("wildcard certificate or private material requested")
	}
	for i := range b.Files {
		if b.Files[i].Path == EdgeConfiguration {
			b.Files[i].Data = bytes.Replace(raw, []byte("127.0.0.1:2020"), []byte("0.0.0.0:2020"), 1)
		}
	}
	if Validate(b, inputs()) == nil {
		t.Fatal("changed Caddy config accepted")
	}
}
func TestPublicHTTPSRejectsOriginsWithoutControlledDNSOrStandardPort(t *testing.T) {
	for _, origin := range []string{"https://1.1.1.1", "https://[2001:4860:4860::8888]", "https://console.example.com:8443", "https://localhost", "https://console.example.com.evil/"} {
		in := inputs()
		in.Origin = origin
		if err := ValidateInputs(in); err == nil || !strings.Contains(err.Error(), "DNS hostname on port 443") {
			t.Fatalf("origin=%s err=%v", origin, err)
		}
		if _, err := Generate(in, rand.Reader); err == nil {
			t.Fatal("invalid public origin generated")
		}
	}
}
