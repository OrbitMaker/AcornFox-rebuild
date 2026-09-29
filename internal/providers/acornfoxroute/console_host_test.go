package acornfoxroute

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"testing"
)

func generatedConsoleProxy(t *testing.T) object {
	t.Helper()
	raw, err := InitialConfig("https://console.example.com", []string{"223.5.5.5:53", "223.6.6.6:53"})
	if err != nil {
		t.Fatal(err)
	}
	var config object
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	servers := config["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	for _, entry := range servers["public_https"].(map[string]any)["routes"].([]any) {
		for _, handler := range entry.(map[string]any)["handle"].([]any) {
			h := handler.(map[string]any)
			if h["handler"] == "reverse_proxy" {
				return h
			}
		}
	}
	t.Fatal("missing console proxy")
	return nil
}

func TestOnlyConsoleProxyOverridesInternalHost(t *testing.T) {
	console := generatedConsoleProxy(t)
	request := console["headers"].(map[string]any)["request"].(map[string]any)
	if !reflect.DeepEqual(request["set"], map[string]any{"Host": []any{"127.0.0.1"}}) {
		t.Fatalf("wrong console request override: %v", request["set"])
	}
	if !reflect.DeepEqual(request["delete"], []any{"X-Open-Card-*"}) {
		t.Fatal("authority stripping changed")
	}
	// Application virtual hosts must see their actual public Host.
	_, _, _, intent := fixture(t)
	application := route(intent)["handle"].([]object)[0]
	appHeaders := application["headers"].(object)["request"].(object)
	if _, exists := appHeaders["set"]; exists {
		t.Fatal("application Host was overridden")
	}
}

func TestGeneratedConsoleHostReachesTheInternalSite(t *testing.T) {
	const page = "<!doctype html><div id=\"root\">AcornFox login</div>"
	const origin = "https://console.example.com"
	const csrf = "csrf-regression-fixture"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reproduce the installed Caddy site's exact host matcher. A route miss
		// returns empty 200, so checking only the status cannot establish a UI.
		if r.Host != "127.0.0.1" {
			return
		}
		if r.Header.Get("Origin") != origin || r.Header.Get("X-AcornFox-CSRF") != csrf {
			t.Error("Origin or CSRF changed")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, useGenerated := range []bool{false, true} {
		name := "preserved-public-host-reproduces-empty-200"
		if useGenerated {
			name = "generated-host-delivers-html"
		}
		t.Run(name, func(t *testing.T) {
			p := httputil.NewSingleHostReverseProxy(target)
			transport := &http.Transport{Proxy: nil}
			defer transport.CloseIdleConnections()
			p.Transport = transport
			original := p.Director
			var host string
			if useGenerated {
				handler := generatedConsoleProxy(t)
				set := handler["headers"].(map[string]any)["request"].(map[string]any)["set"].(map[string]any)
				host = set["Host"].([]any)[0].(string)
			}
			p.Director = func(r *http.Request) {
				original(r)
				if host != "" {
					r.Host = host
				}
			}
			request := httptest.NewRequest(http.MethodGet, "https://console.example.com/", nil)
			request.Header.Set("Origin", origin)
			request.Header.Set("X-AcornFox-CSRF", csrf)
			response := httptest.NewRecorder()
			p.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatal(response.Code)
			}
			if useGenerated {
				if response.Body.String() != page || response.Header().Get("Content-Type") != "text/html; charset=utf-8" {
					t.Fatalf("missing actual HTML: %q", response.Body.String())
				}
			} else if response.Body.Len() != 0 {
				t.Fatal("fixture did not reproduce the host mismatch")
			}
		})
	}
}

func TestCustomOnlyConfigHasNoPublicConsoleOrRoot(t *testing.T) {
	raw, err := CustomOnlyInitialConfig([]string{"223.5.5.5:53"})
	if err != nil {
		t.Fatal(err)
	}
	var config object
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	if config["admin"].(map[string]any)["listen"] != nativeAdminListen {
		t.Fatal("custom-only Caddy Admin did not use the protected Unix address")
	}
	apps := config["apps"].(map[string]any)
	servers := apps["http"].(map[string]any)["servers"].(map[string]any)
	routes := servers["public_https"].(map[string]any)["routes"].([]any)
	if len(routes) != 2 || routes[0].(map[string]any)["handle"].([]any)[0].(map[string]any)["@id"] != SubtreeID {
		t.Fatal("custom-only profile changed the owned application subtree")
	}
	tls := apps["tls"].(map[string]any)
	if _, exists := tls["certificates"].(map[string]any)["automate"]; exists {
		t.Fatal("custom-only profile would issue a public console certificate")
	}
	policies := tls["automation"].(map[string]any)["policies"].([]any)
	if len(policies) != 1 || policies[0].(map[string]any)["on_demand"] != true {
		t.Fatal("custom-only profile lost on-demand certificate permission")
	}
	if _, err := InitialConfig("", nil); err == nil {
		t.Fatal("legacy public-console profile accepted an empty root")
	}
	if generatedConsoleProxy(t)["handler"] != "reverse_proxy" {
		t.Fatal("old public-console profile changed")
	}
}
