// Package acornfoxroute owns only the named application subroute in the clean
// Edge configuration. Durable public-access records remain the source of truth.
package acornfoxroute

import (
	"encoding/json"
	"net"
	"net/url"
	"strings"

	"github.com/open-card/open-card/internal/contracts"
)

const (
	SubtreeID      = "acornfox-app-routes"
	AdminURL       = "http://127.0.0.1:2020"
	PermissionPath = "/internal/acornfox/tls/allow"
	PermissionURL  = "http://127.0.0.1:18481" + PermissionPath
)

type object = map[string]any

// AuthorizedRoot preserves the operator's exact DNS subtree. The existing
// AcornFox hostname contract appends apps. itself, so callers store this host
// as PUBLIC_ROOT rather than adding an additional apps. prefix.
func AuthorizedRoot(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Host == "" || origin != "https://"+u.Host || net.ParseIP(u.Hostname()) != nil || (u.Port() != "" && u.Port() != "443") {
		return "", errPolicy
	}
	host := u.Hostname()
	if !strings.Contains(host, ".") || host != strings.ToLower(host) || strings.HasSuffix(host, ".") || u.Host != host && u.Host != host+":443" {
		return "", errPolicy
	}
	derived, err := contracts.AcornFoxPublicHostname(host, "app_validation", "dep_validation")
	if err != nil || len(derived) > 253 {
		return "", errPolicy
	}
	return host, nil
}

func emptySubtree() object {
	return object{"@id": SubtreeID, "handler": "subroute", "routes": []object{}}
}
func proxy(target string) object {
	return object{
		"handler": "reverse_proxy", "upstreams": []object{{"dial": target}},
		// Clean CSRF is X-AcornFox-CSRF and is deliberately retained. None of the
		// historical actor/role/client-IP/task headers can cross this public edge.
		"headers": object{"request": object{"delete": []string{"X-Open-Card-*"}}},
	}
}

// InitialConfig is the exact native Caddy v2.11.4 configuration. Only the
// console is statically automated. Other certificate requests must receive
// permission from the local persisted-intent endpoint; no wildcard cert or
// DNS credentials are requested. Caddy owns HTTP-01 and HTTPS redirects.
const EdgeGracePeriod = "5s"

func InitialConfig(origin string, resolvers []string) ([]byte, error) {
	return initialConfig(origin, resolvers, EdgeGracePeriod)
}

// LegacyInitialConfig preserves the exact persisted pre-drain profile. It is
// only a validation input; new runtime generation uses the bounded profile.
func LegacyInitialConfig(origin string, resolvers []string) ([]byte, error) {
	return initialConfig(origin, resolvers, "")
}

func initialConfig(origin string, resolvers []string, grace string) ([]byte, error) {
	host, err := AuthorizedRoot(origin)
	if err != nil {
		return nil, err
	}
	unavailable := func(match object) object {
		return object{"match": []object{match}, "handle": []object{{"handler": "static_response", "status_code": 404}}, "terminal": true}
	}
	consoleProxy := proxy("127.0.0.1:8080")
	// The internal Caddy site matches Host 127.0.0.1. Preserving the public
	// console Host would miss that site and return Caddy's empty default 200.
	// Only this hop overrides Host; Origin, CSRF and application Hosts remain.
	consoleProxy["headers"].(object)["request"].(object)["set"] = object{"Host": []string{"127.0.0.1"}}
	console := object{"match": []object{{"host": []string{host}}}, "handle": []object{consoleProxy}, "terminal": true}
	appRoutes := object{"handle": []object{emptySubtree()}}
	config := object{
		"admin":   object{"listen": "127.0.0.1:2020", "config": object{"persist": false}},
		"storage": object{"module": "file_system", "root": "/var/lib/acornfox/edge/data"},
		"apps": object{
			"http": object{"servers": object{
				"edge_health": object{"listen": []string{"127.0.0.1:18482"}, "routes": []object{
					{"match": []object{{"path": []string{"/healthz"}}}, "handle": []object{{"handler": "static_response", "status_code": 200}}, "terminal": true},
					{"handle": []object{{"handler": "static_response", "status_code": 404}}},
				}},
				"public_https": object{"listen": []string{":443"}, "tls_connection_policies": []object{{}}, "strict_sni_host": true, "routes": []object{
					unavailable(object{"host": []string{host}, "path": []string{"/internal", "/internal/*", "/config", "/config/*", "/id", "/id/*", "/load", "/stop", "/healthz", "/readyz"}}),
					unavailable(object{"host": []string{host}, "path": []string{"/api", "/api/*"}, "not": []object{{"path": []string{"/api/v1/acornfox/*"}}}}),
					console, appRoutes, {"handle": []object{{"handler": "static_response", "status_code": 404}}},
				}},
			}},
			"tls": object{
				"certificates": object{"automate": []string{host}},
				"resolvers":    append([]string{}, resolvers...),
				"automation": object{
					"policies": []object{
						{"subjects": []string{host}, "issuers": []object{{"module": "acme"}}},
						{"on_demand": true, "issuers": []object{{"module": "acme"}}},
					},
					"on_demand": object{"permission": object{"module": "http", "endpoint": PermissionURL}},
				},
			},
		},
	}
	if grace != "" {
		config["apps"].(object)["http"].(object)["grace_period"] = grace
	}
	raw, err := json.Marshal(config)
	if err != nil {
		return nil, errPolicy
	}
	return append(raw, '\n'), nil
}
