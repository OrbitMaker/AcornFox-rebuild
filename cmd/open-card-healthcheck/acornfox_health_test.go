package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/install"
)

func acornFoxHealthyFixture(t *testing.T) (dependencies, *int, *int) {
	t.Helper()
	oldIdentity, oldVersion, oldCommit, oldLayout := processIdentity, buildVersion, buildSourceCommit, buildLayoutSchema
	t.Cleanup(func() {
		processIdentity, buildVersion, buildSourceCommit, buildLayoutSchema = oldIdentity, oldVersion, oldCommit, oldLayout
	})
	processIdentity, buildVersion, buildSourceCommit, buildLayoutSchema = "acornfox", "1.2.3-test.1", strings.Repeat("a", 40), "1"
	verified, probed := new(int), new(int)
	deps := dependencies{
		euid:      func() int { return 0 },
		newRunner: func() (productionRunner, error) { t.Fatal("legacy runner called"); return nil, nil },
		acornFox: acornFoxHealthDependencies{
			environ: func() []string { return []string{"ACORNFOX_RUNTIME_MODE=clean"} },
			verify: func(id install.AcornFoxBuildIdentityV1) install.AcornFoxHelperContractResultV1 {
				*verified++
				return install.AcornFoxHelperContractResultV1{SchemaVersion: 1, OK: true, Code: "ok", Identity: &id, BindingSHA256: strings.Repeat("b", 64), ExecutableSHA256: strings.Repeat("c", 64), SubstrateReceiptSHA256: strings.Repeat("d", 64)}
			},
			probe: func(ctx context.Context) []acornFoxLocalCheck {
				*probed++
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded check")
				}
				checks := []acornFoxLocalCheck{}
				for _, name := range acornFoxLocalCheckNames() {
					checks = append(checks, acornFoxLocalCheck{Name: name, OK: true})
				}
				return checks
			},
		},
	}
	return deps, verified, probed
}

func TestAcornFoxHealthNoArgumentsRunsBoundedChecksAfterIdentity(t *testing.T) {
	deps, verified, probed := acornFoxHealthyFixture(t)
	var out, errout bytes.Buffer
	code := runWithDependencies(context.Background(), nil, &out, &errout, deps)
	if code != 0 || *verified != 1 || *probed != 1 || errout.Len() != 0 || !strings.Contains(out.String(), `"healthy":true`) || !strings.Contains(out.String(), `"scope":"local_services_only"`) {
		t.Fatalf("code=%d output=%s stderr=%s", code, &out, &errout)
	}
	if strings.Contains(out.String(), "acornfox-healthcheck.service") {
		t.Fatal("oneshot checks itself")
	}
}

func TestAcornFoxHealthRejectsBeforeAnyLocalProbe(t *testing.T) {
	for _, scenario := range []string{"nonroot", "missing-layout", "environment-override", "helper-failure", "wrong-helper-identity", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			deps, _, probed := acornFoxHealthyFixture(t)
			ctx := context.Background()
			switch scenario {
			case "nonroot":
				deps.euid = func() int { return 1000 }
			case "missing-layout":
				buildLayoutSchema = ""
			case "environment-override":
				deps.acornFox.environ = func() []string {
					return []string{"ACORNFOX_RUNTIME_MODE=clean", "OPEN_CARD_DATABASE_URL=credential-canary"}
				}
			case "helper-failure":
				deps.acornFox.verify = func(install.AcornFoxBuildIdentityV1) install.AcornFoxHelperContractResultV1 {
					return install.AcornFoxHelperContractResultV1{SchemaVersion: 1, Code: "credential-canary"}
				}
			case "wrong-helper-identity":
				verify := deps.acornFox.verify
				deps.acornFox.verify = func(id install.AcornFoxBuildIdentityV1) install.AcornFoxHelperContractResultV1 {
					id.SourceCommit = strings.Repeat("f", 40)
					return verify(id)
				}
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			var out, errout bytes.Buffer
			if code := runWithDependencies(ctx, nil, &out, &errout, deps); code == 0 || *probed != 0 || strings.Contains(out.String(), "canary") || errout.Len() != 0 {
				t.Fatalf("code=%d probes=%d out=%s", code, *probed, &out)
			}
		})
	}
}

func TestAcornFoxHealthEnvironmentIsClosed(t *testing.T) {
	for _, env := range [][]string{nil, {"ACORNFOX_RUNTIME_MODE=legacy"}, {"ACORNFOX_RUNTIME_MODE=clean", "ACORNFOX_HEALTH_URL=http://other"}, {"ACORNFOX_RUNTIME_MODE=clean", "OPEN_CARD_HEALTHCHECK_CONFIG=x"}, {"ACORNFOX_RUNTIME_MODE=clean", "ACORNFOX_RUNTIME_MODE=clean"}} {
		if acornFoxHealthEnvironment(env) {
			t.Fatalf("accepted %q", env)
		}
	}
	if !acornFoxHealthEnvironment([]string{"ACORNFOX_RUNTIME_MODE=clean", "HTTP_PROXY=http://ignored", "PATH=/ignored"}) {
		t.Fatal("unconsumed ambient variables should not supply authority")
	}
}

func TestAcornFoxHealthFailedOrUnsafeChecksDoNotReportSuccess(t *testing.T) {
	for _, unsafe := range []bool{false, true} {
		t.Run(map[bool]string{false: "unhealthy", true: "unsafe result"}[unsafe], func(t *testing.T) {
			deps, _, _ := acornFoxHealthyFixture(t)
			probe := deps.acornFox.probe
			deps.acornFox.probe = func(ctx context.Context) []acornFoxLocalCheck {
				checks := probe(ctx)
				checks[0].OK = false
				if unsafe {
					checks[0].Name = "credential-canary"
				}
				return checks
			}
			var out bytes.Buffer
			if code := runWithDependencies(context.Background(), nil, &out, io.Discard, deps); code == 0 || strings.Contains(out.String(), "canary") || strings.Contains(out.String(), `"healthy":true`) {
				t.Fatalf("code=%d out=%s", code, &out)
			}
		})
	}
}

type acornFoxRoundTrip func(*http.Request) (*http.Response, error)

func (f acornFoxRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func acornFoxLocalFixture(t *testing.T) (acornFoxLocalDependencies, *[]string) {
	t.Helper()
	visited := new([]string)
	return acornFoxLocalDependencies{
		command: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			if path != "/usr/bin/systemctl" || len(args) != 4 || !reflect.DeepEqual(args[:3], []string{"show", "--no-pager", "--property=Id,LoadState,ActiveState,SubState"}) {
				t.Fatalf("unsafe command %s %q", path, args)
			}
			unit := args[len(args)-1]
			*visited = append(*visited, unit)
			return []byte("Id=" + unit + "\nLoadState=loaded\nActiveState=active\nSubState=running\n"), nil
		},
		client: &http.Client{Transport: acornFoxRoundTrip(func(r *http.Request) (*http.Response, error) {
			*visited = append(*visited, r.URL.String())
			body := `{"status":"ok","ready":true}`
			if r.URL.Port() == "18482" {
				body = ""
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})},
		lstat: func(path string) (os.FileInfo, error) {
			if path != acornFoxUpgradeMarker {
				t.Fatal(path)
			}
			return nil, os.ErrNotExist
		},
		dataSpace: func() bool { return true },
	}, visited
}

func TestAcornFoxLocalChecksUseExactServicesAndEndpoints(t *testing.T) {
	deps, visited := acornFoxLocalFixture(t)
	checks := probeAcornFoxLocal(context.Background(), deps)
	for _, check := range checks {
		if !check.OK {
			t.Fatal(check)
		}
	}
	want := append(append([]string{}, acornFoxHealthUnits...), "http://127.0.0.1:18481/healthz", "http://127.0.0.1:18481/readyz", "http://127.0.0.1:18482/healthz")
	if !reflect.DeepEqual(*visited, want) {
		t.Fatalf("visited=%q", *visited)
	}
}

func TestAcornFoxLocalFailureClasses(t *testing.T) {
	for _, scenario := range []string{"marker", "marker-unreadable", "disk-full", "service-failed", "service-wrong-name", "readiness-failed", "bad-json", "edge-body", "oversized-body", "http-error", "marker-during-probe"} {
		t.Run(scenario, func(t *testing.T) {
			deps, visited := acornFoxLocalFixture(t)
			switch scenario {
			case "marker":
				deps.lstat = func(string) (os.FileInfo, error) { return nil, nil }
			case "marker-unreadable":
				deps.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
			case "disk-full":
				deps.dataSpace = func() bool { return false }
			case "service-failed":
				deps.command = func(context.Context, string, ...string) ([]byte, error) {
					return []byte("credential-canary"), errors.New("credential-canary")
				}
			case "service-wrong-name":
				cmd := deps.command
				deps.command = func(ctx context.Context, path string, args ...string) ([]byte, error) {
					raw, err := cmd(ctx, path, args...)
					return bytes.ReplaceAll(raw, []byte("Id="), []byte("Id=other-")), err
				}
			case "marker-during-probe":
				calls := 0
				deps.lstat = func(string) (os.FileInfo, error) {
					calls++
					if calls == 2 {
						return nil, nil
					}
					return nil, os.ErrNotExist
				}
			default:
				deps.client = &http.Client{Transport: acornFoxRoundTrip(func(r *http.Request) (*http.Response, error) {
					body, status := `{"status":"ok","ready":true}`, 200
					switch scenario {
					case "readiness-failed":
						status = 503
					case "bad-json":
						body = `{"status":"ok","ready":false}`
					case "edge-body":
						body = "credential-canary"
					case "oversized-body":
						body = strings.Repeat("x", 4097)
					case "http-error":
						return nil, errors.New("credential-canary")
					}
					return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
				})}
			}
			checks := probeAcornFoxLocal(context.Background(), deps)
			failed := false
			for _, check := range checks {
				failed = failed || !check.OK
			}
			if !failed {
				t.Fatalf("false healthy: %+v", checks)
			}
			if strings.HasPrefix(scenario, "marker") && scenario != "marker-during-probe" && len(*visited) != 0 {
				t.Fatal("probed while upgrade state unknown")
			}
		})
	}
}

func TestAcornFoxHTTPRejectsRedirectAndIgnoresProxy(t *testing.T) {
	reached := 0
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached++; w.WriteHeader(200) }))
	defer sink.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, sink.URL, 302) }))
	defer redirect.Close()
	t.Setenv("HTTP_PROXY", sink.URL)
	t.Setenv("HTTPS_PROXY", sink.URL)
	client := acornFoxHealthHTTPClient()
	defer client.CloseIdleConnections()
	if client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("ambient proxy enabled")
	}
	if acornFoxHTTPHealthy(context.Background(), client, redirect.URL, false) || reached != 0 {
		t.Fatal("followed health redirect")
	}
}

func TestAcornFoxBoundedSystemdOutput(t *testing.T) {
	var output acornFoxBoundedOutput
	if _, err := io.Copy(&output, strings.NewReader(strings.Repeat("x", 4097))); err == nil || output.buffer.Len() > 4096 {
		t.Fatal("unbounded systemd output")
	}
}
