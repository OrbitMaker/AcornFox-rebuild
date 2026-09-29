package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/acornfox/acornfox/internal/client"
)

func TestDomainAddPrintsICPNotice(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	if err := saveProject(h.workDir, &projectFile{Target: "dev", App: "notes"}); err != nil {
		t.Fatalf("saveProject: %v", err)
	}
	var gotName string
	h.api.addDomainFn = func(ctx context.Context, app, name string) (client.Domain, error) {
		gotName = name
		return client.Domain{App: app, Name: name, Status: "pending"}, nil
	}
	code, out, _ := h.run("domain", "add", "notes.acornfox.test")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if gotName != "notes.acornfox.test" {
		t.Fatalf("name = %q", gotName)
	}
	if !strings.Contains(out, "ICP 备案") {
		t.Fatalf("ICP notice missing: %s", out)
	}
}

func TestDomainAddDNSMismatchWarning(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	if err := saveProject(h.workDir, &projectFile{Target: "dev", App: "notes"}); err != nil {
		t.Fatalf("saveProject: %v", err)
	}
	h.api.addDomainFn = func(ctx context.Context, app, name string) (client.Domain, error) {
		return client.Domain{
			App: app, Name: name, Status: "pending",
			Warnings: []client.Diagnosis{{
				Stage: "domain", Code: "dns_mismatch",
				Message: "域名的 A 记录未指向本服务器", Hint: "更新 DNS A 记录",
			}},
		}, nil
	}
	code, out, _ := h.run("domain", "add", "x.example.com")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "ICP 备案") {
		t.Fatalf("ICP notice missing: %s", out)
	}
	if !strings.Contains(out, "A 记录未指向") {
		t.Fatalf("dns_mismatch warning missing: %s", out)
	}
}

func TestDomainAddJSONShape(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	if err := saveProject(h.workDir, &projectFile{Target: "dev", App: "notes"}); err != nil {
		t.Fatalf("saveProject: %v", err)
	}
	h.api.addDomainFn = func(ctx context.Context, app, name string) (client.Domain, error) {
		return client.Domain{App: app, Name: name, Status: "pending"}, nil
	}
	code, out, _ := h.run("--json", "domain", "add", "x.example.com")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	m := decodeJSON(t, out)
	if m["ok"] != true {
		t.Fatalf("ok != true")
	}
	d := m["domain"].(map[string]any)
	if d["name"] != "x.example.com" || d["status"] != "pending" {
		t.Fatalf("domain shape = %v", d)
	}
}

func TestDomainListJSONShape(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	if err := saveProject(h.workDir, &projectFile{Target: "dev", App: "notes"}); err != nil {
		t.Fatalf("saveProject: %v", err)
	}
	h.api.domainsFn = func(ctx context.Context, app string) ([]client.Domain, error) {
		return []client.Domain{
			{App: app, Name: "a.example.com", Status: "ready"},
			{App: app, Name: "b.example.com", Status: "pending"},
		}, nil
	}
	code, out, _ := h.run("--json", "domain", "list")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	m := decodeJSON(t, out)
	ds := m["domains"].([]any)
	if len(ds) != 2 {
		t.Fatalf("domains len = %d", len(ds))
	}
	first := ds[0].(map[string]any)
	if first["name"] != "a.example.com" || first["status"] != "ready" {
		t.Fatalf("first domain = %v", first)
	}
}

func TestDomainRemove(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	if err := saveProject(h.workDir, &projectFile{Target: "dev", App: "notes"}); err != nil {
		t.Fatalf("saveProject: %v", err)
	}
	var removed string
	h.api.removeDomainFn = func(ctx context.Context, app, name string) error {
		removed = name
		return nil
	}
	code, out, _ := h.run("--json", "domain", "remove", "a.example.com")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if removed != "a.example.com" {
		t.Fatalf("removed = %q", removed)
	}
	m := decodeJSON(t, out)
	if m["removed"] != "a.example.com" {
		t.Fatalf("removed json = %v", m["removed"])
	}
}

func TestDomainUsageErrors(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	if err := saveProject(h.workDir, &projectFile{Target: "dev", App: "notes"}); err != nil {
		t.Fatalf("saveProject: %v", err)
	}
	if code, _, _ := h.run("domain"); code != exitUsage {
		t.Fatalf("no subcommand exit = %d", code)
	}
	if code, _, _ := h.run("domain", "bogus"); code != exitUsage {
		t.Fatalf("bad subcommand exit = %d", code)
	}
}

// TestStatusShowsDomains: `status` includes domains in JSON and human output.
func TestStatusShowsDomains(t *testing.T) {
	h := newHarness(t)
	h.addTarget("dev", "http://dev")
	if err := saveProject(h.workDir, &projectFile{Target: "dev", App: "notes"}); err != nil {
		t.Fatalf("saveProject: %v", err)
	}
	h.api.appFn = func(ctx context.Context, app string) (client.App, error) {
		return client.App{Name: app, Domains: []client.Domain{
			{Name: "a.example.com", Status: "ready"},
		}}, nil
	}
	code, out, _ := h.run("--json", "status")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	m := decodeJSON(t, out)
	ds, ok := m["domains"].([]any)
	if !ok || len(ds) != 1 {
		t.Fatalf("domains = %v", m["domains"])
	}
}
