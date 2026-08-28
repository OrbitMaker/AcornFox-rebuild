package compose

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

func TestSCHEMA_COMP_001_ImportMapsSupportedSubsetAndReportsDeterministically(t *testing.T) {
	const digest = "sha256:" + "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	input := []byte(`{
      "version": " 3.9 ",
      "volumes": {"data": {}},
      "networks": {"private": {"internal": true}},
      "services": {
        "web": {
          "build": {"context": " ./ ", "dockerfile": " ./deploy/Dockerfile "},
          "command": ["server", "--listen", ":8080"],
          "entrypoint": ["/bin/app"],
          "environment": {" APP_ENV ": "test"},
          "ports": [{"target": 8080, "protocol": " TCP "}],
          "volumes": [{"source": "data", "target": "/var/lib/app", "read_only": true}],
          "depends_on": {"db": {"condition": " SERVICE_HEALTHY "}},
          "healthcheck": {"test": ["CMD", "wget", "-qO-", "http://localhost:8080/health"], "interval": "5s", "timeout": "2s", "retries": 3},
          "restart": "always",
          "networks": ["private"],
          "deploy": {"resources": {"limits": {"cpus": "500M", "memory": "64MiB"}}}
        },
        "db": {
          "image": "postgres@` + digest + `",
          "volumes": [{"source": "data", "target": "/var/lib/postgresql/data"}],
          "networks": ["private"],
          "restart": "unless-stopped",
          "environment": {"POSTGRES_DB": "app"}
        }
      }
    }`)

	result, err := ImportJSON(input, Options{ApplicationID: domain.ID("app-import"), Name: "compose-test", Now: time.Unix(100, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Report.Accepted || result.Report.CanonicalDigest == "" || len(result.Canonical) == 0 {
		t.Fatalf("missing accepted import evidence: %#v", result.Report)
	}
	if got := result.ServiceGroup.Services[0].Name; got != "db" {
		t.Fatalf("services must be sorted by name, got %q", got)
	}
	if got := result.ServiceGroup.Services[1]; got.Role != domain.RoleIngress || got.Port != 8080 || got.Resources.CPUMillis != 500 || got.Resources.MemoryBytes != 64*1024*1024 {
		t.Fatalf("supported fields did not map to controlled service: %#v", got)
	}
	if got, want := result.Report.DependencyOrder, []string{"db", "web"}; !equalStrings(got, want) {
		t.Fatalf("dependency order=%v, want %v", got, want)
	}
	for _, field := range []string{
		"version",
		"networks.private.internal",
		"volumes.data",
		"services.db.image",
		"services.web.build.context",
		"services.web.build.dockerfile",
		"services.web.command",
		"services.web.depends_on",
		"services.web.deploy.resources",
		"services.web.environment",
		"services.web.healthcheck",
		"services.web.networks",
		"services.web.ports",
		"services.web.restart",
		"services.web.volumes",
	} {
		if !contains(result.Report.MappedFields, field) {
			t.Errorf("mapping report missing %q: %#v", field, result.Report.MappedFields)
		}
	}
	if len(result.Report.RejectedFields) != 0 {
		t.Fatalf("accepted import contains rejected fields: %#v", result.Report.RejectedFields)
	}
	if err := result.ServiceGroup.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSCHEMA_COMP_002_UnknownAndDuplicateFieldsFailClosedWithPath(t *testing.T) {
	unknown := []byte(`{"services":{"web":{"image":"nginx:stable","mystery":true}}}`)
	result, err := ImportJSON(unknown, Options{ApplicationID: domain.ID("app-import")})
	if err == nil {
		t.Fatal("unknown field must be rejected")
	}
	if !contains(result.Report.RejectedFields, "services.web.mystery") {
		t.Fatalf("unknown field path missing from report: %#v (%v)", result.Report, err)
	}
	if result.Report.Accepted || !domain.IsCode(err, domain.ErrValidation) {
		t.Fatalf("unknown field did not fail as validation: report=%#v err=%v", result.Report, err)
	}

	duplicate := []byte(`{"services":{"web":{"image":"nginx:stable","image":"nginx:latest"}}}`)
	result, err = ImportJSON(duplicate, Options{ApplicationID: domain.ID("app-import")})
	if err == nil || !contains(result.Report.RejectedFields, "services.web.image") {
		t.Fatalf("duplicate field must be rejected with path: report=%#v err=%v", result.Report, err)
	}
}

func TestSEC_COMP_001_DangerousFieldsAreExplicitlyRejected(t *testing.T) {
	booleanFalse := false
	cases := map[string]domain.ComposeFile{
		"host namespace": {Services: map[string]domain.ComposeService{
			"web": {Image: "nginx:stable", NetworkMode: stringPtr("host")},
		}},
		"host UTS namespace": {Services: map[string]domain.ComposeService{
			"web": {Image: "nginx:stable", UTS: stringPtr("host")},
		}},
		"privileged false still explicit": {Services: map[string]domain.ComposeService{
			"web": {Image: "nginx:stable", Privileged: &booleanFalse},
		}},
		"host bind": {Services: map[string]domain.ComposeService{
			"web": {Image: "nginx:stable", Volumes: []domain.ComposeVolumeMount{{Source: "/var/run/docker.sock", Target: "/var/run/docker.sock", Type: "bind"}}},
		}},
		"published port": {Services: map[string]domain.ComposeService{
			"web": {Image: "nginx:stable", Ports: []domain.ComposePort{{Target: 8080, Published: 8080}}},
		}},
		"external network": {Networks: map[string]domain.ComposeNetwork{"public": {}}, Services: map[string]domain.ComposeService{
			"web": {Image: "nginx:stable", Networks: []string{"public"}},
		}},
		"build traversal": {Services: map[string]domain.ComposeService{
			"web": {Build: &domain.ComposeBuild{Context: "src/../secrets", Dockerfile: "Dockerfile"}},
		}},
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			result, err := ImportDocument(document, Options{ApplicationID: domain.ID("app-import")})
			if err == nil {
				t.Fatal("dangerous Compose input must fail closed")
			}
			if result.Report.Accepted || len(result.Report.RejectedFields) == 0 {
				t.Fatalf("missing fail-closed report: %#v", result.Report)
			}
			if !domain.IsCode(err, domain.ErrValidation) {
				t.Fatalf("expected validation error, got %v", err)
			}
		})
	}
}

func TestUNIT_DAG_001_And_002_DeterministicOrderAndCycleRejection(t *testing.T) {
	document := domain.ComposeFile{Services: map[string]domain.ComposeService{
		"z": {Image: "z:stable", DependsOn: map[string]domain.ComposeDependency{"a": {Condition: "started"}}},
		"a": {Image: "a:stable"},
		"m": {Image: "m:stable", DependsOn: map[string]domain.ComposeDependency{"a": {Condition: "healthy"}}},
	}}
	first, err := ImportDocument(document, Options{ApplicationID: domain.ID("app-import")})
	if err != nil {
		t.Fatal(err)
	}
	document.Services["a"] = domain.ComposeService{Image: "a:stable", DependsOn: map[string]domain.ComposeDependency{"z": {Condition: "completed"}}}
	cycle, err := ImportDocument(document, Options{ApplicationID: domain.ID("app-import")})
	if err == nil || !contains(cycle.Report.RejectedFields, "dependency_graph") {
		t.Fatalf("cycle must be rejected explicitly: report=%#v err=%v", cycle.Report, err)
	}
	if !contains(first.Report.DependencyOrder, "a") {
		t.Fatalf("valid dependency order missing root: %#v", first.Report.DependencyOrder)
	}
}

func TestDeterministicNormalizationProducesSameCanonicalBytesForMapAndFormattingOrder(t *testing.T) {
	left := []byte(`{"services":{"web":{"image":" nginx:stable ","networks":["private"],"depends_on":{"db":{"condition":"SERVICE_STARTED"}}},"db":{"image":" postgres:stable "}},"networks":{"private":{"internal":true}}}`)
	right := []byte(`{ "networks": { "private": { "internal": true } }, "services": { "db": { "image": "postgres:stable" }, "web": { "depends_on": { "db": { "condition": " service_started " } }, "networks": [ "private" ], "image": "nginx:stable" } } }`)
	leftResult, err := ImportJSON(left, Options{ApplicationID: domain.ID("app-import")})
	if err != nil {
		t.Fatal(err)
	}
	rightResult, err := ImportJSON(right, Options{ApplicationID: domain.ID("app-import")})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leftResult.Canonical, rightResult.Canonical) || leftResult.Report.CanonicalDigest != rightResult.Report.CanonicalDigest {
		t.Fatalf("canonical normalization drifted:\nleft=%s\nright=%s", leftResult.Canonical, rightResult.Canonical)
	}
	if !equalStrings(leftResult.Report.MappedFields, rightResult.Report.MappedFields) {
		t.Fatalf("mapping order/content drifted: left=%v right=%v", leftResult.Report.MappedFields, rightResult.Report.MappedFields)
	}
}

func TestImportDoesNotMutateTrustedDocument(t *testing.T) {
	document := domain.ComposeFile{Services: map[string]domain.ComposeService{
		" web ": {
			Image: " nginx:stable ",
			Ports: []domain.ComposePort{{Target: 8080, Protocol: " TCP "}},
		},
	}}
	before, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportDocument(document, Options{ApplicationID: domain.ID("app-import")}); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("trusted document was mutated: before=%s after=%s", before, after)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func stringPtr(value string) *string { return &value }
