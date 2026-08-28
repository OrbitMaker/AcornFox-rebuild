package contracts

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

func resolvedService(name string) ServiceRuntimeSpec {
	return ServiceRuntimeSpec{
		Name: name, Role: domain.RoleWorker, Required: true,
		Image:     domain.ImageDigest{Repository: "registry.example.test/open-card/" + name, Digest: "sha256:" + strings.Repeat("a", 64)},
		Resources: ResourceLimits{CPUMillis: 250, MemoryBytes: 64 << 20, DiskBytes: 128 << 20, PIDs: 64},
	}
}

func TestServiceGroupRuntimeSpecRequiresExactReleaseDigestSet(t *testing.T) {
	web, worker := resolvedService("web"), resolvedService("worker")
	web.Role = domain.RoleIngress
	web.ContainerPorts = []int{8080}
	group := resolvedGroup(web, worker)
	release, err := domain.NewRelease(group.ApplicationID, group.ServiceGroupID, 1, "sha256:"+strings.Repeat("c", 64), map[string]domain.ImageDigest{"web": web.Image, "worker": worker.Image}, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	group.ReleaseID = release.ID
	if err := group.ValidateRelease(*release); err != nil {
		t.Fatal(err)
	}
	group.ConfigDigest = "sha256:" + strings.Repeat("e", 64)
	if err := group.ValidateRelease(*release); err == nil {
		t.Fatal("release config digest mismatch was accepted")
	}
	group.ConfigDigest = release.ConfigDigest
	missing, err := domain.NewRelease(group.ApplicationID, group.ServiceGroupID, 2, "sha256:"+strings.Repeat("d", 64), map[string]domain.ImageDigest{"web": web.Image}, time.Unix(101, 0))
	if err != nil {
		t.Fatal(err)
	}
	group.ReleaseID = missing.ID
	if err := group.ValidateRelease(*missing); err == nil {
		t.Fatal("partial release digest set was accepted")
	}
}

func resolvedGroup(services ...ServiceRuntimeSpec) ServiceGroupRuntimeSpec {
	services = append([]ServiceRuntimeSpec(nil), services...)
	if len(services) > 0 {
		services[0].Role = domain.RoleIngress
		if len(services[0].ContainerPorts) == 0 {
			services[0].ContainerPorts = []int{8080}
		}
	}
	return ServiceGroupRuntimeSpec{
		SchemaVersion: ServiceGroupRuntimeSchema, ApplicationID: domain.ID("app_group"), EnvironmentID: domain.ID("env_group"), ReleaseID: domain.ID("rel_group"), ServiceGroupID: domain.ID("group_group"),
		ConfigDigest: "sha256:" + strings.Repeat("c", 64), EntryService: services[0].Name, Services: services, Rollout: RuntimeRolloutPolicy{Mode: RuntimeRolloutInitial},
	}
}

func TestServiceGroupRuntimeSpecRequiresResolvedBoundedServices(t *testing.T) {
	web := resolvedService("web")
	web.Role = domain.RoleIngress
	web.ContainerPorts = []int{8080}
	db := resolvedService("db")
	db.Role = domain.RoleStateful
	db.Healthcheck = &domain.HealthcheckSpec{Test: []string{"CMD", "true"}}
	web.Dependencies = []domain.ServiceDependency{{Service: "db", Condition: domain.DependsHealthy}}
	web.Volumes = []domain.VolumeMount{{Name: "data", MountPath: "/data"}}
	db.Volumes = []domain.VolumeMount{{Name: "data", MountPath: "/var/lib/data"}}
	group := resolvedGroup(web, db)
	group.EntryService = "web"
	group.VolumeClaims = []RuntimeVolumeClaim{{ID: domain.ID("volume_data"), Name: "data", SizeBytes: 32 << 20, Retain: true}}
	if err := group.Validate(); err != nil {
		t.Fatal(err)
	}
	order, err := group.DependencyOrder()
	if err != nil || strings.Join(order, ",") != "db,web" {
		t.Fatalf("unexpected dependency order: %v %v", order, err)
	}
	total, err := group.AggregateResources()
	if err != nil || total.CPUMillis != 500 || total.MemoryBytes != 128<<20 || total.DiskBytes != 288<<20 || total.PIDs != 128 {
		t.Fatalf("unexpected aggregate: %#v %v", total, err)
	}

	unsafe := web
	unsafe.Volumes = []domain.VolumeMount{{Name: "data", MountPath: "/var/run/docker.sock"}}
	unsafeGroup := resolvedGroup(unsafe)
	unsafeGroup.VolumeClaims = []RuntimeVolumeClaim{{ID: domain.ID("volume_data"), Name: "data", SizeBytes: 1, Retain: true}}
	if err := unsafeGroup.Validate(); err == nil {
		t.Fatal("Docker socket mount target was accepted")
	}
	unresolved := web
	unresolved.Image = domain.ImageDigest{Repository: "registry.example.test/open-card/web", Digest: "latest"}
	if err := resolvedGroup(unresolved).Validate(); err == nil {
		t.Fatal("mutable image reference was accepted")
	}
}

func TestServiceGroupRuntimeSpecRequiresDependencyConditionFacts(t *testing.T) {
	web, db := resolvedService("web"), resolvedService("db")
	web.Dependencies = []domain.ServiceDependency{{Service: "db", Condition: domain.DependsHealthy}}
	if err := resolvedGroup(web, db).Validate(); err == nil {
		t.Fatal("healthy dependency without target healthcheck was accepted")
	}
	db.Healthcheck = &domain.HealthcheckSpec{Disabled: true}
	if err := resolvedGroup(web, db).Validate(); err == nil {
		t.Fatal("healthy dependency with disabled target healthcheck was accepted")
	}
	db.Healthcheck = nil
	web.Dependencies[0].Condition = domain.DependsCompleted
	if err := resolvedGroup(web, db).Validate(); err == nil {
		t.Fatal("completed dependency on a long-running target was accepted")
	}
	db.Role = domain.RoleOneShot
	if err := resolvedGroup(web, db).Validate(); err != nil {
		t.Fatalf("completed dependency on one-shot target was rejected: %v", err)
	}
}

func TestServiceGroupRuntimeSpecUsesTaggedEnvironmentAndExplicitRollout(t *testing.T) {
	service := resolvedService("worker")
	service.Environment = []RuntimeEnvironmentVariable{
		{Name: "APP_MODE", Kind: RuntimeEnvironmentLiteral, Value: "production"},
		{Name: "DATABASE_PASSWORD", Kind: RuntimeEnvironmentSecret, SecretRef: &domain.SecretReference{ID: domain.ID("secret_database"), Name: "database", Provider: "filesystem-secret", Version: "v1"}},
	}
	if err := resolvedGroup(service).Validate(); err != nil {
		t.Fatal(err)
	}
	invalid := service
	invalid.Environment = []RuntimeEnvironmentVariable{{Name: "DATABASE_PASSWORD", Kind: RuntimeEnvironmentSecret, Value: "plaintext"}}
	if err := resolvedGroup(invalid).Validate(); err == nil {
		t.Fatal("plaintext secret environment value was accepted")
	}
	invalid = service
	invalid.Environment = []RuntimeEnvironmentVariable{{Name: "DATABASE_PASSWORD", Kind: RuntimeEnvironmentLiteral, Value: "bare-runtime-canary"}}
	if err := resolvedGroup(invalid).Validate(); err == nil {
		t.Fatal("sensitive literal runtime environment bypassed SecretReference")
	}
	rolling := resolvedGroup(service)
	rolling.Rollout = RuntimeRolloutPolicy{Mode: RuntimeRolloutRolling, PreviousDeploymentID: domain.ID("dep_previous"), PreserveOldUntilHealthy: true}
	if err := rolling.Validate(); err != nil {
		t.Fatal(err)
	}
	rolling.Rollout.PreserveOldUntilHealthy = false
	if err := rolling.Validate(); err == nil {
		t.Fatal("rolling rollout without old deployment preservation was accepted")
	}
}

func TestServiceGroupRuntimeSpecStrictJSONRoundTripRejectsUnknownFields(t *testing.T) {
	service := resolvedService("web")
	group := resolvedGroup(service)
	encoded, err := json.Marshal(group)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeServiceGroupRuntimeSpec(encoded)
	if err != nil || decoded.EntryService != group.EntryService {
		t.Fatalf("strict round trip failed: %#v %v", decoded, err)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	object["host_path"] = "/var/run/docker.sock"
	unknown, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeServiceGroupRuntimeSpec(unknown); err == nil {
		t.Fatal("unknown runtime field was accepted")
	}
}

func TestServiceGroupRuntimeObservationEnforcesCompleteEntryOnlyFacts(t *testing.T) {
	web, worker := resolvedService("web"), resolvedService("worker")
	web.Role, web.ContainerPorts = domain.RoleIngress, []int{8080}
	worker.Required = false
	spec := resolvedGroup(web, worker)
	spec.EntryService = "web"
	observation := ServiceGroupRuntimeObservation{
		DeploymentID: "dep_observed", ReleaseID: spec.ReleaseID, Status: "degraded", Effect: RuntimeEffectKnown,
		Services: []RuntimeObservation{
			{DeploymentID: "dep_observed", ServiceName: "web", Status: "healthy", Healthy: true, HostPort: 38080, Limits: web.Resources},
			{DeploymentID: "dep_observed", ServiceName: "worker", Status: "failed", Healthy: false, Limits: worker.Resources},
		},
	}
	if err := observation.ValidateFor(spec); err != nil {
		t.Fatal(err)
	}
	observation.Services[1].HostPort = 38081
	if err := observation.ValidateFor(spec); err == nil {
		t.Fatal("non-entry service host port was accepted")
	}
	observation.Services[1].HostPort = 0
	observation.Status = "runtime_ready"
	if err := observation.ValidateFor(spec); err == nil {
		t.Fatal("optional failure without degraded status was accepted")
	}
}

func TestCanonicalServiceGroupReleaseDigestCoversExecutableIdentity(t *testing.T) {
	web, worker := resolvedService("web"), resolvedService("worker")
	web.Role, web.ContainerPorts = domain.RoleIngress, []int{8080}
	web.Command = []string{"serve", "--port", "8080"}
	worker.Environment = []RuntimeEnvironmentVariable{{Name: "QUEUE", Kind: RuntimeEnvironmentLiteral, Value: "jobs"}}
	spec := resolvedGroup(web, worker)
	spec.EntryService = "web"
	first, err := CanonicalServiceGroupReleaseDigest("def_group", 1, spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Services[0], spec.Services[1] = spec.Services[1], spec.Services[0]
	second, err := CanonicalServiceGroupReleaseDigest("def_group", 1, spec)
	if err != nil || second != first {
		t.Fatalf("declaration order changed canonical digest: %s %s %v", first, second, err)
	}
	for index := range spec.Services {
		if spec.Services[index].Name == "web" {
			spec.Services[index].Command[2] = "8081"
		}
	}
	changed, err := CanonicalServiceGroupReleaseDigest("def_group", 1, spec)
	if err != nil || changed == first {
		t.Fatalf("executable command change did not change canonical digest: %s %v", changed, err)
	}
}

func TestServiceGroupRuntimeSpecRejectsCyclesAndResourceOverflow(t *testing.T) {
	a, b := resolvedService("a"), resolvedService("b")
	a.Dependencies = []domain.ServiceDependency{{Service: "b", Condition: domain.DependsStarted}}
	b.Dependencies = []domain.ServiceDependency{{Service: "a", Condition: domain.DependsStarted}}
	if err := resolvedGroup(a, b).Validate(); err == nil {
		t.Fatal("dependency cycle was accepted")
	} else if !strings.Contains(err.Error(), "a -> b -> a") {
		t.Fatalf("cycle path was not deterministic: %v", err)
	}
	a.Dependencies = nil
	a.Resources.CPUMillis = math.MaxInt64
	b.Dependencies = nil
	b.Resources.CPUMillis = 1
	if _, err := resolvedGroup(a, b).AggregateResources(); err == nil {
		t.Fatal("resource overflow was accepted")
	}
}
