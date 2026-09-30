package runner

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ErrPullFailed marks a failure to pull an add-on's pinned image. The runner
// socket reports it as ErrorResponse code "pull_failed" (HTTP 502).
var ErrPullFailed = errors.New("runner: add-on image pull failed")

const codePullFailed = "pull_failed"

// IsPullFailed reports whether err (from Docker in-process or from Client over
// the socket) is an add-on image pull failure.
func IsPullFailed(err error) bool {
	if errors.Is(err, ErrPullFailed) {
		return true
	}
	var re *RemoteError
	return errors.As(err, &re) && re.Code == codePullFailed
}

// AddonHealthcheck is the Docker healthcheck of an add-on. It reports healthy
// only once the server accepts TCP connections on 127.0.0.1, which the images'
// temporary first-run init servers never do (PostgreSQL listens on the Unix
// socket only, MySQL starts with networking off). Secrets are read from the
// container environment, never put in argv.
type AddonHealthcheck struct {
	Test        []string
	Interval    time.Duration
	Timeout     time.Duration
	StartPeriod time.Duration // failures do not count while the first init runs
	Retries     int
}

func addonHealthcheck(cmd string) *AddonHealthcheck {
	return &AddonHealthcheck{
		Test:        []string{"CMD-SHELL", cmd},
		Interval:    3 * time.Second,
		Timeout:     5 * time.Second,
		StartPeriod: 120 * time.Second,
		Retries:     5,
	}
}

// Add-on kinds. The runner owns the fixed spec of every kind so that the
// server can never ask it to run an arbitrary image, command or mount under
// the add-on role.
const (
	AddonPostgres = "postgres"
	AddonMySQL    = "mysql"
	AddonRedis    = "redis"
)

// addonIDPrefix marks the pseudo deployment ID of an add-on container. The
// container name is ContainerName(app, "addon-<kind>") = "af-<app>-addon-<kind>".
const addonIDPrefix = "addon-"

// AddonSpec is the pinned runtime shape of one add-on kind.
type AddonSpec struct {
	Kind       string
	Image      string   // pinned official image
	Port       int      // TCP port inside the app network; never published on the host
	DataPath   string   // container path of the persisted data volume
	MemoryMB   int      // default memory limit
	CPUMilli   int      // default CPU limit
	Entrypoint []string // overrides the image entrypoint when non-nil
	Health     *AddonHealthcheck
}

// redisEntrypoint writes requirepass into a 0600 config file (printf is a
// shell builtin, so the password never appears in any process's argv, which
// every host user could read through ps) and then hands over to the image's
// own entrypoint, which fixes ownership of /data and drops to the redis user.
var redisEntrypoint = []string{
	"sh", "-c",
	`umask 077 && printf 'requirepass %s\n' "$REDIS_PASSWORD" > /tmp/acornfox-redis.conf && chown redis:redis /tmp/acornfox-redis.conf && exec docker-entrypoint.sh redis-server /tmp/acornfox-redis.conf --appendonly yes`,
}

var addonSpecs = map[string]AddonSpec{
	AddonPostgres: {Kind: AddonPostgres, Image: "postgres:16-alpine", Port: 5432, DataPath: "/var/lib/postgresql/data", MemoryMB: 512, CPUMilli: 1000,
		Health: addonHealthcheck(`pg_isready -q -h 127.0.0.1 -p 5432 -U "$POSTGRES_USER" -d "$POSTGRES_DB"`)},
	// mysqladmin ping succeeds whenever the server answers, even without
	// credentials, so no password is needed.
	AddonMySQL: {Kind: AddonMySQL, Image: "mysql:8.4", Port: 3306, DataPath: "/var/lib/mysql", MemoryMB: 512, CPUMilli: 1000,
		Health: addonHealthcheck(`mysqladmin ping --silent -h 127.0.0.1 -P 3306`)},
	AddonRedis: {Kind: AddonRedis, Image: "redis:7-alpine", Port: 6379, DataPath: "/data", MemoryMB: 256, CPUMilli: 1000, Entrypoint: redisEntrypoint,
		Health: addonHealthcheck(`REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli -h 127.0.0.1 -p 6379 ping | grep -q PONG`)},
}

// AddonSpecFor returns the pinned spec of kind.
func AddonSpecFor(kind string) (AddonSpec, bool) {
	s, ok := addonSpecs[kind]
	return s, ok
}

// AddonKinds lists the supported kinds in sorted order.
func AddonKinds() []string {
	out := make([]string, 0, len(addonSpecs))
	for k := range addonSpecs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// AddonDeploymentID is the pseudo deployment ID used for an add-on container.
func AddonDeploymentID(kind string) string { return addonIDPrefix + kind }

// AddonContainerName is the fixed container name (and in-network DNS host) of
// an add-on: af-<app>-addon-<kind>.
func AddonContainerName(app, kind string) string {
	return ContainerName(app, AddonDeploymentID(kind))
}

// AddonVolumeName is the fixed data volume of an add-on. It carries the
// app's volume prefix so the ordinary mount checks apply to it.
func AddonVolumeName(app, kind string) string {
	return VolumePrefix(app) + "addon-" + kind + "-data"
}

// addonKindFromID returns the kind encoded in an add-on pseudo deployment ID.
func addonKindFromID(id string) (string, bool) {
	kind, ok := strings.CutPrefix(id, addonIDPrefix)
	if !ok {
		return "", false
	}
	if _, known := addonSpecs[kind]; !known {
		return "", false
	}
	return kind, true
}

// validateAddonRequest checks an EnsureContainer request with Role=RoleAddon
// against the pinned spec: the kind must be known, and image, port and the
// single data mount must match exactly. It returns the spec to use.
func validateAddonRequest(req EnsureContainerRequest) (AddonSpec, error) {
	kind, ok := addonKindFromID(req.DeploymentID)
	if !ok {
		return AddonSpec{}, fmt.Errorf("unknown add-on %q", req.DeploymentID)
	}
	spec := addonSpecs[kind]
	if req.Image != spec.Image {
		return AddonSpec{}, fmt.Errorf("add-on %s must use image %s", kind, spec.Image)
	}
	if req.Port != spec.Port {
		return AddonSpec{}, fmt.Errorf("add-on %s must use port %d", kind, spec.Port)
	}
	wantVolume := AddonVolumeName(req.App, kind)
	if len(req.Mounts) != 1 || req.Mounts[0].Volume != wantVolume || req.Mounts[0].Path != spec.DataPath {
		return AddonSpec{}, fmt.Errorf("add-on %s must mount exactly %s at %s", kind, wantVolume, spec.DataPath)
	}
	return spec, nil
}

// validContainerSuffix reports whether the part of a container name after
// "af-<app>-" is a deployment ID or a known add-on pseudo ID.
func validContainerSuffix(id string) bool {
	if ValidDeploymentID(id) {
		return true
	}
	_, ok := addonKindFromID(id)
	return ok
}
