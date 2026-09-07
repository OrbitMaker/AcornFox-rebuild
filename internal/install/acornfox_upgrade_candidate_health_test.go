package install

import (
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type acornFoxCandidateProcessFake struct {
	once    sync.Once
	done    chan struct{}
	signals []os.Signal
	waitErr error
}

func (p *acornFoxCandidateProcessFake) Signal(signal os.Signal) error {
	p.signals = append(p.signals, signal)
	p.once.Do(func() { close(p.done) })
	return nil
}

func (p *acornFoxCandidateProcessFake) Wait() error {
	<-p.done
	return p.waitErr
}

func TestAcornFoxCandidateHealthUsesClosedCleanEnvironmentAndReaps(t *testing.T) {
	process := &acornFoxCandidateProcessFake{done: make(chan struct{})}
	var path, serverPath string
	var args, environment []string
	var probes []string
	validator := acornFoxCandidateHealthValidator{
		start: func(_ context.Context, gotPath string, gotArgs, gotEnvironment []string, listener *os.File) (candidateServerProcess, error) {
			if listener == nil {
				t.Fatal("candidate listener was not inherited")
			}
			path, args, environment = gotPath, append([]string(nil), gotArgs...), append([]string(nil), gotEnvironment...)
			serverPath = gotArgs[4]
			return process, nil
		},
		probe: func(_ context.Context, target string) error {
			probes = append(probes, target)
			return nil
		},
		probeTimeout:       time.Second,
		terminationTimeout: time.Second,
	}
	principal := acornFoxInstallPrincipal{uid: 2001, gid: 2002}
	dsn := "postgresql://acornfox:redacted@127.0.0.1:5432/acornfox_upg_0123456789abcdef0123?sslmode=disable"
	if err := validator.validate(context.Background(), "/opt/acornfox/releases/release-1.2.4/bin/acornfox-server", dsn, principal); err != nil {
		t.Fatal(err)
	}
	wantArgs := []string{"--reuid=2001", "--regid=2002", "--clear-groups", "--", serverPath, "--candidate-validate"}
	if path != acornFoxCandidatePrivilegeDropPath || !reflect.DeepEqual(args, wantArgs) || !reflect.DeepEqual(process.signals, []os.Signal{syscall.SIGTERM}) {
		t.Fatalf("path=%q args=%q signals=%v", path, args, process.signals)
	}
	if len(probes) != 2 || !strings.HasSuffix(probes[0], "/healthz") || !strings.HasSuffix(probes[1], "/readyz") {
		t.Fatalf("probes=%q", probes)
	}
	want := map[string]string{
		"ACORNFOX_RUNTIME_MODE":        "clean",
		"ACORNFOX_DATABASE_URL":        dsn,
		"ACORNFOX_CANDIDATE_LISTEN_FD": "3",
		"ACORNFOX_M1_ENABLED":          "false",
		"ACORNFOX_M6_ENABLED":          "false",
	}
	for name, value := range want {
		got, ok := acornFoxCandidateEnvironmentValue(environment, name)
		if !ok || got != value {
			t.Fatalf("%s=%q present=%t", name, got, ok)
		}
	}
	for _, forbidden := range []string{"OPEN_CARD_DATABASE_URL", "ACORNFOX_AUTH_ORIGIN", "ACORNFOX_AGENT_GATEWAY_ADDR", "ACORNFOX_ASSISTANT_ENABLED"} {
		if _, ok := acornFoxCandidateEnvironmentValue(environment, forbidden); ok {
			t.Fatalf("forbidden environment %s present", forbidden)
		}
	}
}

func TestAcornFoxCandidateHealthFailsClosedAndReaps(t *testing.T) {
	t.Run("probe-failure", func(t *testing.T) {
		process := &acornFoxCandidateProcessFake{done: make(chan struct{})}
		validator := acornFoxCandidateHealthValidator{
			start: func(context.Context, string, []string, []string, *os.File) (candidateServerProcess, error) {
				return process, nil
			},
			probe:        func(context.Context, string) error { return errors.New("not ready") },
			probeTimeout: 20 * time.Millisecond, terminationTimeout: time.Second,
		}
		err := validator.validate(context.Background(), "/opt/acornfox/releases/release-1.2.4/bin/acornfox-server", "postgresql://x/y", acornFoxInstallPrincipal{uid: 1, gid: 1})
		if !errors.Is(err, ErrAcornFoxUpgradeUnknown) || !reflect.DeepEqual(process.signals, []os.Signal{syscall.SIGTERM}) {
			t.Fatalf("err=%v signals=%v", err, process.signals)
		}
	})
	t.Run("invalid-input-has-no-process", func(t *testing.T) {
		started := false
		validator := acornFoxCandidateHealthValidator{start: func(context.Context, string, []string, []string, *os.File) (candidateServerProcess, error) {
			started = true
			return nil, nil
		}}
		if err := validator.validate(context.Background(), "relative/server", "postgresql://x/y", acornFoxInstallPrincipal{uid: 1, gid: 1}); !errors.Is(err, ErrAcornFoxUpgradeUnknown) || started {
			t.Fatalf("err=%v started=%t", err, started)
		}
	})
}

func TestAcornFoxCandidateEnvironmentHasNoDuplicateKeys(t *testing.T) {
	seen := map[string]bool{}
	for _, entry := range acornFoxCandidateEnvironment("postgresql://x/y", net.JoinHostPort("127.0.0.1", "1234")) {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || name == "" || seen[name] {
			t.Fatalf("invalid environment entry %q", entry)
		}
		seen[name] = true
	}
}
