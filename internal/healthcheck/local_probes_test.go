package healthcheck

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/install"
)

type snapshotSource func(context.Context) (install.ServiceSnapshotV1, error)

func (f snapshotSource) Capture(ctx context.Context) (install.ServiceSnapshotV1, error) {
	return f(ctx)
}

func allUnits() install.ServiceSnapshotV1 {
	active := install.UnitSnapshotV1{Active: true, Enabled: true}
	return install.ServiceSnapshotV1{Edge: active, Agent: active, Server: active, Caddy: active, BuildKit: active}
}

func TestFiveUnitsProbeRequiresEveryActiveEnabledUnit(t *testing.T) {
	for _, unit := range []string{"edge", "agent", "server", "caddy", "buildkit"} {
		t.Run(unit, func(t *testing.T) {
			snapshot := allUnits()
			switch unit {
			case "edge":
				snapshot.Edge.Active = false
			case "agent":
				snapshot.Agent.Enabled = false
			case "server":
				snapshot.Server.Active = false
			case "caddy":
				snapshot.Caddy.Enabled = false
			case "buildkit":
				snapshot.BuildKit.Active = false
			}
			probe, err := NewFiveUnitsProbe(snapshotSource(func(context.Context) (install.ServiceSnapshotV1, error) { return snapshot, nil }))
			if err != nil {
				t.Fatal(err)
			}
			fact, err := probe.Check(context.Background())
			if err != nil || fact.Severity != SeverityEmergency || fact.Subject != "local_systemd_units" {
				t.Fatalf("fact=%+v err=%v", fact, err)
			}
		})
	}
	probe, err := NewFiveUnitsProbe(snapshotSource(func(context.Context) (install.ServiceSnapshotV1, error) { return allUnits(), nil }))
	if err != nil {
		t.Fatal(err)
	}
	fact, err := probe.Check(context.Background())
	if err != nil || fact.Severity != SeverityOK {
		t.Fatalf("fact=%+v err=%v", fact, err)
	}
}

func TestFixedHTTPProbesUseExactTargetsOrderAndRejectRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/unexpected", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var requests []string
	transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		requests = append(requests, request.URL.String())
		mu.Unlock()
		clone := request.Clone(request.Context())
		clone.URL.Scheme, clone.URL.Host = serverURL.Scheme, serverURL.Host
		return http.DefaultTransport.RoundTrip(clone)
	})
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	fact, err := NewControlAPIProbe(client).Check(context.Background())
	if err != nil || fact.Severity != SeverityOK {
		t.Fatalf("fact=%+v err=%v", fact, err)
	}
	mu.Lock()
	got := append([]string(nil), requests...)
	mu.Unlock()
	want := []string{controlAPIHealthURL, controlAPIReadyURL}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests=%v want=%v", got, want)
	}

	var redirectRequests int
	redirectClient := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		redirectRequests++
		clone := request.Clone(request.Context())
		clone.URL.Scheme, clone.URL.Host, clone.URL.Path = serverURL.Scheme, serverURL.Host, "/redirect"
		return http.DefaultTransport.RoundTrip(clone)
	})}
	fact, err = NewEdgeProbe(redirectClient).Check(context.Background())
	if err != nil || fact.Severity != SeverityEmergency || redirectRequests != 1 {
		t.Fatalf("redirect fact=%+v err=%v", fact, err)
	}
}

func TestFixedHTTPProbesTreatTimeoutAndNon200AsUnhealthy(t *testing.T) {
	nonOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer nonOK.Close()
	target, err := url.Parse(nonOK.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := rewriteClient(target)
	fact, err := NewEdgeProbe(client).Check(context.Background())
	if err != nil || fact.Severity != SeverityEmergency {
		t.Fatalf("non-200 fact=%+v err=%v", fact, err)
	}

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()
	slowTarget, err := url.Parse(slow.URL)
	if err != nil {
		t.Fatal(err)
	}
	client = rewriteClient(slowTarget)
	client.Timeout = time.Millisecond
	fact, err = NewEdgeProbe(client).Check(context.Background())
	if err != nil || fact.Severity != SeverityEmergency {
		t.Fatalf("timeout fact=%+v err=%v", fact, err)
	}
}

func TestDiskAndInodeThresholdsInvalidAndOverflowSafe(t *testing.T) {
	for _, tc := range []struct {
		percent int
		want    Severity
	}{{69, SeverityOK}, {70, SeverityWarning}, {84, SeverityWarning}, {85, SeverityCritical}, {94, SeverityCritical}, {95, SeverityEmergency}} {
		t.Run("percent", func(t *testing.T) {
			usage := FilesystemUsage{Blocks: 100, FreeBlocks: uint64(100 - tc.percent), Files: 100, FreeFiles: uint64(100 - tc.percent)}
			statfs := func(context.Context, string) (FilesystemUsage, error) { return usage, nil }
			disk, _ := NewDiskProbe(statfs)
			inode, _ := NewInodeProbe(statfs)
			for _, probe := range []HostProbe{disk, inode} {
				fact, err := probe.Check(context.Background())
				if err != nil || fact.Severity != tc.want {
					t.Fatalf("probe=%s fact=%+v err=%v", probe.Kind, fact, err)
				}
			}
		})
	}
	for _, usage := range []FilesystemUsage{{}, {Blocks: 1, FreeBlocks: 2, Files: 1, FreeFiles: 2}} {
		statfs := func(context.Context, string) (FilesystemUsage, error) { return usage, nil }
		disk, _ := NewDiskProbe(statfs)
		inode, _ := NewInodeProbe(statfs)
		for _, probe := range []HostProbe{disk, inode} {
			fact, err := probe.Check(context.Background())
			if err != nil || fact.Severity != SeverityEmergency {
				t.Fatalf("invalid %s fact=%+v err=%v", probe.Kind, fact, err)
			}
		}
	}
	percent, ok := usedPercent(math.MaxUint64, 0)
	if !ok || percent != 100 {
		t.Fatalf("overflow percent=%d ok=%t", percent, ok)
	}
	if _, ok := usedPercent(0, 0); ok {
		t.Fatal("zero capacity accepted")
	}
}

func TestLocalProbesRedactFailuresAndHonorCancellation(t *testing.T) {
	secret := "https://token:secret@example.invalid/healthz"
	probe, err := NewFiveUnitsProbe(snapshotSource(func(context.Context) (install.ServiceSnapshotV1, error) {
		return install.ServiceSnapshotV1{}, errors.New(secret)
	}))
	if err != nil {
		t.Fatal(err)
	}
	fact, err := probe.Check(context.Background())
	if err != nil || fact.Severity != SeverityEmergency || strings.Contains(fact.Subject, secret) {
		t.Fatalf("fact=%+v err=%v", fact, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fact, err = NewEdgeProbe(nil).Check(ctx)
	if err == nil || fact.Severity != SeverityEmergency || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("cancel fact=%+v err=%v", fact, err)
	}
	statfs := func(ctx context.Context, root string) (FilesystemUsage, error) {
		if root != openCardDataRoot {
			t.Fatalf("root=%q", root)
		}
		return FilesystemUsage{}, nil
	}
	disk, _ := NewDiskProbe(statfs)
	fact, err = disk.Check(ctx)
	if err == nil || fact.Severity != SeverityEmergency {
		t.Fatalf("cancel disk fact=%+v err=%v", fact, err)
	}
	statfs = func(context.Context, string) (FilesystemUsage, error) {
		return FilesystemUsage{}, errors.New(secret)
	}
	disk, _ = NewDiskProbe(statfs)
	fact, err = disk.Check(context.Background())
	if err != nil || fact.Severity != SeverityEmergency || strings.Contains(fact.Subject, secret) {
		t.Fatalf("statfs fact=%+v err=%v", fact, err)
	}
}

func TestTaskLocalProbesRequireAllInjectedDependencies(t *testing.T) {
	source := snapshotSource(func(context.Context) (install.ServiceSnapshotV1, error) { return allUnits(), nil })
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("not called") })}
	statfs := func(context.Context, string) (FilesystemUsage, error) {
		return FilesystemUsage{Blocks: 1, Files: 1}, nil
	}
	for _, inputs := range []struct {
		source ServiceSnapshotSource
		client *http.Client
		statfs StatFS
	}{{nil, client, statfs}, {source, nil, statfs}, {source, client, nil}} {
		if _, err := NewTaskLocalProbes(inputs.source, inputs.client, inputs.statfs); err == nil {
			t.Fatal("task probes accepted a missing dependency")
		}
	}
	if _, err := NewDiskProbe(nil); err == nil {
		t.Fatal("disk probe accepted a missing statfs dependency")
	}
	if _, err := NewInodeProbe(nil); err == nil {
		t.Fatal("inode probe accepted a missing statfs dependency")
	}
}

func TestOperationalProbeFailuresPersistEmergencyIncident(t *testing.T) {
	for _, failure := range []string{"service", "statfs"} {
		t.Run(failure, func(t *testing.T) {
			source := snapshotSource(func(context.Context) (install.ServiceSnapshotV1, error) {
				if failure == "service" {
					return install.ServiceSnapshotV1{}, errors.New("postgresql://secret@host/db")
				}
				return allUnits(), nil
			})
			statfs := func(context.Context, string) (FilesystemUsage, error) {
				if failure == "statfs" {
					return FilesystemUsage{}, errors.New("token=secret")
				}
				return FilesystemUsage{Blocks: 100, FreeBlocks: 100, Files: 100, FreeFiles: 100}, nil
			}
			client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
			})}
			local, err := NewTaskLocalProbes(source, client, statfs)
			if err != nil {
				t.Fatal(err)
			}
			complete := collectorProbes(nil, nil)
			for _, probe := range local {
				for index := range complete {
					if complete[index].Kind == probe.Kind {
						complete[index] = probe
					}
				}
			}
			root := t.TempDir()
			store, err := NewTaskStateStore(root)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			now := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
			collector, err := NewTaskHostCollector(complete, store, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			evaluation, err := collector.Evaluate(context.Background())
			if err != nil || !evaluation.Decision.Notify || evaluation.Decision.State.PendingNotification != "occurrence" || evaluation.Snapshot.Overall != SeverityEmergency {
				t.Fatalf("evaluation=%+v err=%v", evaluation, err)
			}
			if raw, err := os.ReadFile(filepath.Join(root, incidentStateFile)); err != nil || strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "postgresql") {
				t.Fatalf("state=%q err=%v", raw, err)
			}
		})
	}
}

func TestProductionStatFSUsesServiceAvailableBlocks(t *testing.T) {
	usage := filesystemUsageFromStat(syscall.Statfs_t{Blocks: 100, Bfree: 50, Bavail: 4, Files: 100, Ffree: 25})
	if usage.FreeBlocks != 4 || usage.FreeFiles != 25 {
		t.Fatalf("usage=%+v", usage)
	}
	percent, ok := usedPercent(usage.Blocks, usage.FreeBlocks)
	if !ok || DiskSeverity(percent) != SeverityEmergency {
		t.Fatalf("percent=%d ok=%t", percent, ok)
	}
}

func rewriteClient(target *url.URL) *http.Client {
	return &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		clone := request.Clone(request.Context())
		clone.URL.Scheme, clone.URL.Host = target.Scheme, target.Host
		return http.DefaultTransport.RoundTrip(clone)
	})}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
