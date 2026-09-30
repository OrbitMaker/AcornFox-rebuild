package runner

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func observationDocker(t *testing.T, handler http.HandlerFunc) *Docker {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	cli, err := client.New(client.WithHost(srv.URL), client.WithVersion("1.56"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return NewDocker(cli)
}

func TestObservationsRejectUnownedContainersBeforeOperation(t *testing.T) {
	name := ContainerName("shop", "0123456789ab")
	for _, labels := range []map[string]string{nil, {LabelManaged: "1", LabelApp: "other"}, {LabelApp: "shop"}} {
		var operations atomic.Int32
		d := observationDocker(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/json") {
				_ = json.NewEncoder(w).Encode(container.InspectResponse{ID: "actual-id", Name: "/" + name, Config: &container.Config{Labels: labels}, State: &container.State{Running: true}})
				return
			}
			operations.Add(1)
			w.WriteHeader(500)
		})
		calls := []func() error{
			func() error { return d.StopContainer(context.Background(), "shop", name) },
			func() error { _, err := d.StartContainer(context.Background(), "shop", name); return err },
			func() error { return d.RemoveContainer(context.Background(), "shop", name) },
			func() error { _, err := d.Logs(context.Background(), "shop", name, 100); return err },
			func() error { _, err := d.ContainerStats(context.Background(), "shop", name); return err },
			func() error { _, err := d.Diff(context.Background(), "shop", name); return err },
		}
		for _, call := range calls {
			var remote *RemoteError
			if err := call(); !errors.As(err, &remote) || remote.Code != "refused" {
				t.Fatalf("expected refused, got %v", err)
			}
		}
		if operations.Load() != 0 {
			t.Fatal("an unowned container was operated on")
		}
	}
}

func TestObservationsMissingStopAndRemoveAreIdempotent(t *testing.T) {
	d := observationDocker(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"message":"No such container"}`))
	})
	name := ContainerName("shop", "0123456789ab")
	if err := d.StopContainer(context.Background(), "shop", name); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveContainer(context.Background(), "shop", name); err != nil {
		t.Fatal(err)
	}
}

func TestObservationsLogFramesReassembleFragmentsAndTailBoundary(t *testing.T) {
	name := ContainerName("shop", "0123456789ab")
	var raw bytes.Buffer
	writeFrame := func(data []byte) {
		var header [8]byte
		header[0] = 1
		binary.BigEndian.PutUint32(header[4:], uint32(len(data)))
		raw.Write(header[:])
		raw.Write(data)
	}
	stamp := "2026-09-30T10:00:00.123456789Z "
	writeFrame([]byte(stamp + "prefix-password"))
	writeFrame([]byte("-suffix\n" + stamp + "same\n" + stamp + "same\n"))
	d := observationDocker(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/json") {
			_ = json.NewEncoder(w).Encode(container.InspectResponse{ID: "actual-id", Name: "/" + name, Config: &container.Config{Labels: map[string]string{LabelManaged: "1", LabelApp: "shop"}}, State: &container.State{Running: true}})
			return
		}
		if !strings.Contains(r.URL.Path, "actual-id/logs") || r.URL.Query().Get("timestamps") != "1" || (r.URL.Query().Get("tail") != "all" && r.URL.Query().Get("tail") != "") {
			t.Errorf("unexpected logs request %s", r.URL)
		}
		_, _ = w.Write(raw.Bytes())
	})
	batch, err := d.LogBatch(context.Background(), "shop", name, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Records) != 2 || batch.BoundaryOffset != 3 || batch.Records[0].Text != "same" || batch.Records[1].Text != "same" {
		t.Fatalf("batch=%+v", batch)
	}
	batch, err = d.LogBatch(context.Background(), "shop", name, 100, "")
	if err != nil || len(batch.Records) != 3 || batch.Records[0].Text != "prefix-password-suffix" {
		t.Fatalf("fragmented batch=%+v err=%v", batch, err)
	}
}

func TestObservationsStatsDeltasAndWorkingSet(t *testing.T) {
	var sample container.StatsResponse
	sample.CPUStats.CPUUsage.TotalUsage = 300
	sample.PreCPUStats.CPUUsage.TotalUsage = 100
	sample.CPUStats.SystemUsage = 2000
	sample.PreCPUStats.SystemUsage = 1000
	sample.CPUStats.OnlineCPUs = 2
	sample.MemoryStats.Usage = 128 << 20
	sample.MemoryStats.Limit = 512 << 20
	sample.MemoryStats.Stats = map[string]uint64{"inactive_file": 32 << 20}
	view := containerStatsView(sample)
	if !view.CPUAvailable || view.CPUPercent != 40 || view.MemoryUsageMB != 96 || view.MemoryLimitMB != 512 {
		t.Fatalf("stats=%+v", view)
	}
	sample.CPUStats.CPUUsage.TotalUsage = 50 // counter reset must not underflow
	sample.MemoryStats.Limit = 0
	view = containerStatsView(sample)
	if view.CPUAvailable || view.CPUPercent != 0 || view.MemoryLimitMB != 0 {
		t.Fatalf("reset stats=%+v", view)
	}
	sample.PreCPUStats.SystemUsage = 0
	if containerStatsView(sample).CPUAvailable {
		t.Fatal("first sample must be unavailable")
	}
}

func TestObservationsStatsStoppedContainerDoesNotReadStats(t *testing.T) {
	name := ContainerName("shop", "0123456789ab")
	d := observationDocker(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/json") {
			t.Error("stats read for a stopped container")
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(container.InspectResponse{ID: "actual-id", Name: "/" + name, Config: &container.Config{Labels: map[string]string{LabelManaged: "1", LabelApp: "shop"}}, State: &container.State{Running: false}})
	})
	_, err := d.ContainerStats(context.Background(), "shop", name)
	if !errors.Is(err, ErrStopped) {
		t.Fatalf("err=%v", err)
	}
}
