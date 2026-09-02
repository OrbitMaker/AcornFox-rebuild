package probe

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

func TestDeriveLoopbackTargetAcceptsOnlyMatchingCanonicalIPv4Loopback(t *testing.T) {
	request := probeRequest(t, contracts.AcornFoxProbeProtocolTCP, "")
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(request.Reference.Fact)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []struct {
		name    string
		address string
		want    bool
	}{
		{name: "canonical ipv4", address: "127.0.0.1:18080", want: true},
		{name: "all interfaces", address: "0.0.0.0:18080"},
		{name: "ipv6", address: "[::1]:18080"},
		{name: "other loopback", address: "127.0.0.2:18080"},
		{name: "hostname", address: "localhost:18080"},
		{name: "scheme", address: "http://127.0.0.1:18080"},
		{name: "path", address: "127.0.0.1:18080/path"},
		{name: "leading zero port", address: "127.0.0.1:018080"},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			target, err := DeriveLoopbackTarget(request, contracts.AcornFoxRuntimeObservation{DeploymentID: deploymentID, ServiceName: "web", InternalAddress: candidate.address})
			if candidate.want {
				if err != nil || !target.Applicable || target.Address != candidate.address {
					t.Fatalf("target=%+v err=%v", target, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("unsafe address was accepted: %+v", target)
			}
		})
	}
	zeroPortRequest := withContainerPort(t, request, 0)
	if target, err := DeriveLoopbackTarget(zeroPortRequest, probeObservation(t, zeroPortRequest, "")); err != nil || target.Applicable {
		t.Fatalf("zero-port target=%+v err=%v", target, err)
	}
	if _, err := DeriveLoopbackTarget(request, probeObservation(t, request, "")); err == nil {
		t.Fatal("portful runtime reference accepted a missing observed address")
	}
	if _, err := DeriveLoopbackTarget(zeroPortRequest, probeObservation(t, zeroPortRequest, "127.0.0.1:18080")); err == nil {
		t.Fatal("portless runtime reference accepted an observed address")
	}
	if _, err := DeriveLoopbackTarget(request, contracts.AcornFoxRuntimeObservation{DeploymentID: "dep_other", ServiceName: "web", InternalAddress: "127.0.0.1:18080"}); err == nil {
		t.Fatal("mismatched deployment was accepted")
	}
}

func TestHTTPProbeRespondsForEveryHTTPStatusAndDoesNotFollowRedirect(t *testing.T) {
	listener := localListener(t)
	defer listener.Close()
	redirected := make(chan struct{}, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/ok":
			writer.WriteHeader(http.StatusNoContent)
		case "/failure":
			writer.WriteHeader(http.StatusServiceUnavailable)
		case "/redirect":
			writer.Header().Set("Location", "/followed")
			writer.WriteHeader(http.StatusFound)
		case "/followed":
			redirected <- struct{}{}
			writer.WriteHeader(http.StatusOK)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	})}
	go server.Serve(listener)
	defer server.Close()

	for _, candidate := range []struct {
		path   string
		status int
	}{
		{"/ok", http.StatusNoContent},
		{"/failure", http.StatusServiceUnavailable},
		{"/redirect", http.StatusFound},
	} {
		t.Run(candidate.path, func(t *testing.T) {
			result := runProbe(t, contracts.AcornFoxProbeProtocolHTTP, candidate.path, listener.Addr().String())
			if result.Outcome != contracts.AcornFoxProbeOutcomeResponded || result.HTTPStatus == nil || *result.HTTPStatus != candidate.status || result.ErrorCode != "" {
				t.Fatalf("result=%+v", result)
			}
		})
	}
	select {
	case <-redirected:
		t.Fatal("HTTP client followed a redirect")
	default:
	}
}

func TestProbeClassifiesTimeoutRefusedMalformedAndCancelledWithoutRawErrors(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		listener := localListener(t)
		defer listener.Close()
		server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			<-request.Context().Done()
		})}
		go server.Serve(listener)
		defer server.Close()
		result := runProbeWithConfig(t, contracts.AcornFoxProbeProtocolHTTP, "/", listener.Addr().String(), Config{HTTPTimeout: 30 * time.Millisecond, TCPTimeout: time.Second, MaxResponseBytes: 16})
		if result.Outcome != contracts.AcornFoxProbeOutcomeTimeout || result.ErrorCode != contracts.AcornFoxProbeErrorTimeout {
			t.Fatalf("result=%+v", result)
		}
	})
	t.Run("refused", func(t *testing.T) {
		port := closedLoopbackPort(t)
		result := runProbe(t, contracts.AcornFoxProbeProtocolTCP, "", "127.0.0.1:"+strconv.Itoa(port))
		if result.Outcome != contracts.AcornFoxProbeOutcomeRefused || result.ErrorCode != contracts.AcornFoxProbeErrorConnectionRefused {
			t.Fatalf("result=%+v", result)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		listener := localListener(t)
		defer listener.Close()
		go func() {
			connection, err := listener.Accept()
			if err == nil {
				_, _ = connection.Write([]byte("definitely-not-http secret=never-persisted\r\n"))
				_ = connection.Close()
			}
		}()
		result := runProbe(t, contracts.AcornFoxProbeProtocolHTTP, "/", listener.Addr().String())
		if result.Outcome != contracts.AcornFoxProbeOutcomeMalformedResponse || result.ErrorCode != contracts.AcornFoxProbeErrorMalformedResponse {
			t.Fatalf("result=%+v", result)
		}
		raw := fmt.Sprintf("%+v", result)
		if strings.Contains(raw, "never-persisted") {
			t.Fatalf("raw transport error leaked: %s", raw)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		listener := localListener(t)
		defer listener.Close()
		request := probeRequest(t, contracts.AcornFoxProbeProtocolHTTP, "/")
		observation := probeObservation(t, request, listener.Addr().String())
		prober, err := New(DefaultConfig(), func() time.Time { return time.Unix(7, 0).UTC() })
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := prober.Probe(ctx, request, observation)
		if err != nil || result.Outcome != contracts.AcornFoxProbeOutcomeCancelled || result.ErrorCode != contracts.AcornFoxProbeErrorCancelled {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("parent deadline is timeout", func(t *testing.T) {
		listener := localListener(t)
		defer listener.Close()
		server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			<-request.Context().Done()
		})}
		go server.Serve(listener)
		defer server.Close()
		request := probeRequest(t, contracts.AcornFoxProbeProtocolHTTP, "/")
		observation := probeObservation(t, request, listener.Addr().String())
		prober, err := New(DefaultConfig(), func() time.Time { return time.Unix(7, 0).UTC() })
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		result, err := prober.Probe(ctx, request, observation)
		if err != nil || result.Outcome != contracts.AcornFoxProbeOutcomeTimeout || result.ErrorCode != contracts.AcornFoxProbeErrorTimeout {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
}

func TestHTTPProbeClassifiesClosedLoopbackPortAsRefused(t *testing.T) {
	port := closedLoopbackPort(t)
	result := runProbe(t, contracts.AcornFoxProbeProtocolHTTP, "/", "127.0.0.1:"+strconv.Itoa(port))
	if result.Outcome != contracts.AcornFoxProbeOutcomeRefused || result.ErrorCode != contracts.AcornFoxProbeErrorConnectionRefused || result.HTTPStatus != nil {
		t.Fatalf("result=%+v", result)
	}
}

func TestTCPProbeAndNoPort(t *testing.T) {
	listener := localListener(t)
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- struct{}{}
			_ = connection.Close()
		}
	}()
	responded := runProbe(t, contracts.AcornFoxProbeProtocolTCP, "", listener.Addr().String())
	if responded.Outcome != contracts.AcornFoxProbeOutcomeResponded || responded.HTTPStatus != nil {
		t.Fatalf("result=%+v", responded)
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("TCP probe did not connect")
	}

	request := withContainerPort(t, probeRequest(t, contracts.AcornFoxProbeProtocolHTTP, "/"), 0)
	observation := probeObservation(t, request, "")
	prober, err := New(DefaultConfig(), func() time.Time { return time.Unix(7, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	result, err := prober.Probe(context.Background(), request, observation)
	if err != nil || result.Outcome != contracts.AcornFoxProbeOutcomeNotApplicable || result.LatencyMS != 0 || result.ErrorCode != "" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestTCPProbeClassifiesInjectedDeadlineAndCancellation(t *testing.T) {
	request := probeRequest(t, contracts.AcornFoxProbeProtocolTCP, "")
	address := "127.0.0.1:18080"
	observation := probeObservation(t, request, address)
	for _, candidate := range []struct {
		name      string
		config    Config
		context   func() (context.Context, context.CancelFunc)
		outcome   contracts.AcornFoxProbeOutcome
		errorCode string
	}{
		{
			name:      "attempt deadline",
			config:    Config{HTTPTimeout: time.Second, TCPTimeout: 20 * time.Millisecond, MaxResponseBytes: 16},
			context:   func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			outcome:   contracts.AcornFoxProbeOutcomeTimeout,
			errorCode: contracts.AcornFoxProbeErrorTimeout,
		},
		{
			name:   "parent cancellation",
			config: Config{HTTPTimeout: time.Second, TCPTimeout: time.Second, MaxResponseBytes: 16},
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(20*time.Millisecond, cancel)
				return ctx, cancel
			},
			outcome:   contracts.AcornFoxProbeOutcomeCancelled,
			errorCode: contracts.AcornFoxProbeErrorCancelled,
		},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			prober, err := New(candidate.config, func() time.Time { return time.Unix(7, 0).UTC() })
			if err != nil {
				t.Fatal(err)
			}
			prober.dialContext = func(ctx context.Context, network, target string) (net.Conn, error) {
				if network != "tcp" || target != address {
					t.Fatalf("network=%q target=%q", network, target)
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}
			ctx, cancel := candidate.context()
			defer cancel()
			result, err := prober.Probe(ctx, request, observation)
			if err != nil || result.Outcome != candidate.outcome || result.ErrorCode != candidate.errorCode {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

func TestHTTPProbeBoundsBodyRead(t *testing.T) {
	listener := localListener(t)
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(bytes.Repeat([]byte("x"), 1<<20))
	})}
	go server.Serve(listener)
	defer server.Close()
	started := time.Now()
	result := runProbeWithConfig(t, contracts.AcornFoxProbeProtocolHTTP, "/", listener.Addr().String(), Config{HTTPTimeout: time.Second, TCPTimeout: time.Second, MaxResponseBytes: 1})
	if result.Outcome != contracts.AcornFoxProbeOutcomeResponded || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("result=%+v elapsed=%s", result, time.Since(started))
	}
}

func TestHTTPProbeDoesNotCallAHeaderOnlyResponseResponded(t *testing.T) {
	for _, candidate := range []struct {
		name string
		body string
	}{
		{name: "truncated content length", body: "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"},
		{name: "invalid chunk", body: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nnot-a-chunk\r\n"},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			listener := localListener(t)
			defer listener.Close()
			go func() {
				connection, err := listener.Accept()
				if err == nil {
					_, _ = connection.Write([]byte(candidate.body))
					_ = connection.Close()
				}
			}()
			result := runProbe(t, contracts.AcornFoxProbeProtocolHTTP, "/", listener.Addr().String())
			if result.Outcome != contracts.AcornFoxProbeOutcomeMalformedResponse || result.ErrorCode != contracts.AcornFoxProbeErrorMalformedResponse || result.HTTPStatus != nil {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestHTTPProbeClassifiesBodyReadDeadlineAndParentCancellation(t *testing.T) {
	t.Run("body read deadline", func(t *testing.T) {
		listener := localListener(t)
		defer listener.Close()
		server := bodyStallServer()
		go server.Serve(listener)
		defer server.Close()
		result := runProbeWithConfig(t, contracts.AcornFoxProbeProtocolHTTP, "/", listener.Addr().String(), Config{HTTPTimeout: 30 * time.Millisecond, TCPTimeout: time.Second, MaxResponseBytes: 16})
		if result.Outcome != contracts.AcornFoxProbeOutcomeTimeout || result.ErrorCode != contracts.AcornFoxProbeErrorTimeout || result.HTTPStatus != nil {
			t.Fatalf("result=%+v", result)
		}
	})
	t.Run("parent cancellation during body", func(t *testing.T) {
		listener := localListener(t)
		defer listener.Close()
		started := make(chan struct{}, 1)
		server := bodyStallServerStarted(started)
		go server.Serve(listener)
		defer server.Close()
		request := probeRequest(t, contracts.AcornFoxProbeProtocolHTTP, "/")
		observation := probeObservation(t, request, listener.Addr().String())
		prober, err := New(DefaultConfig(), func() time.Time { return time.Unix(7, 0).UTC() })
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		resultCh := make(chan contracts.AcornFoxProbeResult, 1)
		errCh := make(chan error, 1)
		go func() {
			result, err := prober.Probe(ctx, request, observation)
			resultCh <- result
			errCh <- err
		}()
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("body read never started")
		}
		cancel()
		select {
		case result := <-resultCh:
			if err := <-errCh; err != nil || result.Outcome != contracts.AcornFoxProbeOutcomeCancelled || result.ErrorCode != contracts.AcornFoxProbeErrorCancelled || result.HTTPStatus != nil {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		case <-time.After(time.Second):
			t.Fatal("body read did not observe parent cancellation")
		}
	})
}

func runProbe(t *testing.T, protocol contracts.AcornFoxProbeProtocol, path, address string) contracts.AcornFoxProbeResult {
	t.Helper()
	return runProbeWithConfig(t, protocol, path, address, DefaultConfig())
}

func runProbeWithConfig(t *testing.T, protocol contracts.AcornFoxProbeProtocol, path, address string, config Config) contracts.AcornFoxProbeResult {
	t.Helper()
	request := probeRequest(t, protocol, path)
	prober, err := New(config, func() time.Time { return time.Unix(7, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	result, err := prober.Probe(context.Background(), request, probeObservation(t, request, address))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func probeRequest(t *testing.T, protocol contracts.AcornFoxProbeProtocol, path string) contracts.AcornFoxProbeRequest {
	t.Helper()
	fact := contracts.AcornFoxRuntimeReleaseFact{
		ApplicationID: "app_probe",
		EnvironmentID: "env_probe",
		ReleaseID:     "rel_probe",
		ServiceName:   "web",
		Image:         domain.ImageDigest{Repository: "registry.open-card.test/apps/web", Digest: "sha256:" + strings.Repeat("b", 64)},
		Resources:     contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 1, MemoryBytes: 1, PIDs: 1, DiskReservationBytes: 1},
		ContainerPort: 8080,
		AcceptedAt:    time.Unix(1, 0).UTC(),
		Immutable:     true,
	}
	request, err := contracts.NewAcornFoxProbeRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, protocol, path, "probe-idempotency")
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func probeObservation(t *testing.T, request contracts.AcornFoxProbeRequest, address string) contracts.AcornFoxRuntimeObservation {
	t.Helper()
	deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(request.Reference.Fact)
	if err != nil {
		t.Fatal(err)
	}
	return contracts.AcornFoxRuntimeObservation{DeploymentID: deploymentID, ServiceName: request.Reference.Fact.ServiceName, InternalAddress: address}
}

func withContainerPort(t *testing.T, request contracts.AcornFoxProbeRequest, port int) contracts.AcornFoxProbeRequest {
	t.Helper()
	fact := request.Reference.Fact
	fact.ContainerPort = port
	updated, err := contracts.NewAcornFoxProbeRequest(contracts.AcornFoxRuntimeReference{Fact: fact}, request.Protocol, request.HTTPPath, request.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	return updated
}

func localListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func closedLoopbackPort(t *testing.T) int {
	t.Helper()
	listener := localListener(t)
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func bodyStallServer() *http.Server {
	return bodyStallServerStarted(nil)
}

func bodyStallServerStarted(started chan<- struct{}) *http.Server {
	return &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", "10")
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		if started != nil {
			started <- struct{}{}
		}
		<-request.Context().Done()
	})}
}
