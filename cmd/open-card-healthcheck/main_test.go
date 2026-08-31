package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/healthcheck"
)

type runnerStub struct {
	run    func(context.Context) (healthcheck.ProductionRunResult, error)
	close  func() error
	trace  *[]string
	runs   int
	closes int
}

func (s *runnerStub) RunOnce(ctx context.Context) (healthcheck.ProductionRunResult, error) {
	s.runs++
	if s.trace != nil {
		*s.trace = append(*s.trace, "run")
	}
	return s.run(ctx)
}

func (s *runnerStub) Close() error {
	s.closes++
	if s.trace != nil {
		*s.trace = append(*s.trace, "close")
	}
	if s.close == nil {
		return nil
	}
	return s.close()
}

func TestHealthcheckRejectsArgumentsAndNonRootBeforeConstruction(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		euid int
		code string
	}{
		{name: "arguments", args: []string{"--unexpected"}, euid: 0, code: "invalid_arguments"},
		{name: "non root", euid: 1000, code: "root_required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			constructed := false
			output, stderr, exit := invoke(t, context.Background(), test.args, dependencies{
				euid: func() int { return test.euid },
				newRunner: func() (productionRunner, error) {
					constructed = true
					return nil, errors.New("must not construct")
				},
				timeout: commandTimeout,
			})
			if exit != exitFailure || constructed || output.Code != test.code || output.OK || output.Result != nil || stderr != "" {
				t.Fatalf("exit=%d constructed=%t output=%+v stderr=%q", exit, constructed, output, stderr)
			}
		})
	}
}

func TestHealthcheckConstructionFailureIsSanitized(t *testing.T) {
	output, stderr, exit := invoke(t, context.Background(), nil, dependencies{
		euid: func() int { return 0 },
		newRunner: func() (productionRunner, error) {
			return nil, errors.New("configuration /etc/open-card/server.env postgres://user:secret@example.invalid/open-card")
		},
		timeout: commandTimeout,
	})
	if exit != exitFailure || output.Code != "construction_failed" || output.Result != nil || stderr != "" || strings.Contains(outputString(output), "postgres") || strings.Contains(outputString(output), "/etc/") {
		t.Fatalf("exit=%d output=%+v stderr=%q", exit, output, stderr)
	}
}

func TestHealthcheckPreCanceledContextDoesNotConstructRunner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	constructed := false
	output, stderr, exit := invoke(t, ctx, nil, dependencies{
		euid: func() int { return 0 },
		newRunner: func() (productionRunner, error) {
			constructed = true
			return nil, errors.New("must not construct")
		},
		timeout: commandTimeout,
	})
	if exit != exitFailure || constructed || output.Code != "context_canceled" || output.OK || output.Result != nil || stderr != "" {
		t.Fatalf("exit=%d constructed=%t output=%+v stderr=%q", exit, constructed, output, stderr)
	}
}

func TestHealthcheckSuccessAndUnhealthyDelivery(t *testing.T) {
	for _, test := range []struct {
		name    string
		result  healthcheck.ProductionRunResult
		healthy bool
	}{
		{name: "healthy", result: validResult(healthcheck.SeverityOK), healthy: true},
		{name: "unhealthy delivered", result: validResult(healthcheck.SeverityCritical), healthy: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &runnerStub{run: func(context.Context) (healthcheck.ProductionRunResult, error) { return test.result, nil }}
			output, stderr, exit := invoke(t, context.Background(), nil, testDependencies(stub))
			if exit != exitSuccess || !output.OK || output.Code != "ok" || output.Healthy != test.healthy || output.Result == nil || stderr != "" {
				t.Fatalf("exit=%d output=%+v stderr=%q", exit, output, stderr)
			}
		})
	}
}

func TestHealthcheckRunErrorsUseFixedCodesAndRedactUnsafePartialResult(t *testing.T) {
	valid := pendingDeliveryResult(t, healthcheck.WebhookDeliveryRetryableFailure)
	terminal := pendingDeliveryResult(t, healthcheck.WebhookDeliveryFailed)
	unsafe := valid
	unsafe.Snapshot.Results = append([]healthcheck.CheckResult(nil), valid.Snapshot.Results...)
	unsafe.Snapshot.Results[0].SubjectSHA256 = "postgres://secret@example.invalid/open-card"
	unsafe.Delivery.Status = ""
	for _, test := range []struct {
		name       string
		result     healthcheck.ProductionRunResult
		wantCode   string
		wantResult bool
	}{
		{name: "retryable", result: valid, wantCode: "delivery_retryable_failure", wantResult: true},
		{name: "terminal", result: terminal, wantCode: "delivery_terminal_failure", wantResult: true},
		{name: "unsafe partial", result: unsafe, wantCode: "healthcheck_failed", wantResult: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &runnerStub{run: func(context.Context) (healthcheck.ProductionRunResult, error) {
				return test.result, errors.New("database postgres://secret@example.invalid/open-card failed")
			}}
			output, stderr, exit := invoke(t, context.Background(), nil, testDependencies(stub))
			raw := outputString(output)
			if exit != exitFailure || output.Code != test.wantCode || (output.Result != nil) != test.wantResult || stderr != "" || strings.Contains(raw, "postgres") || strings.Contains(raw, "secret") {
				t.Fatalf("exit=%d output=%+v stderr=%q", exit, output, stderr)
			}
		})
	}
}

func TestHealthcheckUnsafeRunErrorsCannotSelectDeliveryFailureCode(t *testing.T) {
	wrongEvent := pendingDeliveryResult(t, healthcheck.WebhookDeliveryRetryableFailure)
	wrongEvent.Delivery.EventID = "sha256:" + strings.Repeat("d", 64)
	noPending := pendingDeliveryResult(t, healthcheck.WebhookDeliveryFailed)
	noPending.IncidentState.PendingNotification = ""
	invalidSnapshot := pendingDeliveryResult(t, healthcheck.WebhookDeliveryRetryableFailure)
	invalidSnapshot.Snapshot.Results[0].SubjectSHA256 = "postgres://user:secret@example.invalid/open-card"
	for _, test := range []struct {
		name   string
		result healthcheck.ProductionRunResult
	}{
		{name: "foreign event", result: wrongEvent},
		{name: "no pending notification", result: noPending},
		{name: "invalid snapshot", result: invalidSnapshot},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &runnerStub{run: func(context.Context) (healthcheck.ProductionRunResult, error) {
				return test.result, errors.New("delivery postgres://user:secret@example.invalid/open-card failed")
			}}
			output, stderr, exit := invoke(t, context.Background(), nil, testDependencies(stub))
			raw := outputString(output)
			if exit != exitFailure || output.Code != "healthcheck_failed" || output.Result != nil || stderr != "" || strings.Contains(raw, "postgres") || strings.Contains(raw, "secret") {
				t.Fatalf("exit=%d output=%+v stderr=%q", exit, output, stderr)
			}
		})
	}
}

func TestHealthcheckRejectsUnsafeSuccessfulResult(t *testing.T) {
	invalidSnapshot := validResult(healthcheck.SeverityOK)
	invalidSnapshot.Snapshot.Results[0].SubjectSHA256 = "postgres://user:secret@example.invalid/open-card"
	pendingWithoutDelivery := validResult(healthcheck.SeverityCritical)
	pendingWithoutDelivery.IncidentState.PendingNotification = "occurrence"
	incoherentFailure := pendingDeliveryResult(t, healthcheck.WebhookDeliveryRetryableFailure)
	incoherentFailure.IncidentState.PendingNotification = ""
	for _, test := range []struct {
		name   string
		result healthcheck.ProductionRunResult
	}{
		{name: "invalid snapshot", result: invalidSnapshot},
		{name: "pending without delivery", result: pendingWithoutDelivery},
		{name: "failed delivery after acknowledgement", result: incoherentFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &runnerStub{run: func(context.Context) (healthcheck.ProductionRunResult, error) {
				return test.result, nil
			}}
			output, stderr, exit := invoke(t, context.Background(), nil, testDependencies(stub))
			raw := outputString(output)
			if exit != exitFailure || output.Code != "healthcheck_failed" || output.OK || output.Healthy || output.Result != nil || stderr != "" || stub.closes != 1 || strings.Contains(raw, "postgres") || strings.Contains(raw, "secret") {
				t.Fatalf("exit=%d output=%+v stderr=%q closes=%d", exit, output, stderr, stub.closes)
			}
		})
	}
}

func TestHealthcheckClosesAfterRunAndBoundsContext(t *testing.T) {
	trace := []string{}
	stub := &runnerStub{
		trace: &trace,
		run: func(ctx context.Context) (healthcheck.ProductionRunResult, error) {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 50*time.Second || time.Until(deadline) <= 0 {
				t.Fatalf("deadline=%v ok=%t", deadline, ok)
			}
			return validResult(healthcheck.SeverityOK), nil
		},
	}
	output, stderr, exit := invoke(t, context.Background(), nil, testDependencies(stub))
	if exit != exitSuccess || output.Code != "ok" || stderr != "" || strings.Join(trace, ",") != "run,close" || stub.runs != 1 || stub.closes != 1 {
		t.Fatalf("exit=%d output=%+v stderr=%q trace=%v calls=%d/%d", exit, output, stderr, trace, stub.runs, stub.closes)
	}
}

func TestHealthcheckCancellationAndCloseFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stub := &runnerStub{
		run: func(got context.Context) (healthcheck.ProductionRunResult, error) {
			cancel()
			if got.Err() == nil {
				t.Fatal("cancellation was not propagated")
			}
			return healthcheck.ProductionRunResult{}, errors.New("canceled with /etc/open-card/secret")
		},
		close: func() error { return errors.New("close /var/lib/open-card/secret") },
	}
	output, stderr, exit := invoke(t, ctx, nil, testDependencies(stub))
	if exit != exitFailure || output.Code != "close_failed" || output.Result != nil || stderr != "" || stub.runs != 1 || stub.closes != 1 {
		t.Fatalf("exit=%d output=%+v stderr=%q calls=%d/%d", exit, output, stderr, stub.runs, stub.closes)
	}
}

func TestHealthcheckSystemdContracts(t *testing.T) {
	service := readContractFile(t, filepath.Join("..", "..", "deploy", "systemd", "open-card-healthcheck.service"))
	timer := readContractFile(t, filepath.Join("..", "..", "deploy", "systemd", "open-card-healthcheck.timer"))
	for _, want := range []string{
		"Type=oneshot", "User=root", "Group=root", "ExecStart=/opt/open-card/current/bin/open-card-healthcheck", "TimeoutStartSec=50s",
		"After=network-online.target open-card-server.service open-card-agent.service open-card-edge.service open-card-caddy.service open-card-buildkit.service open-card-upgrade-safe.target",
		"NoNewPrivileges=yes", "PrivateTmp=yes", "PrivateDevices=yes", "ProtectSystem=strict", "ProtectHome=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes", "RestrictNamespaces=yes", "LockPersonality=yes",
		"CapabilityBoundingSet=CAP_DAC_READ_SEARCH", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "ReadWritePaths=/var/lib/open-card/healthcheck /var/lib/open-card/health-secret-materials", "UMask=0077",
	} {
		if !strings.Contains(service, want+"\n") {
			t.Errorf("service missing %q", want)
		}
	}
	for _, forbidden := range []string{"EnvironmentFile=", "/bin/sh", "/bin/bash", "Restart="} {
		if strings.Contains(service, forbidden) {
			t.Errorf("service contains forbidden %q", forbidden)
		}
	}
	if strings.Count(service, "ReadWritePaths=") != 1 {
		t.Error("service must have exactly one ReadWritePaths declaration")
	}
	for _, want := range []string{"OnBootSec=30s", "OnUnitActiveSec=60s", "AccuracySec=1s", "Persistent=true", "Unit=open-card-healthcheck.service", "WantedBy=timers.target"} {
		if !strings.Contains(timer, want+"\n") {
			t.Errorf("timer missing %q", want)
		}
	}
	if _, err := os.Stat(filepath.Join("..", "..", "cmd", "open-card-healthcheck", "main.go")); err != nil {
		t.Fatalf("command source missing: %v", err)
	}
}

func readContractFile(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read contract %s: %v", path, err)
	}
	return string(contents)
}

func invoke(t *testing.T, ctx context.Context, args []string, deps dependencies) (commandOutput, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	exit := runWithDependencies(ctx, args, &stdout, &stderr, deps)
	raw := stdout.String()
	if strings.Count(raw, "\n") != 1 {
		t.Fatalf("healthcheck did not emit exactly one JSON object: %q", raw)
	}
	var output commandOutput
	if err := json.Unmarshal([]byte(raw), &output); err != nil {
		t.Fatalf("decode healthcheck output: %v", err)
	}
	return output, stderr.String(), exit
}

func outputString(output commandOutput) string {
	encoded, err := json.Marshal(output)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func testDependencies(runner productionRunner) dependencies {
	return dependencies{
		euid:      func() int { return 0 },
		newRunner: func() (productionRunner, error) { return runner, nil },
		timeout:   commandTimeout,
	}
}

func validResult(overall healthcheck.Severity) healthcheck.ProductionRunResult {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	kinds := []healthcheck.CheckKind{
		healthcheck.CheckFiveUnits, healthcheck.CheckListeners, healthcheck.CheckDatabase, healthcheck.CheckControlAPI, healthcheck.CheckEdge,
		healthcheck.CheckBackup, healthcheck.CheckDisk, healthcheck.CheckInode, healthcheck.CheckCertificate, healthcheck.CheckWebhook,
	}
	results := make([]healthcheck.CheckResult, 0, len(kinds))
	for _, kind := range kinds {
		severity := healthcheck.SeverityOK
		code := "ok"
		if overall != healthcheck.SeverityOK && kind == healthcheck.CheckWebhook {
			severity = overall
			code = "delivery_failed"
		}
		results = append(results, healthcheck.CheckResult{Kind: kind, SubjectSHA256: strings.Repeat("a", 64), Severity: severity, Code: code})
	}
	fingerprint := healthcheck.HealthyFingerprint
	healthy := overall == healthcheck.SeverityOK
	if !healthy {
		fingerprint = strings.Repeat("b", 64)
	}
	return healthcheck.ProductionRunResult{
		Snapshot:      healthcheck.Snapshot{SchemaVersion: healthcheck.SchemaVersion, ObservedAt: now, Results: results, Overall: overall},
		IncidentState: healthcheck.IncidentState{SchemaVersion: healthcheck.SchemaVersion, Revision: 1, Fingerprint: fingerprint, FirstObserved: now, LastObserved: now, Severity: overall, NotificationStage: notificationStage(healthy), Healthy: healthy},
	}
}

func pendingDeliveryResult(t *testing.T, status healthcheck.WebhookDeliveryHealthStatus) healthcheck.ProductionRunResult {
	t.Helper()
	result := validResult(healthcheck.SeverityCritical)
	result.IncidentState.PendingNotification = "occurrence"
	event, err := healthcheck.WebhookDeliveryEventFromIncident(result.IncidentState)
	if err != nil {
		t.Fatalf("derive delivery event: %v", err)
	}
	result.Delivery = healthcheck.ProductionDeliveryResult{Status: status, Generation: 1, EventID: event.EventID}
	return result
}

func notificationStage(healthy bool) int {
	if healthy {
		return 0
	}
	return 1
}
