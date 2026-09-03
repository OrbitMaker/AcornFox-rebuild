// Command open-card-healthcheck runs one bounded, root-only production host
// health evaluation. Its output is deliberately a single secret-free JSON
// object so a systemd timer has no ambient configuration or logging channel.
package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/open-card/open-card/internal/healthcheck"
	"github.com/open-card/open-card/internal/install"
)

const helperRole = "healthcheck"

var (
	processIdentity   = "legacy"
	buildVersion      string
	buildSourceCommit string
	buildLayoutSchema string
)

const (
	outputSchemaVersion = 1
	commandTimeout      = 45 * time.Second

	exitSuccess = 0
	exitFailure = 1
)

type productionRunner interface {
	RunOnce(context.Context) (healthcheck.ProductionRunResult, error)
	Close() error
}

type dependencies struct {
	euid      func() int
	newRunner func() (productionRunner, error)
	timeout   time.Duration
}

type commandOutput struct {
	Schema  int                              `json:"schema"`
	OK      bool                             `json:"ok"`
	Healthy bool                             `json:"healthy"`
	Code    string                           `json:"code"`
	Result  *healthcheck.ProductionRunResult `json:"result,omitempty"`
}

func main() {
	os.Exit(runWithDependencies(context.Background(), os.Args[1:], os.Stdout, os.Stderr, productionDependencies()))
}

func productionDependencies() dependencies {
	return dependencies{
		euid: os.Geteuid,
		newRunner: func() (productionRunner, error) {
			return healthcheck.NewProductionRunner()
		},
		timeout: commandTimeout,
	}
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithDependencies(context.Background(), args, stdout, stderr, productionDependencies())
}

func runWithDependencies(ctx context.Context, args []string, stdout, stderr io.Writer, deps dependencies) int {
	if processIdentity == "acornfox" {
		return runAcornFoxContractCheck(args, stdout, helperRole)
	}
	if processIdentity != "legacy" {
		return writeAcornFoxContractFailure(stdout, install.AcornFoxHelperCodeIdentityMismatch)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	output := commandOutput{Schema: outputSchemaVersion, Code: "healthcheck_failed"}
	if len(args) != 0 {
		output.Code = "invalid_arguments"
		return writeOutput(stdout, stderr, output)
	}
	if deps.euid == nil || deps.euid() != 0 {
		output.Code = "root_required"
		return writeOutput(stdout, stderr, output)
	}
	if deps.newRunner == nil {
		output.Code = "construction_failed"
		return writeOutput(stdout, stderr, output)
	}
	if ctx.Err() != nil {
		output.Code = "context_canceled"
		return writeOutput(stdout, stderr, output)
	}

	runner, err := deps.newRunner()
	if err != nil || runner == nil {
		output.Code = "construction_failed"
		return writeOutput(stdout, stderr, output)
	}

	timeout := deps.timeout
	if timeout <= 0 || timeout > 50*time.Second {
		timeout = commandTimeout
	}
	runContext, cancel := context.WithTimeout(ctx, timeout)
	result, runErr := runner.RunOnce(runContext)
	cancel()
	resultIsSafe := safeResult(result)
	if resultIsSafe {
		resultCopy := result
		output.Result = &resultCopy
		output.Healthy = result.Snapshot.Overall == healthcheck.SeverityOK
	}
	closeErr := runner.Close()

	if closeErr != nil {
		output.Code = "close_failed"
		return writeOutput(stdout, stderr, output)
	}
	if runErr != nil {
		output.Code = failureCode(result, resultIsSafe)
		return writeOutput(stdout, stderr, output)
	}
	if !resultIsSafe {
		return writeOutput(stdout, stderr, output)
	}
	output.OK = true
	output.Code = "ok"
	return writeOutput(stdout, stderr, output)
}

func runAcornFoxContractCheck(args []string, stdout io.Writer, role string) int {
	if len(args) != 5 || args[0] != "contract-check" || args[1] != "--product" || args[2] != "acornfox" || args[3] != "--layout-schema" || args[4] != "1" {
		return writeAcornFoxContractFailure(stdout, install.AcornFoxHelperCodeInvalidArguments)
	}
	identity := install.AcornFoxBuildIdentityV1{SchemaVersion: install.AcornFoxHelperContractV1Schema, Product: install.AcornFoxV1Product, LayoutVersion: install.AcornFoxSubstrateLayoutV1, Role: role, Version: buildVersion, ReleaseID: "release-" + buildVersion, SourceCommit: buildSourceCommit}
	if buildLayoutSchema != "1" || identity.Validate() != nil {
		return writeAcornFoxContractFailure(stdout, install.AcornFoxHelperCodeIdentityMismatch)
	}
	return writeAcornFoxContractResult(stdout, install.VerifyProductionAcornFoxHelperContract(identity))
}

func writeAcornFoxContractFailure(stdout io.Writer, code string) int {
	return writeAcornFoxContractResult(stdout, install.AcornFoxHelperContractResultV1{SchemaVersion: install.AcornFoxHelperContractV1Schema, Code: code})
}

func writeAcornFoxContractResult(stdout io.Writer, result install.AcornFoxHelperContractResultV1) int {
	raw, err := install.MarshalAcornFoxHelperContractResultV1(result)
	if err != nil || stdout == nil {
		return exitFailure
	}
	_, err = stdout.Write(append(raw, '\n'))
	if err != nil {
		return exitFailure
	}
	if result.OK {
		return exitSuccess
	}
	return exitFailure
}

func failureCode(result healthcheck.ProductionRunResult, resultIsSafe bool) string {
	if !resultIsSafe {
		return "healthcheck_failed"
	}
	switch result.Delivery.Status {
	case healthcheck.WebhookDeliveryRetryableFailure:
		return "delivery_retryable_failure"
	case healthcheck.WebhookDeliveryFailed:
		return "delivery_terminal_failure"
	default:
		return "healthcheck_failed"
	}
}

func safeResult(result healthcheck.ProductionRunResult) bool {
	if result.Snapshot.Validate() != nil || result.IncidentState.Validate() != nil {
		return false
	}
	delivery := result.Delivery
	if delivery.Status == "" {
		return delivery.Generation == 0 && delivery.EventID == "" && !delivery.Delivered && result.IncidentState.PendingNotification == ""
	}
	if delivery.Generation < 1 || !safeEventID(delivery.EventID) {
		return false
	}
	switch delivery.Status {
	case healthcheck.WebhookDeliveryDelivered:
		return delivery.Delivered && result.IncidentState.PendingNotification == ""
	case healthcheck.WebhookDeliveryRetryableFailure, healthcheck.WebhookDeliveryFailed:
		if delivery.Delivered || result.IncidentState.PendingNotification == "" {
			return false
		}
		event, err := healthcheck.WebhookDeliveryEventFromIncident(result.IncidentState)
		return err == nil && delivery.EventID == event.EventID
	default:
		return false
	}
}

func safeEventID(value string) bool {
	if len(value) != len("sha256:")+64 || value[:len("sha256:")] != "sha256:" {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func writeOutput(stdout, stderr io.Writer, output commandOutput) int {
	encoded, err := json.Marshal(output)
	if err == nil {
		encoded = append(encoded, '\n')
		_, err = stdout.Write(encoded)
	}
	if err == nil {
		if output.OK {
			return exitSuccess
		}
		return exitFailure
	}
	// The output shape above cannot fail to encode in normal operation. This is
	// only a last-resort diagnostic for a broken output device.
	_, _ = io.WriteString(stderr, "open-card-healthcheck: output unavailable\n")
	return exitFailure
}
