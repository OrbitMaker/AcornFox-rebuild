package main

import (
	"errors"
	"testing"

	"github.com/open-card/open-card/internal/unifiedinstall"
)

type rejectedResultWriter struct{ cause error }

func (w rejectedResultWriter) Write([]byte) (int, error) { return 0, w.cause }

func TestNativeBindingCLIRequiresFixedStageAndDistinctPIDs(t *testing.T) {
	valid := []string{"--stage", "/var/lib/acornfox/unified-install/ready-fixture", "--core-pid", "101", "--container-pid", "102", "--source-pid", "103", "--gateway-pid", "104"}
	request, err := parseNativeBindingArgs(valid)
	if err != nil || request.CorePID != 101 || request.ContainerPID != 102 || request.SourcePID != 103 || request.GatewayPID != 104 {
		t.Fatalf("Native publisher flags rejected: %v", err)
	}
	for _, args := range [][]string{
		{"--stage", "/opt/acornfox/current", "--core-pid", "101", "--container-pid", "102", "--source-pid", "103", "--gateway-pid", "104"},
		{"--stage", "/var/lib/acornfox/unified-install/ready-fixture", "--core-pid", "101", "--container-pid", "101", "--source-pid", "103", "--gateway-pid", "104"},
		{"--stage", "/var/lib/acornfox/unified-install/ready-fixture", "--core-pid", "101", "--container-pid", "102", "--source-pid", "103", "--gateway-pid", "102"},
		{"--stage", "/var/lib/acornfox/unified-install/ready-fixture", "--core-pid", "101", "--container-pid", "102", "--source-pid", "103"},
		{"--stage", "/var/lib/acornfox/unified-install/ready-fixture", "--core-pid", "101", "--container-pid", "102", "--source-pid", "103", "--gateway-pid", "104", "--self-declared-sha", "fake"},
	} {
		if _, err := parseNativeBindingArgs(args); err == nil {
			t.Fatalf("unsafe Native publisher flags accepted: %v", args)
		}
	}
}

func TestCommittedNativeBindingOutputFailureIsUnknown(t *testing.T) {
	cause := errors.New("output unavailable")
	err := writeNativeBindingResult(rejectedResultWriter{cause}, unifiedinstall.NativeBindingResult{Digest: "sha256:fixture"})
	if !errors.Is(err, unifiedinstall.ErrBindingCommitUnknown) || !errors.Is(err, cause) {
		t.Fatalf("committed binding output error lost unknown outcome: %v", err)
	}
}
