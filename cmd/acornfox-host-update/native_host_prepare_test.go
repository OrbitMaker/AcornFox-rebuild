package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/unifiedinstall"
)

func TestNativeHostPrepareRequiresOneFixedReadyStage(t *testing.T) {
	stage := "/var/lib/acornfox/unified-install/ready-0123456789abcdef0123456789abcdef"
	if got, err := parseNativeHostPrepareArgs([]string{"--stage", stage}); err != nil || got != stage {
		t.Fatalf("fixed stage rejected: %v", err)
	}
	for _, args := range [][]string{nil, {"--stage", "/tmp/ready-0123456789abcdef0123456789abcdef"}, {"--stage", "/var/lib/acornfox/unified-install/ready-bad"}, {"--stage", stage, "--target-root", "/tmp/foreign"}, {"--stage", stage, "extra"}} {
		if _, err := parseNativeHostPrepareArgs(args); err == nil {
			t.Fatalf("unsafe host prepare args accepted: %v", args)
		}
	}
}

func TestNativeHostPrepareUnknownIsVisibleWithoutPrivateCause(t *testing.T) {
	private := errors.New("private stage and account path")
	message := nativeHostPrepareFailureMessage(errors.Join(unifiedinstall.ErrNativeHostPrepareUnknown, private))
	if !strings.Contains(message, "outcome unknown") || strings.Contains(message, private.Error()) {
		t.Fatal("post-effect failure was hidden or leaked private path")
	}
	if strings.Contains(nativeHostPrepareFailureMessage(errors.New("preflight refused")), "outcome unknown") {
		t.Fatal("pre-effect refusal mislabeled unknown")
	}
}
