package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/unifiedinstall"
)

func TestNativeDockerPrepareCLIHasFixedStageAndUnknownGuidance(t *testing.T) {
	stage := "/var/lib/acornfox/unified-install/ready-0123456789abcdef0123456789abcdef"
	if got, err := parseNativeDockerPrepareArgs([]string{"--stage", stage}); err != nil || got != stage {
		t.Fatalf("fixed stage refused: %v", err)
	}
	if _, err := parseNativeDockerPrepareArgs([]string{"--stage", "/tmp/ready-0123456789abcdef0123456789abcdef"}); err == nil {
		t.Fatal("foreign stage accepted")
	}
	private := errors.New("private daemon configuration")
	message := nativeDockerPrepareFailureMessage(errors.Join(unifiedinstall.ErrNativeDockerPrepareUnknown, private))
	if !strings.Contains(message, "outcome unknown") || strings.Contains(message, private.Error()) {
		t.Fatal("unknown outcome hidden or private cause leaked")
	}
}
