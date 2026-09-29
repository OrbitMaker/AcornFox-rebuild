package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/unifiedinstall"
)

func TestNativeFirstCoreCLIUsesFixedReadyStageAndUnknownText(t *testing.T) {
	stage := "/var/lib/acornfox/unified-install/ready-0123456789abcdef0123456789abcdef"
	if got, err := parseNativeFirstCoreArgs([]string{"--stage", stage}); err != nil || got != stage {
		t.Fatalf("fixed stage refused: %v", err)
	}
	if _, err := parseNativeFirstCoreArgs([]string{"--stage", "/tmp/ready-0123456789abcdef0123456789abcdef"}); err == nil {
		t.Fatal("foreign stage accepted")
	}
	private := errors.New("private credential path")
	text := nativeFirstCoreFailureMessage(errors.Join(unifiedinstall.ErrNativeFirstCoreUnknown, private))
	if !strings.Contains(text, "outcome unknown") || strings.Contains(text, private.Error()) {
		t.Fatal("unknown result hidden or private cause leaked")
	}
}
