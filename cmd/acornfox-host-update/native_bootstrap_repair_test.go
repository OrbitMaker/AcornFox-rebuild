package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/unifiedinstall"
)

func TestNativeBootstrapRepairCLIRejectsUntrustedInputsBeforeEffects(t *testing.T) {
	cases := [][]string{
		{"begin"},
		{"begin", "--bundle-id", "../foreign"},
		{"stage"},
		{"stage", "--bundle-id", "../foreign"},
		{"continue", "--stage", "/tmp/ready-0123456789abcdef0123456789abcdef"},
		{"recover", "--stage", "/tmp/ready-0123456789abcdef0123456789abcdef"},
		{"unknown"},
	}
	for _, args := range cases {
		var output bytes.Buffer
		if err := runNativeBootstrapRepair(context.Background(), args, &output); err == nil {
			t.Fatalf("untrusted input accepted: %q", args)
		}
		if output.Len() != 0 || strings.Contains(output.String(), "token") {
			t.Fatalf("rejected input produced output: %q", args)
		}
	}
	var output bytes.Buffer
	if err := runNativeBootstrapRepairChild(context.Background(), []string{"foreign"}, &output); err == nil || output.Len() != 0 {
		t.Fatal("untrusted child operation accepted")
	}
}

func TestNativeBootstrapRepairRestoreClassificationIsFixedText(t *testing.T) {
	private := errors.New("private quarantine filename")
	for _, item := range []struct {
		cause error
		want  string
	}{
		{unifiedinstall.ErrBootstrapRepairRestoreUnapproved, "not approved"},
		{unifiedinstall.ErrBootstrapRepairRestoreUncertain, "outcome unknown"},
	} {
		message := nativeBootstrapRepairFailureMessage(errors.Join(item.cause, private))
		if !strings.Contains(message, item.want) || strings.Contains(message, private.Error()) {
			t.Fatal("restore status was ambiguous or leaked a private cause")
		}
	}
}
