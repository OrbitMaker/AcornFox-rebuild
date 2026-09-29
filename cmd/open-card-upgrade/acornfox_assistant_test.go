package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/install"
)

func TestAcornFoxAssistantCLIIsClosedAndDoesNotEchoKeyPath(t *testing.T) {
	withAcornFoxIdentity(t)
	for _, args := range [][]string{
		{"configure-assistant"},
		{"configure-assistant", "--deepseek-key-file", "relative"},
		{"configure-assistant", "--deepseek-key-file", "/"},
		{"configure-assistant", "--deepseek-key-file", "/root/key", "extra"},
		{"configure-assistant", "--provider", "deepseek"},
		{"disable-assistant", "extra"},
	} {
		var output bytes.Buffer
		called := false
		deps := upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{
			euid: func() int { called = true; return 0 },
			configureAssistant: func(context.Context, string) (install.AcornFoxAssistantConfigReceiptV1, error) {
				called = true
				return install.AcornFoxAssistantConfigReceiptV1{}, nil
			},
		}}
		if code := runWithDependencies(context.Background(), args, &output, &bytes.Buffer{}, deps); code != exitArgs || called {
			t.Fatalf("args=%q code=%d called=%t", args, code, called)
		}
		if strings.Contains(output.String(), "key") || strings.Contains(output.String(), "provider") || cleanJSON(t, output.Bytes())["code"] != "invalid_arguments" {
			t.Fatalf("arguments leaked: %q", output.String())
		}
	}
}

func TestAcornFoxAssistantCLIDispatchAndRedaction(t *testing.T) {
	withAcornFoxIdentity(t)
	calls := 0
	deps := upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{
		euid: func() int { return 0 },
		disableAssistant: func(context.Context) (install.AcornFoxAssistantConfigReceiptV1, error) {
			calls++
			return install.AcornFoxAssistantConfigReceiptV1{SchemaVersion: 1, State: "ASSISTANT_DISABLED", Configured: true}, nil
		},
	}}
	var output bytes.Buffer
	if code := runWithDependencies(context.Background(), []string{"disable-assistant"}, &output, &bytes.Buffer{}, deps); code != exitOK || calls != 1 {
		t.Fatalf("code=%d calls=%d output=%q", code, calls, output.String())
	}
	result := cleanJSON(t, output.Bytes())
	if result["ok"] != true || result["command"] != "disable-assistant" {
		t.Fatalf("result=%#v", result)
	}

	output.Reset()
	if code := runWithDependencies(context.Background(), []string{"configure-assistant", "--deepseek-key-file", "/root/deepseek-secret"}, &output, &bytes.Buffer{}, deps); code != exitIneligible || cleanJSON(t, output.Bytes())["code"] != "assistant_retired" {
		t.Fatalf("code=%d output=%q", code, output.String())
	}
}

func TestAcornFoxAssistantCLIMapsPrivateFailures(t *testing.T) {
	withAcornFoxIdentity(t)
	for _, test := range []struct {
		err  error
		code int
		text string
	}{{install.ErrAcornFoxAssistantConfigConflict, exitConflict, "assistant_configuration_conflict"}, {install.ErrAcornFoxAssistantConfigUnknown, exitRecovery, "assistant_configuration_unknown"}, {errors.New("secret canary"), exitIneligible, "assistant_configuration_ineligible"}} {
		var output bytes.Buffer
		deps := upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{euid: func() int { return 0 }, disableAssistant: func(context.Context) (install.AcornFoxAssistantConfigReceiptV1, error) {
			return install.AcornFoxAssistantConfigReceiptV1{}, test.err
		}}}
		if code := runWithDependencies(context.Background(), []string{"disable-assistant"}, &output, &bytes.Buffer{}, deps); code != test.code || cleanJSON(t, output.Bytes())["code"] != test.text || strings.Contains(output.String(), "canary") {
			t.Fatalf("code=%d output=%q", code, output.String())
		}
	}
}

func TestAcornFoxAssistantCLIHelpStatesServerRestartBoundary(t *testing.T) {
	for _, command := range []string{"configure-assistant", "disable-assistant"} {
		var output bytes.Buffer
		if code := runAcornFoxClean(context.Background(), []string{command, "--help"}, &output, "invalid", acornFoxCleanDependencies{}); code != exitOK {
			t.Fatalf("command=%s code=%d", command, code)
		}
		text := output.String()
		for _, required := range []string{"acornfox-server.service", "application containers are not restarted"} {
			if !strings.Contains(text, required) {
				t.Fatalf("command=%s help=%q", command, text)
			}
		}
		if strings.Contains(text, "deepseek_api_key") {
			t.Fatal("help exposed credential internals")
		}
	}
}
