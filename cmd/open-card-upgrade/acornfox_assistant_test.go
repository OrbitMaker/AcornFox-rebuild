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
	const keyPath = "/root/deepseek-secret"
	for _, command := range []string{"configure-assistant", "disable-assistant"} {
		t.Run(command, func(t *testing.T) {
			calls := 0
			deps := upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{
				euid: func() int { return 0 },
				configureAssistant: func(_ context.Context, got string) (install.AcornFoxAssistantConfigReceiptV1, error) {
					calls++
					if got != keyPath {
						t.Fatal("key path was not passed privately")
					}
					return install.AcornFoxAssistantConfigReceiptV1{SchemaVersion: 1, State: "ASSISTANT_ENABLED", Configured: true, Enabled: true}, nil
				},
				disableAssistant: func(context.Context) (install.AcornFoxAssistantConfigReceiptV1, error) {
					calls++
					return install.AcornFoxAssistantConfigReceiptV1{SchemaVersion: 1, State: "ASSISTANT_DISABLED", Configured: true}, nil
				},
			}}
			args := []string{command}
			if command == "configure-assistant" {
				args = append(args, "--deepseek-key-file", keyPath)
			}
			var output bytes.Buffer
			if code := runWithDependencies(context.Background(), args, &output, &bytes.Buffer{}, deps); code != exitOK || calls != 1 {
				t.Fatalf("code=%d calls=%d output=%q", code, calls, output.String())
			}
			if strings.Contains(output.String(), keyPath) || strings.Contains(output.String(), "deepseek-secret") {
				t.Fatalf("key path leaked: %q", output.String())
			}
			result := cleanJSON(t, output.Bytes())
			if result["ok"] != true || result["command"] != command {
				t.Fatalf("result=%#v", result)
			}
		})
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
		deps := upgradeDependencies{acornFoxClean: acornFoxCleanDependencies{euid: func() int { return 0 }, configureAssistant: func(context.Context, string) (install.AcornFoxAssistantConfigReceiptV1, error) {
			return install.AcornFoxAssistantConfigReceiptV1{}, test.err
		}}}
		if code := runWithDependencies(context.Background(), []string{"configure-assistant", "--deepseek-key-file", "/root/key"}, &output, &bytes.Buffer{}, deps); code != test.code || cleanJSON(t, output.Bytes())["code"] != test.text || strings.Contains(output.String(), "canary") {
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
