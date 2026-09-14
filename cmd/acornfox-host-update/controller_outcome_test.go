package main

import (
	"github.com/open-card/open-card/internal/hostlifecycle"
	"strings"
	"testing"
)

func TestLifecycleTerminalOutcomeUsesExistingVocabulary(t *testing.T) {
	for _, outcome := range []string{"backend-rolled-back", "host-rolled-back", "backend-rejected"} {
		t.Run(outcome, func(t *testing.T) {
			state, reason := lifecycleOutcome(outcome, "ok")
			expected := "failed"
			if outcome == "backend-rejected" {
				expected = "ineligible"
			}
			if state != "idle" || reason != expected {
				t.Fatal(state, reason)
			}
			frame := &hostlifecycle.ResultFrame{Type: hostlifecycle.FrameTypeResult, SchemaVersion: 1, Nonce: strings.Repeat("a", 64), Operation: hostlifecycle.OpAdvance, State: state, ReasonCode: reason, Version: "1.0.0", SlotID: strings.Repeat("b", 64)}
			raw, err := hostlifecycle.EncodeResult(frame)
			if err != nil {
				t.Fatal(err)
			}
			got, err := hostlifecycle.DecodeResult(raw)
			if err != nil || *got != *frame {
				t.Fatal("existing decoder rejected terminal result", err)
			}
		})
	}
	state, reason := lifecycleOutcome("unknown-state", "ok")
	if state != "unknown-state" || reason != "ok" {
		t.Fatal("unknown outcome was hidden")
	}
}
