package compatibility

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseLegacyAndSemanticVersions(t *testing.T) {
	for raw, want := range map[string]Version{"v1": {1, 0}, "1": {1, 0}, "1.0": {1, 0}, "1.1": {1, 1}} {
		got, err := Parse(raw)
		if err != nil || got != want {
			t.Fatalf("Parse(%q)=%v,%v want %v", raw, got, err, want)
		}
	}
}

func TestNegotiateNAndNMinusOneWithExplicitDegradation(t *testing.T) {
	v10, v11 := Version{1, 0}, Version{1, 1}
	capabilities := map[Version][]string{v10: {"mtls", "task"}, v11: {"mtls", "task", "agent_sequence", "observation_details"}}
	current, err := Negotiate(v10, v11, []Version{v11, v10}, capabilities)
	if err != nil || current.Version != v11 || len(current.DisabledCapabilities) != 0 {
		t.Fatalf("current negotiation=%#v err=%v", current, err)
	}
	oldControlPlane, err := Negotiate(v10, v11, []Version{v10}, capabilities)
	if err != nil || oldControlPlane.Version != v10 || !reflect.DeepEqual(oldControlPlane.DisabledCapabilities, []string{"agent_sequence", "observation_details"}) {
		t.Fatalf("N-1 negotiation=%#v err=%v", oldControlPlane, err)
	}
	if _, err := Negotiate(Version{2, 0}, Version{2, 0}, []Version{v11, v10}, capabilities); !errors.Is(err, ErrIncompatibleMajor) {
		t.Fatalf("major mismatch error=%v", err)
	}
}
