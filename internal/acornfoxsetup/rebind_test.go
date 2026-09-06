package acornfoxsetup

import (
	"bytes"
	"reflect"
	"slices"
	"testing"

	"github.com/open-card/open-card/internal/acornfoxenv"
)

func TestRebindVersionPreservesRuntime(t *testing.T) {
	bundle, input := generate(t), inputs()
	// Validate permits arbitrary file order; rebinding must also use paths.
	slices.Reverse(bundle.Files)
	before := clone(bundle)
	const version = "v1.0.0-beta.2"
	next, nextInput, err := RebindVersion(bundle, input, version)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(next, nextInput); err != nil {
		t.Fatal(err)
	}
	wantInput := input
	wantInput.Version = version
	if !reflect.DeepEqual(nextInput, wantInput) {
		t.Fatal("rebind changed inputs other than version")
	}
	if !reflect.DeepEqual(bundle, before) || input.Version != inputs().Version {
		t.Fatal("rebind mutated caller state")
	}
	if len(next.Files) != len(bundle.Files) {
		t.Fatal("rebind changed file closure")
	}
	for i, old := range bundle.Files {
		got := next.Files[i]
		if got.Path != old.Path || got.Mode != old.Mode || got.Owner != old.Owner || got.Group != old.Group {
			t.Fatal("rebind changed file order or metadata")
		}
		if old.Path != AgentEnvironment && !bytes.Equal(got.Data, old.Data) {
			t.Fatalf("rebind changed non-version file %s", old.Path)
		}
	}
	env, err := acornfoxenv.ResolveEnviron(acornfoxenv.ProcessAgent, "acornfox", envLines(t, file(next, AgentEnvironment)))
	if err != nil {
		t.Fatal(err)
	}
	if env.Get(acornfoxenv.AgentVersion) != version {
		t.Fatal("agent did not receive next version")
	}
	// A same-version rebind is also valid and preserves every byte.
	same, _, err := RebindVersion(next, nextInput, version)
	if err != nil || !reflect.DeepEqual(same, next) {
		t.Fatal("same-version rebind changed runtime")
	}
}

func TestRebindVersionRejectsInvalidState(t *testing.T) {
	base := generate(t)
	for _, name := range []string{"invalid-old-bundle", "invalid-old-input", "mismatched-old-version", "invalid-next-version"} {
		t.Run(name, func(t *testing.T) {
			bundle, input, version := clone(base), inputs(), "v1.0.0-beta.2"
			switch name {
			case "invalid-old-bundle":
				file(bundle, AgentEnvironment)[0] ^= 1
			case "invalid-old-input":
				input.Origin = "http://console.example.com"
			case "mismatched-old-version":
				input.Version = version
			case "invalid-next-version":
				version = "bad\nversion"
			}
			before := clone(bundle)
			next, nextInput, err := RebindVersion(bundle, input, version)
			if err == nil {
				t.Fatal("accepted invalid state")
			}
			if !reflect.DeepEqual(next, Bundle{}) || !reflect.DeepEqual(nextInput, Inputs{}) {
				t.Fatal("failure returned runtime material")
			}
			if !reflect.DeepEqual(bundle, before) {
				t.Fatal("failed rebind mutated caller bundle")
			}
		})
	}
}

func TestRebindVersionDoesNotAlias(t *testing.T) {
	for _, direction := range []string{"output-to-input", "input-to-output"} {
		t.Run(direction, func(t *testing.T) {
			bundle, input := generate(t), inputs()
			next, nextInput, err := RebindVersion(bundle, input, "v1.0.0-beta.2")
			if err != nil {
				t.Fatal(err)
			}
			mutateBundle, mutateInput := &next, &nextInput
			observeBundle, observeInput := &bundle, &input
			if direction == "input-to-output" {
				mutateBundle, mutateInput = &bundle, &input
				observeBundle, observeInput = &next, &nextInput
			}
			beforeBundle := clone(*observeBundle)
			beforeInput := *observeInput
			beforeInput.ResolverEndpoints = slices.Clone(observeInput.ResolverEndpoints)
			for i := range mutateBundle.Files {
				mutateBundle.Files[i].Data[0] ^= 1
				mutateBundle.Files[i].Mode = 0
			}
			mutateInput.ResolverEndpoints[0] = "9.9.9.9:53"
			if !reflect.DeepEqual(*observeBundle, beforeBundle) || !reflect.DeepEqual(*observeInput, beforeInput) {
				t.Fatal("rebound state shares mutable storage")
			}
		})
	}
}
