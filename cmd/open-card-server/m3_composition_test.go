package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestM3CompositionFailsClosedOutsideTheCleanWorkerFixtureBoundary(t *testing.T) {
	allowFixture := func(string) error { return nil }
	if _, err := resolveM3Composition("", m3FixtureTaskPrefix, false, allowFixture); err == nil {
		t.Fatal("implicit M3 composition was accepted")
	}
	if _, err := resolveM3Composition(m3CompositionFixture, "ordinary-host", false, allowFixture); err == nil {
		t.Fatal("ordinary host fixture composition was accepted")
	}
	if _, err := resolveM3Composition(m3CompositionFixture, m3FixtureTaskPrefix, false, func(string) error { return errors.New("missing marker") }); err == nil {
		t.Fatal("fixture composition without a clean-worker marker was accepted")
	}
	if _, err := resolveM3Composition(m3CompositionFixture, m3FixtureTaskPrefix, false, allowFixture); err != nil {
		t.Fatalf("clean-worker fixture composition rejected: %v", err)
	}
	if _, err := resolveM3Composition(m3CompositionProduction, "opencard-host", false, nil); err == nil {
		t.Fatal("production composition without a convergence provider was accepted")
	}
	if mode, err := resolveM3Composition(m3CompositionProduction, "opencard-host", true, nil); err != nil || mode != m3CompositionProduction {
		t.Fatalf("available production composition mode=%q err=%v", mode, err)
	}
}

func TestM3FixtureMarkerValidationIsStrict(t *testing.T) {
	valid := m3FixtureMarkerFact{Mode: 0o644, OwnerID: 0, Content: m3FixtureMarkerValue + "\n"}
	if err := validateM3FixtureMarker(valid); err != nil {
		t.Fatalf("valid fixture marker rejected: %v", err)
	}
	for name, fact := range map[string]m3FixtureMarkerFact{
		"symlink":        {Mode: os.ModeSymlink | 0o644, OwnerID: 0, Content: m3FixtureMarkerValue},
		"directory":      {Mode: os.ModeDir | 0o755, OwnerID: 0, Content: m3FixtureMarkerValue},
		"unsafe mode":    {Mode: 0o664, OwnerID: 0, Content: m3FixtureMarkerValue},
		"wrong owner":    {Mode: 0o644, OwnerID: 1000, Content: m3FixtureMarkerValue},
		"wrong identity": {Mode: 0o644, OwnerID: 0, Content: "ordinary-host"},
	} {
		if err := validateM3FixtureMarker(fact); err == nil {
			t.Fatalf("%s marker was accepted", name)
		}
	}
}

func TestMainEntrypointHasNoFixtureProviderWiring(t *testing.T) {
	for _, filename := range []string{"main.go", "m3_adapters.go"} {
		source, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		text := string(source)
		for _, forbidden := range []string{"dnsfixture", "certfixture"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s still imports fixture provider %q", filename, forbidden)
			}
		}
	}
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "resolveM3Composition") || !strings.Contains(text, "authorizeM3FixtureHost") || !strings.Contains(text, "newM3FixtureAccessController") {
		t.Fatal("main entrypoint does not select explicit M3 composition")
	}
}
