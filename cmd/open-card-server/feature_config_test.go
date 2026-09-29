package main

import "testing"

func TestFeatureHierarchyFailsClosedForM4Dependencies(t *testing.T) {
	if err := validateFeatureHierarchy(true, true, true, true, true, true, true, false); err != nil {
		t.Fatalf("complete M4/M5 composition rejected: %v", err)
	}
	// Retired M6 flag must log warning, be treated as false, and not reject valid composition
	if err := validateFeatureHierarchy(true, true, true, true, true, true, true, true); err != nil {
		t.Fatalf("retired M6 flag caused composition rejection: %v", err)
	}
	// M5 disabled without M6 is a valid composition
	if err := validateFeatureHierarchy(true, true, true, true, true, true, false, false); err != nil {
		t.Fatalf("valid composition without M5 rejected: %v", err)
	}
	// M5 disabled with legacy M6 flag must also be accepted because M6 is retired
	if err := validateFeatureHierarchy(true, true, true, true, true, true, false, true); err != nil {
		t.Fatalf("valid composition without M5 with retired M6 rejected: %v", err)
	}

	invalid := [][8]bool{
		{false, true, true, true, true, true, true, false},
		{true, false, true, true, true, true, true, false},
		{true, true, false, false, true, false, true, false},
		{true, true, true, false, true, true, true, false},
		{true, true, true, true, false, true, true, false},
		{true, true, true, true, false, false, true, false},
	}
	for _, flags := range invalid {
		for _, retiredAI := range []bool{false, true} {
			flags[7] = retiredAI
			if err := validateFeatureHierarchy(flags[0], flags[1], flags[2], flags[3], flags[4], flags[5], flags[6], flags[7]); err == nil {
				t.Fatalf("invalid feature hierarchy accepted: %#v", flags)
			}
		}
	}
	if err := validateFeatureHierarchy(false, false, false, false, false, false, false, false); err != nil {
		t.Fatalf("legacy bootstrap without optional milestones was rejected: %v", err)
	}
}
