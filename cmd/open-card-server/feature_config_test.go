package main

import "testing"

func TestFeatureHierarchyFailsClosedForM4Dependencies(t *testing.T) {
	if err := validateFeatureHierarchy(true, true, true, true, true, true, true, true); err != nil {
		t.Fatalf("complete M4 composition rejected: %v", err)
	}
	invalid := [][8]bool{
		{false, true, true, true, true, true, true, true},
		{true, false, true, true, true, true, true, true},
		{true, true, false, false, true, false, true, true},
		{true, true, true, false, true, true, true, true},
		{true, true, true, true, false, true, true, true},
		{true, true, true, true, false, false, true, true},
		{true, true, true, true, true, true, false, true},
	}
	for _, flags := range invalid {
		if err := validateFeatureHierarchy(flags[0], flags[1], flags[2], flags[3], flags[4], flags[5], flags[6], flags[7]); err == nil {
			t.Fatalf("invalid feature hierarchy accepted: %#v", flags)
		}
	}
	if err := validateFeatureHierarchy(false, false, false, false, false, false, false, false); err != nil {
		t.Fatalf("legacy bootstrap without optional milestones was rejected: %v", err)
	}
}
