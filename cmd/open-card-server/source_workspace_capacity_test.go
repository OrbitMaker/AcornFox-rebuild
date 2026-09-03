package main

import (
	"testing"

	"github.com/open-card/open-card/internal/acornfoxenv"
)

func TestSourceWorkspaceCapacityConfigRejectsInvalidValues(t *testing.T) {
	values := map[string]string{
		"OPEN_CARD_SOURCE_WORKSPACE_CAPACITY_BYTES":              "1024",
		"OPEN_CARD_SOURCE_WORKSPACE_CAPACITY_ENTRIES":            "200",
		"OPEN_CARD_SOURCE_WORKSPACE_OPERATIONAL_RESERVE_BYTES":   "2048",
		"OPEN_CARD_SOURCE_WORKSPACE_OPERATIONAL_RESERVE_ENTRIES": "300",
	}
	getenv := func(key acornfoxenv.Key) string { return values[acornfoxenv.Environment{}.Name(key)] }
	bytes, entries, reserveBytes, reserveEntries, err := sourceWorkspaceCapacityConfig(getenv)
	if err != nil || bytes != 1024 || entries != 200 || reserveBytes != 2048 || reserveEntries != 300 {
		t.Fatalf("parsed source workspace config bytes=%d entries=%d reserveBytes=%d reserveEntries=%d err=%v", bytes, entries, reserveBytes, reserveEntries, err)
	}
	for _, value := range []string{"-1", "not-a-number", "999999999999999999999999"} {
		values["OPEN_CARD_SOURCE_WORKSPACE_CAPACITY_BYTES"] = value
		if _, _, _, _, err := sourceWorkspaceCapacityConfig(getenv); err == nil {
			t.Fatal("invalid source workspace environment was accepted")
		}
	}
}
