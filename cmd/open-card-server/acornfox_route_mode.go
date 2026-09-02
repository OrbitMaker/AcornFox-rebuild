package main

import (
	"fmt"
	"strings"
)

// acornFoxMigrationCompatibilityMode recognizes one intentionally explicit
// upgraded-install escape hatch. Empty is clean mode; accepting aliases such
// as true/1 would make an accidental environment value publish legacy routes.
func acornFoxMigrationCompatibilityMode(value string) (bool, error) {
	value = strings.TrimSpace(value)
	switch value {
	case "":
		return false, nil
	case "enabled":
		return true, nil
	default:
		return false, fmt.Errorf("ACORNFOX_MIGRATION_COMPATIBILITY must be empty or enabled")
	}
}
