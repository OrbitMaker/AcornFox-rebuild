// Test-only cross-platform helper. Never distributed as an AcornFox launcher.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "fixture-start" {
		os.Exit(3)
	}
	fmt.Print("fixture-started")
}
