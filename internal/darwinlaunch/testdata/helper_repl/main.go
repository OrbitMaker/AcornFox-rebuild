package main

import (
	"fmt"
	"os"
)

const markerReplacement = "ACORNFOX_REPLACEMENT_CONTROLLER_MARKER_V2\n"

func main() {
	var markerFile string
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "--marker-file" && i+1 < len(os.Args) {
			markerFile = os.Args[i+1]
			i++
		}
	}
	if markerFile != "" {
		_ = os.WriteFile(markerFile, []byte(markerReplacement), 0644)
	}
	fmt.Print(markerReplacement)
	os.Exit(0)
}
