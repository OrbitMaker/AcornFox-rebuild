package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	mode := flag.String("mode", "echo", "run mode")
	flag.Parse()
	switch *mode {
	case "version":
		fmt.Println("1.0.0")
	case "echo":
		fmt.Println("fixture adapter ready")
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %s\n", *mode)
		os.Exit(1)
	}
}
