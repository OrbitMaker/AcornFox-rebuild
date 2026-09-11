//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() { fmt.Fprintln(os.Stderr, "acornfox guest update requires Linux"); os.Exit(1) }
