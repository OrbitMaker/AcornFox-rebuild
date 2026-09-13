package main

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

const markerOriginal = "ACORNFOX_ORIGINAL_CONTROLLER_FD_OK_MARKER_V1\n"

func main() {
	var markerFile string
	var lifecycleMode bool
	var floodMode bool
	var probeEarlyCore bool
	var hangMode bool
	var fastExitTail string

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--marker-file":
			if i+1 < len(os.Args) {
				markerFile = os.Args[i+1]
				i++
			}
		case "--lifecycle":
			lifecycleMode = true
		case "--flood-stdout":
			floodMode = true
		case "--probe-early-core":
			probeEarlyCore = true
		case "--hang":
			hangMode = true
		case "--fast-exit-tail":
			if i+1 < len(os.Args) {
				fastExitTail = os.Args[i+1]
				i++
			}
		}
	}

	if fastExitTail != "" {
		fmt.Print(fastExitTail)
		os.Exit(0)
	}

	if hangMode {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM)
		select {}
	}

	// In Darwin launch, FD 3 is the child lifecycle socket
	lifecycleFD := os.NewFile(3, "lifecycle")

	if floodMode {
		// Write 256 KiB to stdout to test capped pipe drain
		bigData := bytes.Repeat([]byte("A"), 256*1024)
		_, _ = os.Stdout.Write(bigData)
		if markerFile != "" {
			_ = os.WriteFile(markerFile, []byte(markerOriginal), 0644)
		}
		// Wait for EOF on lifecycle socket
		buf := make([]byte, 1)
		_, _ = lifecycleFD.Read(buf)
		os.Exit(0)
	}

	if probeEarlyCore {
		// Attempt early access before reading admission
		// Non-blocking read: if no admission frame present, reject with 42
		_ = syscall.SetNonblock(3, true)
		buf := make([]byte, 8)
		n, err := syscall.Read(3, buf)
		if err != nil || n == 0 || string(buf[:n]) != "admit-v1" {
			os.Exit(42)
		}
	}

	if lifecycleMode {
		// Read admission frame
		buf := make([]byte, 8)
		n, err := lifecycleFD.Read(buf)
		if err != nil || n == 0 || string(buf[:n]) != "admit-v1" {
			os.Exit(43)
		}
		if markerFile != "" {
			_ = os.WriteFile(markerFile, []byte(markerOriginal), 0644)
		}
		// Wait for parent EOF (cooperative stop)
		waitBuf := make([]byte, 1)
		_, _ = lifecycleFD.Read(waitBuf)
		os.Exit(0)
	}

	// Normal run: write marker if requested
	if markerFile != "" {
		if err := os.WriteFile(markerFile, []byte(markerOriginal), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write marker: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Print(markerOriginal)
	_ = syscall.Close(3)
	os.Exit(0)
}
