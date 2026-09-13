package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/open-card/open-card/internal/darwinlaunch"
)

func main() {
	fmt.Printf("mode=%s\n", darwinlaunch.DistributionMode)

	// Call with nil FD to check constructor availability without starting any process or VM
	_, _, errController := darwinlaunch.PrepareTestDistributionController(context.Background(), nil)
	_, _, errLauncher := darwinlaunch.PrepareTestDistributionSlotLauncher(context.Background(), nil, darwinlaunch.LauncherActionStart)

	if darwinlaunch.DistributionMode == "production" {
		if !errors.Is(errController, darwinlaunch.ErrTestDistributionUnavailable) {
			fmt.Fprintf(os.Stderr, "expected ErrTestDistributionUnavailable for controller, got: %v\n", errController)
			os.Exit(1)
		}
		if !errors.Is(errLauncher, darwinlaunch.ErrTestDistributionUnavailable) {
			fmt.Fprintf(os.Stderr, "expected ErrTestDistributionUnavailable for launcher, got: %v\n", errLauncher)
			os.Exit(2)
		}
		fmt.Println("constructors=unavailable_in_production")
	} else if darwinlaunch.DistributionMode == "test-distribution" {
		if !errors.Is(errController, os.ErrInvalid) {
			fmt.Fprintf(os.Stderr, "expected os.ErrInvalid for nil FD controller, got: %v\n", errController)
			os.Exit(3)
		}
		if !errors.Is(errLauncher, os.ErrInvalid) {
			fmt.Fprintf(os.Stderr, "expected os.ErrInvalid for nil FD launcher, got: %v\n", errLauncher)
			os.Exit(4)
		}
		fmt.Println("constructors=available_in_test_distribution")
	} else {
		fmt.Fprintf(os.Stderr, "unknown mode: %s\n", darwinlaunch.DistributionMode)
		os.Exit(5)
	}
}
