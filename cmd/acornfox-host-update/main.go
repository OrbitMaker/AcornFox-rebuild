package main

import (
	"context"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: acornfox-host-update managed-child | acornfox-host-launcher <slot-start|slot-stop|slot-probe>\n")
		os.Exit(2)
	}

	subcmd := os.Args[1]

	opts := getProductionControllerOptions()
	if !opts.AllowNonRoot && os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "acornfox-host-update: root privileges required\n")
		os.Exit(1)
	}

	ctx := context.Background()

	switch subcmd {
	case "managed-child":
		lifecycleFile := os.NewFile(4, "lifecycle-socket")
		if lifecycleFile == nil {
			fmt.Fprintf(os.Stderr, "acornfox-host-update: lifecycle descriptor missing\n")
			os.Exit(1)
		}
		defer lifecycleFile.Close()

		if err := RunManagedChild(ctx, lifecycleFile, opts); err != nil {
			fmt.Fprintf(os.Stderr, "acornfox-host-update: controller error: %v\n", err)
			os.Exit(1)
		}

	case "slot-start", "slot-stop", "slot-probe":
		if err := HandleLauncherCommand(ctx, subcmd); err != nil {
			fmt.Fprintf(os.Stderr, "acornfox-host-launcher: %s failed: %v\n", subcmd, err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "acornfox-host-update: unrecognized command %q\n", subcmd)
		os.Exit(2)
	}
}
