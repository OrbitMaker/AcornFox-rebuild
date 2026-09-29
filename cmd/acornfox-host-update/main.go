package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "native-bootstrap-repair-child" {
		if err := runNativeBootstrapRepairChild(context.Background(), os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "acornfox-host-update: owned bootstrap repair child refused or outcome unknown")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "native-bootstrap-repair" {
		if os.Geteuid() != 0 || os.Getegid() != 0 {
			fmt.Fprintln(os.Stderr, "acornfox-host-update: root required for owned bootstrap repair")
			os.Exit(1)
		}
		if err := runNativeBootstrapRepair(context.Background(), os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, nativeBootstrapRepairFailureMessage(err))
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "native-docker-prepare" {
		if os.Geteuid() != 0 || os.Getegid() != 0 {
			fmt.Fprintln(os.Stderr, "acornfox-host-update: root required for Native Docker preparation")
			os.Exit(1)
		}
		if err := runNativeDockerPrepare(context.Background(), os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, nativeDockerPrepareFailureMessage(err))
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "native-first-core" {
		if os.Geteuid() != 0 || os.Getegid() != 0 {
			fmt.Fprintln(os.Stderr, "acornfox-host-update: root privileges required for first Native Core start")
			os.Exit(1)
		}
		if err := runNativeFirstCore(context.Background(), os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, nativeFirstCoreFailureMessage(err))
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "native-host-prepare" {
		if os.Geteuid() != 0 || os.Getegid() != 0 {
			fmt.Fprintln(os.Stderr, "acornfox-host-update: root privileges required for Native host preparation")
			os.Exit(1)
		}
		if err := runNativeHostPrepare(context.Background(), os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, nativeHostPrepareFailureMessage(err))
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "native-stage" {
		if os.Geteuid() != 0 || os.Getegid() != 0 {
			fmt.Fprintln(os.Stderr, "acornfox-host-update: root required for Native staging")
			os.Exit(1)
		}
		if err := runNativeStage(context.Background(), os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "acornfox-host-update: Native stage unavailable or incomplete; inactive bytes preserved for inspection")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "native-sqlite-restore-child" {
		if err := runNativeSQLiteRestoreChild(context.Background(), os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "acornfox-host-update: Native SQLite restore child failed; preserve quarantine")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "native-sqlite-restore" {
		if os.Geteuid() != 0 || os.Getegid() != 0 {
			fmt.Fprintln(os.Stderr, "acornfox-host-update: root privileges required for Native SQLite restore")
			os.Exit(1)
		}
		if err := runNativeSQLiteRestore(context.Background(), os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, nativeSQLiteRestoreFailureMessage(err))
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "native-core-launch" {
		if os.Geteuid() != 0 || os.Getegid() != 0 {
			fmt.Fprintln(os.Stderr, "acornfox-host-update: root privileges required for Native Core launch")
			os.Exit(1)
		}
		launchContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := runNativeCoreLaunch(launchContext, os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "acornfox-host-update: Native Core launch failed; preserve launch reservation and inspect before retry")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "native-sqlite-backup-child" {
		if err := runNativeSQLiteBackupChild(context.Background(), os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "acornfox-host-update: Native SQLite backup child failed")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "native-sqlite-backup" {
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "acornfox-host-update: root privileges required for Native SQLite backup")
			os.Exit(1)
		}
		if err := runNativeSQLiteBackup(context.Background(), os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, nativeSQLiteFailureMessage(err))
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "native-publish-binding" {
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "acornfox-host-update: root privileges required for Native binding publication")
			os.Exit(1)
		}
		if err := runNativePublishBinding(context.Background(), os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "acornfox-host-update: Native binding publication failed: %v\n", err)
			os.Exit(1)
		}
		return
	}
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
		lifecycleConn, err := adoptLifecycleFile(lifecycleFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "acornfox-host-update: invalid lifecycle descriptor")
			os.Exit(1)
		}
		defer lifecycleConn.Close()

		if err := RunManagedChild(ctx, lifecycleConn, opts); err != nil {
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
