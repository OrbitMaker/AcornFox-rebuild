package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"path/filepath"

	"github.com/open-card/open-card/internal/unifiedinstall"
)

func runNativeBootstrapRepair(ctx context.Context, args []string, stdout io.Writer) error {
	if ctx == nil || stdout == nil || len(args) == 0 {
		return unifiedinstall.ErrIncomplete
	}
	switch args[0] {
	case "begin", "stage":
		fs := flag.NewFlagSet("native-bootstrap-repair "+args[0], flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		bundle := fs.String("bundle-id", "", "one fixed private Source16 incoming bundle")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || !unifiedinstall.ValidNativeBundleID(*bundle) {
			return errors.New("one fixed bootstrap repair bundle ID is required")
		}
		var result any
		var err error
		if args[0] == "begin" {
			result, err = unifiedinstall.BeginNativeBootstrapRepair(ctx, *bundle)
		} else {
			result, err = unifiedinstall.StageNativeBootstrapRepair(ctx, *bundle)
		}
		if err != nil {
			return err
		}
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			return errors.Join(unifiedinstall.ErrBootstrapRepairUnknown, err)
		}
		return nil
	case "continue", "recover":
		fs := flag.NewFlagSet("native-bootstrap-repair "+args[0], flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		stage := fs.String("stage", "", "one fixed trusted new ready stage")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || !nativeFirstCoreStage.MatchString(filepath.Base(*stage)) || filepath.Dir(*stage) != unifiedinstall.UnifiedPrivateStageRoot || filepath.Clean(*stage) != *stage {
			return errors.New("one exact bootstrap repair ready stage is required")
		}
		if args[0] == "continue" {
			result, err := unifiedinstall.ContinueNativeBootstrapRepair(ctx, *stage)
			if err != nil {
				return err
			}
			return json.NewEncoder(stdout).Encode(result)
		}
		result, err := unifiedinstall.RecoverNativeBootstrapRepair(ctx, *stage)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(result)
	default:
		return errors.New("unknown fixed bootstrap repair phase")
	}
}

func runNativeBootstrapRepairChild(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 1 || args[0] != "backup" && args[0] != "restore" {
		return unifiedinstall.ErrIncomplete
	}
	return unifiedinstall.RunNativeBootstrapRepairChild(ctx, args[0], stdout)
}

func nativeBootstrapRepairFailureMessage(err error) string {
	if errors.Is(err, unifiedinstall.ErrBootstrapRepairRestoreUnapproved) {
		return "acornfox-host-update: restore was not approved; original database identity retained; keep repair gate closed and inspect the attempt"
	}
	if errors.Is(err, unifiedinstall.ErrBootstrapRepairRestoreUncertain) {
		return "acornfox-host-update: restore approval or replacement outcome unknown; keep repair gate closed and preserve quarantine"
	}
	return "acornfox-host-update: owned bootstrap repair unavailable or outcome unknown; preserve fixed state"
}
