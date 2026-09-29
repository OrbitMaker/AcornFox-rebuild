package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"regexp"

	"github.com/open-card/open-card/internal/unifiedinstall"
)

var nativePrepareStage = regexp.MustCompile(`^ready-[0-9a-f]{32}$`)

func parseNativeHostPrepareArgs(args []string) (string, error) {
	fs := flag.NewFlagSet("native-host-prepare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stage := fs.String("stage", "", "root-protected complete Native ready stage")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() != 0 || filepath.Dir(*stage) != unifiedinstall.UnifiedPrivateStageRoot || filepath.Clean(*stage) != *stage || !nativePrepareStage.MatchString(filepath.Base(*stage)) {
		return "", errors.New("one fixed Native ready stage is required")
	}
	return *stage, nil
}

func runNativeHostPrepare(ctx context.Context, args []string, stdout io.Writer) error {
	if stdout == nil {
		return errors.New("Native host prepare output is required")
	}
	stage, err := parseNativeHostPrepareArgs(args)
	if err != nil {
		return err
	}
	prepared, err := unifiedinstall.PrepareNativeHost(ctx, stage)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdout).Encode(prepared); err != nil {
		return errors.Join(unifiedinstall.ErrNativeHostPrepareUnknown, err)
	}
	return nil
}

func nativeHostPrepareFailureMessage(err error) string {
	if errors.Is(err, unifiedinstall.ErrNativeHostPrepareUnknown) {
		return "acornfox-host-update: Native host preparation outcome unknown; preserve the private intent and inspect before retry"
	}
	return "acornfox-host-update: Native host preparation refused before a verified completion receipt"
}
