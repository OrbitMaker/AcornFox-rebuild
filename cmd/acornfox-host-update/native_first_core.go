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

var nativeFirstCoreStage = regexp.MustCompile(`^ready-[0-9a-f]{32}$`)

func parseNativeFirstCoreArgs(args []string) (string, error) {
	fs := flag.NewFlagSet("native-first-core", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stage := fs.String("stage", "", "fixed root-owned Native ready stage")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() != 0 || filepath.Dir(*stage) != unifiedinstall.UnifiedPrivateStageRoot || filepath.Clean(*stage) != *stage || !nativeFirstCoreStage.MatchString(filepath.Base(*stage)) {
		return "", errors.New("one fixed ready stage required")
	}
	return *stage, nil
}

func runNativeFirstCore(ctx context.Context, args []string, output io.Writer) error {
	if output == nil {
		return unifiedinstall.ErrIncomplete
	}
	stage, err := parseNativeFirstCoreArgs(args)
	if err != nil {
		return err
	}
	result, err := unifiedinstall.StartNativeFirstCore(ctx, stage)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		return errors.Join(unifiedinstall.ErrNativeFirstCoreUnknown, err)
	}
	return nil
}

func nativeFirstCoreFailureMessage(err error) string {
	if errors.Is(err, unifiedinstall.ErrNativeFirstCoreUnknown) {
		return "acornfox-host-update: first Core start outcome unknown; inspect current, credential and unit state before retry"
	}
	return "acornfox-host-update: first Core start refused before a verified result"
}
