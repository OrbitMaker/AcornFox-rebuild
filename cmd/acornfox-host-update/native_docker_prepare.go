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

var nativeDockerStage = regexp.MustCompile(`^ready-[0-9a-f]{32}$`)

func parseNativeDockerPrepareArgs(args []string) (string, error) {
	fs := flag.NewFlagSet("native-docker-prepare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stage := fs.String("stage", "", "fixed complete Native ready stage")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() != 0 || filepath.Dir(*stage) != unifiedinstall.UnifiedPrivateStageRoot || filepath.Clean(*stage) != *stage || !nativeDockerStage.MatchString(filepath.Base(*stage)) {
		return "", errors.New("one fixed ready stage is required")
	}
	return *stage, nil
}

func runNativeDockerPrepare(ctx context.Context, args []string, out io.Writer) error {
	if out == nil {
		return unifiedinstall.ErrIncomplete
	}
	stage, err := parseNativeDockerPrepareArgs(args)
	if err != nil {
		return err
	}
	result, err := unifiedinstall.PrepareNativeDocker(ctx, stage)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return errors.Join(unifiedinstall.ErrNativeDockerPrepareUnknown, err)
	}
	return nil
}

func nativeDockerPrepareFailureMessage(err error) string {
	if errors.Is(err, unifiedinstall.ErrNativeDockerPrepareUnknown) {
		return "acornfox-host-update: Docker preparation outcome unknown; inspect fixed intent and actual daemon before retry"
	}
	return "acornfox-host-update: Docker preparation refused before a verified receipt"
}
