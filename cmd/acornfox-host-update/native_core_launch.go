package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"path/filepath"

	"github.com/open-card/open-card/internal/unifiedinstall"
)

func runNativeCoreLaunch(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("native-core-launch", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var stage string
	fs.StringVar(&stage, "stage", "", "fixed trusted Native ready stage")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || filepath.Dir(stage) != unifiedinstall.UnifiedPrivateStageRoot || filepath.Clean(stage) != stage {
		return errors.New("fixed ready stage is required")
	}
	return unifiedinstall.LaunchNativeCore(ctx, stage, stdout)
}
