package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/open-card/open-card/internal/unifiedinstall"
)

func parseNativeStageArgs(args []string) (string, error) {
	fs := flag.NewFlagSet("native-stage", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bundle := fs.String("bundle-id", "", "fixed private incoming bundle ID")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || !unifiedinstall.ValidNativeBundleID(*bundle) {
		return "", errors.New("native-stage requires one exact private --bundle-id")
	}
	return *bundle, nil
}

func runNativeStage(ctx context.Context, args []string, output io.Writer) (runErr error) {
	if os.Geteuid() != 0 || os.Getegid() != 0 || output == nil {
		return unifiedinstall.ErrIncomplete
	}
	bundle, err := parseNativeStageArgs(args)
	if err != nil {
		return err
	}
	loaded, err := unifiedinstall.LoadProductionNativeStageInput(ctx, bundle)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := loaded.Close(); closeErr != nil {
			runErr = errors.Join(runErr, unifiedinstall.ErrStageCommitUnknown, closeErr)
		}
	}()
	staged, err := unifiedinstall.StageProductionCandidate(ctx, loaded.Intake)
	if err != nil {
		return err
	}
	provision := []string{}
	for _, fact := range loaded.Intake.Facts.Dependencies {
		if fact.Ownership == "absent" {
			provision = append(provision, fact.Name)
		}
	}
	if err := json.NewEncoder(output).Encode(struct {
		StagePath         string   `json:"stage_path"`
		ReleaseID         string   `json:"release_id"`
		ManifestSHA256    string   `json:"manifest_sha256"`
		ProvisionRequired []string `json:"provision_required"`
		Status            string   `json:"status"`
	}{staged.Path, staged.ReleaseID, staged.ManifestSHA256, provision, "inactive_staged"}); err != nil {
		return errors.Join(unifiedinstall.ErrStageCommitUnknown, err)
	}
	return nil
}
