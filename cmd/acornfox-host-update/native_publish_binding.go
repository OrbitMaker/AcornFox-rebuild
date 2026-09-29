package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"strings"

	"github.com/open-card/open-card/internal/unifiedinstall"
)

// native-publish-binding is deliberately separate from the older managed-child
// and slot launcher paths. All hashes and UIDs come from protected facts, never
// these PID selector flags.
func parseNativeBindingArgs(args []string) (unifiedinstall.NativeBindingRequest, error) {
	var out unifiedinstall.NativeBindingRequest
	const maxPID = int(^uint32(0) >> 1)
	fs := flag.NewFlagSet("native-publish-binding", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var core, container, source, gateway int
	fs.StringVar(&out.StagePath, "stage", "", "root-owned complete unified ready stage")
	fs.IntVar(&core, "core-pid", 0, "already started Core PID")
	fs.IntVar(&container, "container-pid", 0, "already started Container PID")
	fs.IntVar(&source, "source-pid", 0, "already started Source adapter PID")
	fs.IntVar(&gateway, "gateway-pid", 0, "already started Gateway adapter PID")
	if err := fs.Parse(args); err != nil {
		return out, err
	}
	if fs.NArg() != 0 || filepath.Dir(out.StagePath) != unifiedinstall.UnifiedPrivateStageRoot || filepath.Clean(out.StagePath) != out.StagePath || !strings.HasPrefix(filepath.Base(out.StagePath), "ready-") || core <= 0 || container <= 0 || source <= 0 || gateway <= 0 || core > maxPID || container > maxPID || source > maxPID || gateway > maxPID || core == container || core == source || core == gateway || container == source || container == gateway || source == gateway {
		return out, errors.New("native-publish-binding requires one fixed ready stage and four distinct positive PIDs")
	}
	out.CorePID, out.ContainerPID, out.SourcePID, out.GatewayPID = int32(core), int32(container), int32(source), int32(gateway)
	return out, nil
}

func runNativePublishBinding(ctx context.Context, args []string, stdout io.Writer) error {
	request, err := parseNativeBindingArgs(args)
	if err != nil {
		return err
	}
	result, err := unifiedinstall.PublishNativeBinding(ctx, request)
	if err != nil {
		return err
	}
	return writeNativeBindingResult(stdout, result)
}

func writeNativeBindingResult(stdout io.Writer, result unifiedinstall.NativeBindingResult) error {
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return errors.Join(unifiedinstall.ErrBindingCommitUnknown, err)
	}
	return nil
}
