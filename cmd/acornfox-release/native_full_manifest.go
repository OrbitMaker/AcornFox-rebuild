package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"path/filepath"

	"github.com/open-card/open-card/internal/acornfoxrelease"
)

// native-full-manifest consumes pinned, already-built product and material
// bytes. It does not run the installer, fabricate role facts, or fetch tools.
func runNativeFullManifest(ctx context.Context, args []string, out, diagnostic io.Writer) error {
	fs := flag.NewFlagSet("native-full-manifest", flag.ContinueOnError)
	fs.SetOutput(diagnostic)
	var productRoot, productReceipt, productSHA, materialRoot, materials, materialSHA, output string
	for _, item := range []struct {
		name  string
		value *string
	}{
		{"product-root", &productRoot}, {"product-receipt", &productReceipt}, {"product-receipt-sha256", &productSHA},
		{"material-root", &materialRoot}, {"materials", &materials}, {"materials-sha256", &materialSHA}, {"output", &output},
	} {
		fs.StringVar(item.value, item.name, "", item.name)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected Native manifest positional arguments")
	}
	for _, path := range []string{productRoot, productReceipt, materialRoot, materials, output} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("Native manifest paths must be absolute and clean")
		}
	}
	if productSHA == "" || materialSHA == "" {
		return errors.New("both external SHA pins are required")
	}
	productBytes, err := readBuildInput(productReceipt)
	if err != nil {
		return err
	}
	materialBytes, err := readBuildInput(materials)
	if err != nil {
		return err
	}
	result, err := acornfoxrelease.BuildNativeFullManifestV1(ctx, acornfoxrelease.NativeFullManifestRequest{
		ProductRoot: productRoot, ProductResponse: productBytes, ProductResponseSHA256: productSHA,
		MaterialRoot: materialRoot, MaterialInputs: materialBytes, MaterialInputsSHA256: materialSHA, Output: output,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}
