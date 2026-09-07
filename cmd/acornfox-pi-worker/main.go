// Command acornfox-pi-worker runs the unprivileged, single-active Pi process
// boundary. It has no database or host-operation integration.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/open-card/open-card/internal/piworker"
)

const configCredentialName = "pi-config"
const systemCredentialDirectory = "/run/credentials/acornfox-pi-worker.service"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stderr, os.Geteuid, os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "acornfox-pi-worker:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, _ io.Writer, euid func() int, getenv func(string) string) error {
	if euid() == 0 {
		return errors.New("refusing to run as root")
	}
	credentialDirectory := filepath.Clean(getenv("CREDENTIALS_DIRECTORY"))
	if credentialDirectory != systemCredentialDirectory || strings.ContainsRune(credentialDirectory, 0) {
		return errors.New("systemd credential directory is unavailable")
	}
	configPath, err := parseConfigArgument(args, credentialDirectory)
	if err != nil {
		return err
	}
	if err := validateConfigCredential(configPath, os.Lstat); err != nil {
		return err
	}
	config, err := piworker.LoadConfig(configPath)
	if err != nil {
		return errors.New("load worker configuration failed")
	}
	server, err := piworker.NewServer(config, credentialDirectory)
	if err != nil {
		return errors.New("initialize worker failed")
	}
	if err := server.ListenAndServe(ctx); err != nil {
		return errors.New("serve worker failed")
	}
	return nil
}

func validateConfigCredential(path string, lstat func(string) (os.FileInfo, error)) error {
	info, err := lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o222 != 0 {
		return errors.New("systemd pi-config credential is not read-only")
	}
	return nil
}

func parseConfigArgument(args []string, credentialDirectory string) (string, error) {
	if len(args) != 2 || args[0] != "--config" {
		return "", errors.New("usage: acornfox-pi-worker --config %d/pi-config")
	}
	expected := filepath.Join(credentialDirectory, configCredentialName)
	provided := filepath.Clean(args[1])
	if !filepath.IsAbs(provided) || provided != expected {
		return "", errors.New("configuration must use the systemd pi-config credential")
	}
	return provided, nil
}
