//go:build !windows

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestServerRejectsInvalidPublicPortRange(t *testing.T) {
	var out, errOut bytes.Buffer
	dir := t.TempDir()
	code := runServer([]string{
		"-data-dir", dir, "-listen", "unix:" + filepath.Join(dir, "api.sock"),
		"-console-listen", "", "-public-port-min", "20000", "-public-port-max", "19999",
	}, &out, &errOut)
	if code == 0 || !strings.Contains(errOut.String(), "invalid public port range") {
		t.Fatalf("invalid range must fail before listeners start: exit=%d stderr=%s", code, errOut.String())
	}
}
