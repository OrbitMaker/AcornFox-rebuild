package main

import (
	"io"
	"strings"
	"testing"
)

func TestAcornFoxAdminRejectsLegacyAuthority(t *testing.T) {
	old, layout := processIdentity, buildLayoutSchema
	processIdentity, buildLayoutSchema = "acornfox", "1"
	defer func() { processIdentity, buildLayoutSchema = old, layout }()
	for _, args := range [][]string{
		{"bootstrap", "--password-file", "/root/password", "--task-root", "/tmp/fake"},
		{"activation", "validate", "--activation-id", "example"},
		{"candidate", "validate", "--activation-id", "example"},
	} {
		if err := runWithEUID(args, io.Discard, func() int { return 0 }); err == nil || !strings.Contains(err.Error(), "unsupported AcornFox") {
			t.Fatalf("args=%v err=%v", args, err)
		}
	}
	if err := runWithEUID([]string{"bootstrap", "--password-file", "/root/password"}, io.Discard, func() int { return 1000 }); err == nil || err.Error() != "root is required" {
		t.Fatalf("nonroot: %v", err)
	}
}
