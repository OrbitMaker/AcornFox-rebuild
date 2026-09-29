package main

import "testing"

func TestSourceBuildFlagsRequireExplicitInputs(t *testing.T) {
	args := []string{"-runtime-binding", "/run/acornfox/runtime-binding.json", "-upload-root", "/var/lib/acornfox-source/uploads", "-workspace-root", "/var/lib/acornfox-source/source", "-work-root", "/var/lib/acornfox-source/work", "-image-store", "/var/lib/acornfox-source/images", "-log-root", "/var/lib/acornfox-source/logs", "-git-resolvers", "1.1.1.1:53"}
	c, err := parseFlags(args)
	if err != nil || len(c.production.GitResolverEndpoints) != 1 {
		t.Fatal("explicit source-build inputs rejected")
	}
	if c.socketGID != 0 {
		t.Fatal("legacy Source socket group default changed")
	}
	withIPC, err := parseFlags(append(append([]string(nil), args...), "-socket-gid", "981"))
	if err != nil || withIPC.socketGID != 981 {
		t.Fatal("explicit Source socket group was not passed to listener config")
	}
	if _, err := parseFlags(nil); err == nil {
		t.Fatal("missing fixed production inputs accepted")
	}
	if _, err := parseFlags(append(args, "unexpected")); err == nil {
		t.Fatal("extra source input accepted")
	}
	if _, err := parseFlags(append(append([]string(nil), args...), "-buildctl", "/caller-selected/buildctl")); err == nil {
		t.Fatal("caller-selected BuildKit client path accepted")
	}
}
