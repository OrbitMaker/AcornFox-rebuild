package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContainerSocketGIDUsesPublisherParentOnlyWhenOptedIn(t *testing.T) {
	root := t.TempDir()
	args := []string{"-runtime-binding", filepath.Join(root, "binding.json"), "-work-root", filepath.Join(root, "work"), "-image-store", filepath.Join(root, "images")}
	legacy, err := parseFlags(args)
	if err != nil || legacy.socketGID != 0 {
		t.Fatalf("legacy Container socket group changed: %#v %v", legacy, err)
	}
	opted, err := parseFlags(append(append([]string(nil), args...), "-socket-gid", "981"))
	if err != nil || opted.socketGID != 981 {
		t.Fatalf("explicit Container IPC group not retained: %#v %v", opted, err)
	}
	socket := filepath.Join(root, "container-ipc", "container.sock")
	if err := prepareContainerSocketParent(socket, opted.socketGID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Dir(socket)); !os.IsNotExist(err) {
		t.Fatal("unified mode created a permissive socket parent")
	}
	if err := prepareContainerSocketParent(socket, legacy.socketGID); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(filepath.Dir(socket)); err != nil || !info.IsDir() {
		t.Fatal("legacy socket parent behavior regressed")
	}
}
