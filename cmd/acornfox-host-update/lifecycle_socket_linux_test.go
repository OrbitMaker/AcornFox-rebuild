//go:build linux

package main

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestLifecycleSocketNotInheritedByDescendants(t *testing.T) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	syscall.CloseOnExec(pair[0])
	readerFile := os.NewFile(uintptr(pair[0]), "reader")
	peerFile := os.NewFile(uintptr(pair[1]), "inherited-lifecycle")
	reader, err := net.FileConn(readerFile)
	readerFile.Close()
	if err != nil {
		peerFile.Close()
		t.Fatal(err)
	}
	defer reader.Close()
	peer, err := adoptLifecycleFile(peerFile)
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command("/bin/sleep", "2")
	if err := child.Start(); err != nil {
		peer.Close()
		t.Fatal(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	n, err := reader.Read(b[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("descendant retained lifecycle socket: bytes=%d err=%v", n, err)
	}
}
