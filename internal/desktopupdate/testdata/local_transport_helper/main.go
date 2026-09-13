package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "missing command")
		os.Exit(2)
	}

	verb := os.Args[1]
	attempt := ""
	if len(os.Args) >= 3 {
		attempt = os.Args[2]
	}

	switch verb {
	case "observe":
		switch attempt {
		case strings.Repeat("b", 64): // Block
			time.Sleep(30 * time.Second)
		case strings.Repeat("c", 64): // Spawn descendant in SAME group that holds stdout/stderr, parent exits
			cmd := exec.Command("sleep", "30")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "spawn child failed: %v\n", err)
				os.Exit(1)
			}
			_ = os.WriteFile("/tmp/acornfox-test-child.pid", []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0644)
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "code": "ok", "child_pid": cmd.Process.Pid})
			os.Exit(0)
		case strings.Repeat("4", 64): // Spawn detached worker in a NEW session (setsid) that closes stdio
			cmd := exec.Command("sleep", "60")
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			cmd.Stdin = nil
			cmd.Stdout = nil
			cmd.Stderr = nil
			if err := cmd.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "spawn detached worker failed: %v\n", err)
				os.Exit(1)
			}
			_ = os.WriteFile("/tmp/acornfox-test-detached.pid", []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0644)
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "code": "ok", "detached_pid": cmd.Process.Pid})
			time.Sleep(30 * time.Second)
		case strings.Repeat("5", 64): // Spawn detached worker (setsid) that deliberately retains inherited pipes
			cmd := exec.Command("sleep", "60")
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				os.Exit(1)
			}
			_ = os.WriteFile("/tmp/acornfox-test-retaining.pid", []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0644)
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "code": "ok", "retaining_pid": cmd.Process.Pid})
			os.Exit(0)
		case strings.Repeat("6", 64): // Spawn descendant in SAME group that closes stdio and keeps running, parent exits 0
			cmd := exec.Command("sleep", "30")
			cmd.Stdin = nil
			cmd.Stdout = nil
			cmd.Stderr = nil
			if err := cmd.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "spawn same-group child failed: %v\n", err)
				os.Exit(1)
			}
			_ = os.WriteFile("/tmp/acornfox-test-samegroup-closedstdio.pid", []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0644)
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "code": "ok", "child_pid": cmd.Process.Pid})
			os.Exit(0)
		case strings.Repeat("7", 64): // Direct child closes stdio and keeps running (for deterministic waitid error tests)
			_ = os.WriteFile("/tmp/acornfox-test-livechild.pid", []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
			_ = os.Stdout.Close()
			_ = os.Stderr.Close()
			time.Sleep(30 * time.Second)
		case strings.Repeat("8", 64): // Spawn detached worker in a NEW session (setsid) that closes stdio, parent exits 0
			cmd := exec.Command("sleep", "30")
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			cmd.Stdin = nil
			cmd.Stdout = nil
			cmd.Stderr = nil
			if err := cmd.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "spawn detached child failed: %v\n", err)
				os.Exit(1)
			}
			_ = os.WriteFile("/tmp/acornfox-test-detached-normal.pid", []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0644)
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "code": "ok", "detached_pid": cmd.Process.Pid})
			os.Exit(0)
		case strings.Repeat("e", 64): // Write to stderr and exit 42
			fmt.Fprintln(os.Stderr, "secret-internal-error: private database connection failed")
			os.Exit(42)
		case strings.Repeat("d", 64): // Overflow stdout (> 64KB)
			os.Stdout.Write(bytes.Repeat([]byte("A"), 128*1024))
			os.Exit(0)
		default:
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
				"ok":      true,
				"code":    "ok",
				"verb":    verb,
				"attempt": attempt,
			})
		}
	case "status":
		if attempt == strings.Repeat("e", 64) {
			fmt.Fprintln(os.Stderr, "private status error")
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"ok":      true,
			"code":    "ok",
			"verb":    verb,
			"attempt": attempt,
		})
	case "submit":
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"ok":         true,
			"code":       "ok",
			"read_bytes": len(data),
		})
	case "recover":
		if attempt == strings.Repeat("e", 64) {
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"ok":      true,
			"code":    "ok",
			"verb":    verb,
			"attempt": attempt,
		})
	default:
		fmt.Fprintf(os.Stderr, "unexpected verb: %s\n", verb)
		os.Exit(3)
	}
}
