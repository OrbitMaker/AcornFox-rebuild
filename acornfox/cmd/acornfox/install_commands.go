//go:build !windows

// This file implements installation and upgrade subcommands for N5:
// - version: print version information
// - init: initialize database (migrations run automatically via state.Open)
// - migrate: run database migrations (for upgrades)
// - admin-token: generate initial admin token
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/acornfox/acornfox/internal/state"
)

// version is the AcornFox version string. It is set at build time via
// -ldflags "-X main.version=x.y.z" or defaults to dev.
var version = "0.2.0-dev"

// runVersion implements `acornfox version`: print version information.
func runVersion(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fmt.Fprintf(stdout, "acornfox %s\n", version)
	return 0
}

// runInit implements `acornfox init`: initialize the database. The actual
// migrations are run automatically by state.Open, so this just ensures the
// database file exists and is openable. It is idempotent.
func runInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", "/var/lib/acornfox", "state directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	dbPath := filepath.Join(*dataDir, "acornfox.db")

	// Create data directory if needed
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		fmt.Fprintf(stderr, "创建数据目录失败: %v\n", err)
		return 1
	}

	// Open/create database (runs migrations automatically via state.Open)
	st, err := state.Open(state.Config{Path: dbPath})
	if err != nil {
		fmt.Fprintf(stderr, "初始化数据库失败: %v\n", err)
		return 1
	}
	defer st.Close()

	fmt.Fprintln(stdout, "数据库初始化完成")
	return 0
}

// runMigrate implements `acornfox migrate`: run database migrations on an
// existing database. This is called during upgrades after backing up the
// current version. Migrations run automatically via state.Open.
func runMigrate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", "/var/lib/acornfox", "state directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	dbPath := filepath.Join(*dataDir, "acornfox.db")

	// Check if database exists
	if _, err := os.Stat(dbPath); err != nil {
		fmt.Fprintf(stderr, "数据库不存在: %s\n", dbPath)
		return 1
	}

	// Open database (this runs migrations automatically via state.Open)
	st, err := state.Open(state.Config{Path: dbPath})
	if err != nil {
		fmt.Fprintf(stderr, "迁移失败: %v\n", err)
		return 1
	}
	defer st.Close()

	fmt.Fprintln(stdout, "数据库迁移完成")
	return 0
}

// runAdminToken implements `acornfox admin-token`: generate a secure random
// token for initial admin setup. The install script saves this token and the
// user uses it to log in for the first time through the web console.
//
// N3 已实现完整的管理员认证系统（internal/auth、admin_credentials 表、
// 登录限速等），但 N5 首发不需要公网控制台，所以这里只生成令牌给安装脚本
// 保存，实际认证逻辑由 internal/auth 和 apiserver 的控制台登录处理。
func runAdminToken(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("admin-token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Generate a secure random token (32 bytes = 64 hex chars)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		fmt.Fprintf(stderr, "生成令牌失败: %v\n", err)
		return 1
	}
	token := hex.EncodeToString(tokenBytes)

	// Output just the token for easy capture by install script.
	// The install script saves it to /root/.acornfox-token (mode 0600).
	// TODO N3+: 实际使用时需要在首次打开控制台时，用此令牌创建管理员账号
	// 或设置密码。当前 N5 默认 SSH 访问不需要令牌，这里先生成令牌占位。
	fmt.Fprintln(stdout, token)
	return 0
}
