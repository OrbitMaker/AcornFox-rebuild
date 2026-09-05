//go:build linux

package runtimenetwork

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/install"
)

type production struct {
	persistent, runtime *install.DurableWriter
	lock                *install.DurableLock
}

func productionBackend(create bool) (backend, error) {
	if os.Geteuid() != 0 {
		return nil, ErrUnavailable
	}
	// The initial user namespace has the full identity UID map. Also require
	// PID 1's netns: rules must protect the Docker host, not a caller's netns.
	raw, err := os.ReadFile("/proc/self/uid_map")
	if err != nil || strings.Join(strings.Fields(string(raw)), " ") != "0 0 4294967295" {
		return nil, ErrUnavailable
	}
	for _, kind := range []string{"user", "net"} {
		a, e := os.Stat("/proc/self/ns/" + kind)
		z, f := os.Stat("/proc/1/ns/" + kind)
		if e != nil || f != nil || !os.SameFile(a, z) {
			return nil, ErrUnavailable
		}
	}
	if !safeRootParents(filepath.Dir(IntentPath)) || !safeRootParents("/run") {
		return nil, ErrUnavailable
	}
	state, err := install.ProductionDurableWriter(filepath.Dir(IntentPath))
	if err != nil {
		return nil, ErrUnavailable
	}
	p := &production{persistent: state}
	fail := func() (backend, error) { p.close(); return nil, ErrUnavailable }
	// Verify may acquire an existing lock but never create state witnesses.
	if !create {
		for _, name := range []string{"runtime-network.json", "runtime-network.lock"} {
			if _, err := state.ReadMetadata(name); err != nil {
				return fail()
			}
		}
	}
	if p.lock, err = state.AcquireMetadataLock("runtime-network.lock"); err != nil {
		return fail()
	}
	if create {
		if err = os.Mkdir(StateRoot, 0700); err != nil && !os.IsExist(err) {
			return fail()
		}
	}
	info, err := os.Lstat(StateRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return fail()
	}
	if p.runtime, err = install.ProductionDurableWriter(StateRoot); err != nil {
		return fail()
	}
	return p, nil
}
func (p *production) close() error {
	if p == nil {
		return nil
	}
	var failed bool
	if p.runtime != nil {
		failed = p.runtime.Close() != nil || failed
		p.runtime = nil
	}
	if p.lock != nil {
		failed = p.lock.Release() != nil || failed
		p.lock = nil
	}
	if p.persistent != nil {
		failed = p.persistent.Close() != nil || failed
		p.persistent = nil
	}
	if failed {
		return ErrUnavailable
	}
	return nil
}
func (p *production) readIntent() ([]byte, error) {
	return p.persistent.ReadMetadata("runtime-network.json")
}
func (p *production) writeIntent(raw []byte, create bool) error {
	if create {
		return p.persistent.CreateMetadata("runtime-network.json", raw)
	}
	return p.persistent.WriteMetadata("runtime-network.json", raw)
}
func (p *production) readRuntime() ([]byte, error) { return p.runtime.ReadMetadata("state.json") }
func (p *production) writeRuntime(raw []byte, create bool) error {
	if create {
		return p.runtime.CreateMetadata("state.json", raw)
	}
	return p.runtime.WriteMetadata("state.json", raw)
}
func (p *production) random(raw []byte) error { _, err := rand.Read(raw); return err }
func (p *production) ready(ctx context.Context) error {
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	// Docker must already supply forwarding and bridge filtering; never change
	// host sysctls. ICC=false plus bridge netfilter blocks sibling connections.
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/bridge/bridge-nf-call-iptables"} {
		raw, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(raw)) != "1" {
			return ErrUnavailable
		}
	}
	return nil
}

type boundedBuffer struct{ body bytes.Buffer }

func (b *boundedBuffer) Write(raw []byte) (int, error) {
	if len(raw) > maxOutput-b.body.Len() {
		return 0, ErrUnavailable
	}
	return b.body.Write(raw)
}
func (p *production) run(ctx context.Context, path string, args []string, input []byte) ([]byte, error) {
	if path != "/usr/bin/docker" && path != "/usr/sbin/nft" && path != "/usr/sbin/ip" {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if p.runtime.VerifyLiveRoot() != nil {
		return nil, ErrUnavailable
	}
	home, err := os.MkdirTemp(StateRoot, ".docker-cli-")
	if err != nil {
		return nil, ErrUnavailable
	}
	defer os.RemoveAll(home)
	cmd := exec.CommandContext(ctx, path, args...)
	// In particular, DOCKER_HOST/context and proxy/credential variables cannot
	// redirect these fixed local commands. The explicit Unix host bypasses CLI
	// Docker config context selection too.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=" + home, "DOCKER_CONFIG=" + filepath.Join(home, ".docker")}
	if path == "/usr/bin/docker" {
		cmd.Args = append([]string{path, "--host", "unix:///var/run/docker.sock"}, args...)
	}
	if len(input) > 0 {
		cmd.Stdin = bytes.NewReader(input)
	}
	var out boundedBuffer
	cmd.Stdout, cmd.Stderr = &out, io.Discard
	if err := cmd.Run(); err != nil {
		return nil, ErrUnavailable
	}
	return out.body.Bytes(), nil
}

func safeRootParents(path string) bool {
	for {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || stat.Gid != 0 {
			return false
		}
		if path == "/" {
			return true
		}
		path = filepath.Dir(path)
	}
}
