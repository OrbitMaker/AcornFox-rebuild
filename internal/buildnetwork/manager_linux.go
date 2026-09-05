//go:build linux

package buildnetwork

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/install"
)

const statePath = RunRoot + "/state.json"
const workerUnit = "acornfox-buildkit.service"

type state struct {
	Schema               int    `json:"schema"`
	Token                string `json:"token"`
	PolicyDigest         string `json:"policy_digest"`
	ImplementationDigest string `json:"implementation_digest"`
	NamespaceInode       uint64 `json:"namespace_inode"`
	NamespaceDevice      uint64 `json:"namespace_device"`
	HostLinkIndex        int    `json:"host_link_index"`
	WorkerRules          string `json:"worker_rules_sha256"`
	HostRules            string `json:"host_rules_sha256"`
	NATRules             string `json:"nat_rules_sha256"`
	Topology             string `json:"topology_sha256"`
	Ready                bool   `json:"ready"`
}

type Manager struct {
	policy    []byte
	digest    string
	serverUID uint32
	serverGID int
	workerUID uint32
	lock      *os.File
	state     state
	mu        sync.Mutex
}

func ReadInstalledPolicy() ([]byte, string, error) {
	raw, err := readRootFile(PolicyPath, 65536)
	if err != nil {
		return nil, "", err
	}
	_, digest, err := ParsePolicy(raw)
	return raw, digest, err
}

func readRootFile(path string, limit int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > limit {
		return nil, ErrPolicy
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if int64(len(raw)) > limit {
		return nil, ErrPolicy
	}
	return raw, err
}

func NewProductionManager() (*Manager, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("build network manager requires host root")
	}
	self, err := os.Stat("/proc/self/ns/user")
	if err != nil {
		return nil, err
	}
	init, err := os.Stat("/proc/1/ns/user")
	if err != nil || !os.SameFile(self, init) {
		return nil, ErrPolicy
	}
	raw, digest, err := ReadInstalledPolicy()
	if err != nil {
		return nil, err
	}
	server, err := user.Lookup("acornfox")
	if err != nil {
		return nil, err
	}
	worker, err := user.Lookup("acornfox-buildkit")
	if err != nil {
		return nil, err
	}
	suid, err := strconv.ParseUint(server.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	wuid, err := strconv.ParseUint(worker.Uid, 10, 32)
	if err != nil || suid == wuid || wuid == 0 || suid == 0 {
		return nil, ErrPolicy
	}
	gid, err := strconv.Atoi(server.Gid)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(RunRoot)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return nil, ErrPolicy
	}
	lock, err := os.OpenFile(RunRoot+"/lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, err
	}
	return &Manager{policy: raw, digest: digest, serverUID: uint32(suid), serverGID: gid, workerUID: uint32(wuid), lock: lock}, nil
}

func (m *Manager) Close() error {
	if m.lock != nil {
		return m.lock.Close()
	}
	return nil
}

func command(ctx context.Context, input string, path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		// These fixed commands contain no credentials or user-supplied content.
		// Keep bounded operator diagnostics; RPC callers receive no error body.
		if len(output) > 1024 {
			output = output[:1024]
		}
		return nil, fmt.Errorf("build network command %s failed: %w: %s", filepath.Base(path), err, strings.TrimSpace(string(output)))
	}
	if len(output) > 1<<20 {
		return nil, ErrPolicy
	}
	return output, nil
}

func ip(ctx context.Context, args ...string) ([]byte, error) {
	return command(ctx, "", "/usr/sbin/ip", args...)
}
func nft(ctx context.Context, namespace bool, input string, args ...string) ([]byte, error) {
	if namespace {
		return command(ctx, input, "/usr/sbin/ip", append([]string{"netns", "exec", Namespace, "/usr/sbin/nft"}, args...)...)
	}
	return command(ctx, input, "/usr/sbin/nft", args...)
}

func (m *Manager) writeState() error {
	raw, err := json.Marshal(m.state)
	if err != nil {
		return err
	}
	return install.AtomicWriteFile(statePath, append(raw, '\n'), 0600)
}

func (m *Manager) loadState() error {
	raw, err := readRootFile(statePath, 65536)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&m.state) != nil || m.state.Schema != 1 || !fingerprintPattern.MatchString(m.state.Token) || m.state.PolicyDigest != m.digest || m.state.ImplementationDigest != implementationDigest() {
		return ErrPolicy
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrPolicy
	}
	return nil
}

func namespaceIdentity() (uint64, uint64, error) {
	f, err := os.Open("/run/netns/" + Namespace)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	var stat syscall.Stat_t
	if err = syscall.Fstat(int(f.Fd()), &stat); err != nil {
		return 0, 0, err
	}
	// NS_GET_USERNS returns the namespace that owns this network namespace.
	fd, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), 0xb701, 0)
	if errno != 0 {
		return 0, 0, errno
	}
	defer syscall.Close(int(fd))
	var owner syscall.Stat_t
	if err = syscall.Fstat(int(fd), &owner); err != nil {
		return 0, 0, err
	}
	init, err := os.Stat("/proc/1/ns/user")
	if err != nil {
		return 0, 0, err
	}
	i := init.Sys().(*syscall.Stat_t)
	if owner.Ino != i.Ino || owner.Dev != i.Dev {
		return 0, 0, ErrPolicy
	}
	return uint64(stat.Dev), stat.Ino, nil
}

type linkInfo struct {
	Index int    `json:"ifindex"`
	Alias string `json:"ifalias"`
	Name  string `json:"ifname"`
}

func hostLink(ctx context.Context) (linkInfo, error) {
	raw, err := ip(ctx, "-j", "link", "show", "dev", HostLink)
	if err != nil {
		return linkInfo{}, err
	}
	var links []linkInfo
	if json.Unmarshal(raw, &links) != nil || len(links) != 1 {
		return linkInfo{}, ErrPolicy
	}
	return links[0], nil
}

func kernelHash(raw []byte) (string, error) {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return "", ErrPolicy
	}
	var normalize func(any)
	normalize = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			delete(x, "handle")
			delete(x, "metainfo")
			if _, ok := x["counter"]; ok {
				x["counter"] = nil
			}
			for _, child := range x {
				normalize(child)
			}
		case []any:
			for _, child := range x {
				normalize(child)
			}
		}
	}
	normalize(v)
	canonical, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func tableHash(ctx context.Context, namespace bool, family, name string) (string, error) {
	raw, err := nft(ctx, namespace, "", "-s", "-j", "list", "table", family, name)
	if err != nil {
		return "", err
	}
	return kernelHash(raw)
}

func topologyHash(ctx context.Context) (string, error) {
	var all bytes.Buffer
	for _, args := range [][]string{{"-j", "-4", "-n", Namespace, "address", "show"}, {"-j", "-4", "-n", Namespace, "route", "show"}, {"-j", "-4", "address", "show", "dev", HostLink}} {
		raw, err := ip(ctx, args...)
		if err != nil {
			return "", err
		}
		var value any
		if json.Unmarshal(raw, &value) != nil {
			return "", ErrPolicy
		}
		// Address lifetime counters decrease with time; topology itself is fixed.
		var strip func(any)
		strip = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				delete(x, "valid_life_time")
				delete(x, "preferred_life_time")
				delete(x, "link_netnsid")
				for _, c := range x {
					strip(c)
				}
			case []any:
				for _, c := range x {
					strip(c)
				}
			}
		}
		strip(value)
		canonical, _ := json.Marshal(value)
		all.Write(canonical)
	}
	sum := sha256.Sum256(all.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

func dockerRule(ctx context.Context, action string, rule []string) error {
	args := []string{"-w", "3", action, "DOCKER-USER"}
	if action == "-I" {
		args = append(args, "1")
	}
	args = append(args, rule...)
	_, err := command(ctx, "", "/usr/sbin/iptables", args...)
	return err
}

func dockerPrerequisites(ctx context.Context) error {
	forward, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil || strings.TrimSpace(string(forward)) != "1" {
		return errors.New("Docker IPv4 forwarding is not ready")
	}
	_, err = command(ctx, "", "/usr/sbin/iptables", "-w", "3", "-C", "FORWARD", "-j", "DOCKER-USER")
	if err != nil {
		return errors.New("supported Docker iptables forwarding is not ready")
	}
	for _, family := range []string{"ip", "ip6"} {
		if _, err := nft(ctx, false, "", "list", "table", family, "docker-bridges"); err == nil {
			return errors.New("Docker native nftables backend is not supported by this release")
		}
	}
	return nil
}

func requireUnusedSubnet(ctx context.Context) error {
	raw, err := ip(ctx, "-j", "-4", "route", "show", "table", "all")
	if err != nil {
		return err
	}
	var routes []struct {
		Destination string `json:"dst"`
	}
	if json.Unmarshal(raw, &routes) != nil {
		return ErrPolicy
	}
	wanted := netip.MustParsePrefix("10.203.253.0/30")
	for _, route := range routes {
		if route.Destination == "default" || route.Destination == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil {
			if address, e := netip.ParseAddr(route.Destination); e == nil {
				prefix = netip.PrefixFrom(address, 32)
			} else {
				return ErrPolicy
			}
		}
		if wanted.Overlaps(prefix) {
			return errors.New("build network subnet overlaps an existing host route")
		}
	}
	return nil
}

func loadRootlessProfile(ctx context.Context) error {
	profile, err := readRootFile("/etc/acornfox/rootlesskit.apparmor", 65536)
	if err != nil || !bytes.Equal(profile, RootlessProfile()) {
		return ErrPolicy
	}
	if enabled, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil && strings.TrimSpace(string(enabled)) == "Y" {
		if _, err = command(ctx, "", "/usr/sbin/apparmor_parser", "-r", "/etc/acornfox/rootlesskit.apparmor"); err != nil {
			return err
		}
	}
	return nil
}

func implementationDigest() string {
	rules, _ := json.Marshal(DockerRules())
	sum := sha256.Sum256(append([]byte(WorkerRules()+HostRules()), rules...))
	return hex.EncodeToString(sum[:])
}

func (m *Manager) Prepare(ctx context.Context) error {
	if err := dockerPrerequisites(ctx); err != nil {
		return err
	}
	if _, err := os.Lstat(statePath); err == nil {
		if err = m.loadState(); err != nil {
			return err
		}
		if !m.state.Ready {
			return errors.New("incomplete owned build network requires cleanup")
		}
		if err = m.verifyKernel(ctx); err != nil {
			return err
		}
		return loadRootlessProfile(ctx)
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Lstat(SocketPath); !os.IsNotExist(err) {
		return errors.New("refusing an unowned policy socket")
	}
	if err := requireUnusedSubnet(ctx); err != nil {
		return err
	}
	if _, err := os.Lstat("/run/netns/" + Namespace); !os.IsNotExist(err) {
		return errors.New("refusing an existing build namespace")
	}
	if _, err := hostLink(ctx); err == nil {
		return errors.New("refusing an existing host link")
	}
	if _, err := ip(ctx, "link", "show", "dev", WorkerLink); err == nil {
		return errors.New("refusing an existing peer link")
	}
	for _, table := range [][2]string{{"inet", "acornfox_build_guard"}, {"ip", "acornfox_build_nat"}} {
		if _, err := nft(ctx, false, "", "list", "table", table[0], table[1]); err == nil {
			return errors.New("refusing an existing host policy table")
		}
	}
	for _, rule := range DockerRules() {
		if dockerRule(ctx, "-C", rule) == nil {
			return errors.New("refusing an existing Docker rule")
		}
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	m.state = state{Schema: 1, Token: hex.EncodeToString(token), PolicyDigest: m.digest, ImplementationDigest: implementationDigest()}
	if err := m.writeState(); err != nil {
		return err
	}
	if err := loadRootlessProfile(ctx); err != nil {
		return err
	}
	if _, err := ip(ctx, "netns", "add", Namespace); err != nil {
		return err
	}
	dev, ino, err := namespaceIdentity()
	if err != nil {
		return err
	}
	m.state.NamespaceDevice = dev
	m.state.NamespaceInode = ino
	if err = m.writeState(); err != nil {
		return err
	}
	if _, err = ip(ctx, "link", "add", HostLink, "type", "veth", "peer", "name", WorkerLink); err != nil {
		return err
	}
	link, err := hostLink(ctx)
	if err != nil {
		return err
	}
	m.state.HostLinkIndex = link.Index
	if err = m.writeState(); err != nil {
		return err
	}
	if _, err = ip(ctx, "link", "set", "dev", HostLink, "alias", m.state.Token); err != nil {
		return err
	}
	link, err = hostLink(ctx)
	if err != nil || link.Alias != m.state.Token || link.Index != m.state.HostLinkIndex {
		return ErrPolicy
	}
	steps := [][]string{{"link", "set", WorkerLink, "netns", Namespace}, {"address", "add", Gateway + "/30", "dev", HostLink}, {"link", "set", HostLink, "up"}, {"-n", Namespace, "link", "set", "lo", "up"}, {"-n", Namespace, "address", "add", WorkerIP + "/30", "dev", WorkerLink}, {"-n", Namespace, "link", "set", WorkerLink, "up"}, {"-n", Namespace, "route", "add", "default", "via", Gateway, "dev", WorkerLink}}
	for _, args := range steps {
		if _, err = ip(ctx, args...); err != nil {
			return err
		}
	}
	if _, err = nft(ctx, true, WorkerRules(), "-f", "-"); err != nil {
		return err
	}
	if m.state.WorkerRules, err = tableHash(ctx, true, "inet", "acornfox_build"); err != nil {
		return err
	}
	if err = m.writeState(); err != nil {
		return err
	}
	if _, err = nft(ctx, false, HostRules(), "-f", "-"); err != nil {
		return err
	}
	if m.state.HostRules, err = tableHash(ctx, false, "inet", "acornfox_build_guard"); err != nil {
		return err
	}
	if m.state.NATRules, err = tableHash(ctx, false, "ip", "acornfox_build_nat"); err != nil {
		return err
	}
	if err = m.writeState(); err != nil {
		return err
	}
	for _, rule := range DockerRules() {
		if err = dockerRule(ctx, "-I", rule); err != nil {
			return err
		}
	}
	if m.state.WorkerRules, err = tableHash(ctx, true, "inet", "acornfox_build"); err != nil {
		return err
	}
	if m.state.HostRules, err = tableHash(ctx, false, "inet", "acornfox_build_guard"); err != nil {
		return err
	}
	if m.state.NATRules, err = tableHash(ctx, false, "ip", "acornfox_build_nat"); err != nil {
		return err
	}
	if m.state.Topology, err = topologyHash(ctx); err != nil {
		return err
	}
	m.state.Ready = true
	return m.writeState()
}

func (m *Manager) verifyKernel(ctx context.Context) error {
	if !m.state.Ready || m.state.PolicyDigest != m.digest {
		return ErrPolicy
	}
	dev, ino, err := namespaceIdentity()
	if err != nil || dev != m.state.NamespaceDevice || ino != m.state.NamespaceInode {
		return ErrPolicy
	}
	link, err := hostLink(ctx)
	if err != nil || link.Index != m.state.HostLinkIndex || link.Alias != m.state.Token {
		return ErrPolicy
	}
	for _, item := range []struct {
		ns                 bool
		family, name, want string
	}{{true, "inet", "acornfox_build", m.state.WorkerRules}, {false, "inet", "acornfox_build_guard", m.state.HostRules}, {false, "ip", "acornfox_build_nat", m.state.NATRules}} {
		got, err := tableHash(ctx, item.ns, item.family, item.name)
		if err != nil || got != item.want {
			return ErrPolicy
		}
	}
	got, err := topologyHash(ctx)
	if err != nil || got != m.state.Topology {
		return ErrPolicy
	}
	if err = dockerPrerequisites(ctx); err != nil {
		return err
	}
	for _, rule := range DockerRules() {
		if err = dockerRule(ctx, "-C", rule); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) verifyWorker(ctx context.Context) error {
	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", BuildkitSocketPath)
	if err != nil {
		return err
	}
	defer connection.Close()
	uid, pid, err := peerIdentity(connection)
	if err != nil || uid != m.workerUID || pid <= 0 {
		return ErrPolicy
	}
	proc := "/proc/" + strconv.Itoa(int(pid))
	exe, err := os.Stat(proc + "/exe")
	if err != nil {
		return err
	}
	installed, err := os.Stat("/opt/acornfox/current/bin/buildkitd")
	if err != nil || !os.SameFile(exe, installed) {
		return ErrPolicy
	}
	namespace, err := os.Stat(proc + "/ns/net")
	if err != nil {
		return err
	}
	ns := namespace.Sys().(*syscall.Stat_t)
	if ns.Ino != m.state.NamespaceInode || uint64(ns.Dev) != m.state.NamespaceDevice {
		return ErrPolicy
	}
	cgroup, err := os.ReadFile(proc + "/cgroup")
	if err != nil {
		return err
	}
	group := strings.TrimSpace(string(cgroup))
	if group != "0::/system.slice/"+workerUnit && !strings.HasPrefix(group, "0::/system.slice/"+workerUnit+"/") {
		return ErrPolicy
	}
	for name, want := range map[string]string{"memory.max": "536870912", "cpu.max": "50000 100000"} {
		raw, err := os.ReadFile("/sys/fs/cgroup/system.slice/" + workerUnit + "/" + name)
		if err != nil || strings.TrimSpace(string(raw)) != want {
			return ErrPolicy
		}
	}
	return nil
}

func (m *Manager) attest(ctx context.Context, r AttestationRequest) (AttestationReceipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validRequest(r) || r.PolicyDigest != m.digest {
		return AttestationReceipt{}, ErrPolicy
	}
	current, _, err := ReadInstalledPolicy()
	if err != nil || !bytes.Equal(current, m.policy) {
		return AttestationReceipt{}, ErrPolicy
	}
	if err := m.verifyKernel(ctx); err != nil {
		return AttestationReceipt{}, err
	}
	current, _, err = ReadInstalledPolicy()
	if err != nil || !bytes.Equal(current, m.policy) {
		return AttestationReceipt{}, ErrPolicy
	}
	if err := m.verifyWorker(ctx); err != nil {
		return AttestationReceipt{}, err
	}
	if err := m.verifyKernel(ctx); err != nil {
		return AttestationReceipt{}, err
	}
	return AttestationReceipt{SchemaVersion: 1, PolicyDigest: m.digest, RequestFingerprint: r.RequestFingerprint}, nil
}

func (m *Manager) Serve(ctx context.Context) error {
	if err := m.Prepare(ctx); err != nil {
		return err
	}
	if info, err := os.Lstat(SocketPath); err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode()&os.ModeSocket == 0 {
			return ErrPolicy
		}
		if err = os.Remove(SocketPath); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", SocketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chown(SocketPath, 0, m.serverGID); err != nil {
		return err
	}
	if err = os.Chmod(SocketPath, 0660); err != nil {
		return err
	}
	if address := os.Getenv("NOTIFY_SOCKET"); address != "" {
		connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
		if err != nil {
			return err
		}
		_, err = connection.Write([]byte("READY=1"))
		connection.Close()
		if err != nil {
			return err
		}
	}
	go func() { <-ctx.Done(); listener.Close() }()
	slots := make(chan struct{}, 8)
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			connection.Close()
			continue
		}
		go func(connection net.Conn) {
			defer func() { <-slots; connection.Close() }()
			connection.SetDeadline(time.Now().Add(3 * time.Second))
			uid, _, err := peerIdentity(connection)
			if err != nil || (uid != 0 && uid != m.serverUID) {
				return
			}
			decoder := json.NewDecoder(io.LimitReader(connection, 8193))
			decoder.DisallowUnknownFields()
			var request AttestationRequest
			if decoder.Decode(&request) != nil || !validRequest(request) {
				return
			}
			requestCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
			defer cancel()
			receipt, err := m.attest(requestCtx, request)
			if err != nil {
				return
			}
			json.NewEncoder(connection).Encode(receipt)
		}(connection)
	}
}

// Cleanup is fail closed: a live worker or mismatched ownership leaves the
// filtering intact. It removes only the exact resources recorded by Prepare.
func (m *Manager) Cleanup(ctx context.Context) error {
	if err := m.loadState(); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if _, err := command(ctx, "", "/usr/bin/systemctl", "stop", workerUnit); err != nil {
		return err
	}
	if raw, err := os.ReadFile("/sys/fs/cgroup/system.slice/" + workerUnit + "/cgroup.procs"); err == nil && strings.TrimSpace(string(raw)) != "" {
		return errors.New("worker remains active")
	}
	if m.state.NamespaceInode != 0 {
		dev, ino, err := namespaceIdentity()
		if err != nil || dev != m.state.NamespaceDevice || ino != m.state.NamespaceInode {
			return ErrPolicy
		}
	} else if _, err := os.Lstat("/run/netns/" + Namespace); !os.IsNotExist(err) {
		return ErrPolicy
	}
	if m.state.HostLinkIndex != 0 {
		link, err := hostLink(ctx)
		if err != nil || link.Index != m.state.HostLinkIndex || (link.Alias != m.state.Token && !(link.Alias == "" && !m.state.Ready)) {
			return ErrPolicy
		}
	} else if _, err := hostLink(ctx); err == nil {
		return ErrPolicy
	}
	for _, item := range []struct{ family, name, hash string }{{"inet", "acornfox_build_guard", m.state.HostRules}, {"ip", "acornfox_build_nat", m.state.NATRules}} {
		if _, err := nft(ctx, false, "", "list", "table", item.family, item.name); err == nil {
			got, err := tableHash(ctx, false, item.family, item.name)
			if err != nil || item.hash == "" || got != item.hash {
				return ErrPolicy
			}
		}
	}
	for _, rule := range DockerRules() {
		if dockerRule(ctx, "-C", rule) == nil {
			if err := dockerRule(ctx, "-D", rule); err != nil {
				return err
			}
		}
	}
	for _, table := range [][2]string{{"inet", "acornfox_build_guard"}, {"ip", "acornfox_build_nat"}} {
		if _, err := nft(ctx, false, "", "list", "table", table[0], table[1]); err == nil {
			if _, err = nft(ctx, false, "", "delete", "table", table[0], table[1]); err != nil {
				return err
			}
		}
	}
	if m.state.HostLinkIndex != 0 {
		if _, err := ip(ctx, "link", "delete", HostLink); err != nil {
			return err
		}
	}
	if m.state.NamespaceInode != 0 {
		if _, err := ip(ctx, "netns", "delete", Namespace); err != nil {
			return err
		}
	}
	if err := os.Remove(statePath); err != nil {
		return err
	}
	if info, err := os.Lstat(SocketPath); err == nil && info.Mode()&os.ModeSocket != 0 && info.Sys().(*syscall.Stat_t).Uid == 0 {
		if err = os.Remove(SocketPath); err != nil {
			return err
		}
	}
	return nil
}
