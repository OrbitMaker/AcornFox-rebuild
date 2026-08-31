package healthcheck

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

const (
	listenerSubject      = "fixed_linux_listener_boundary"
	maxListenerFactBytes = 1 << 20
)

var errListenerFacts = errors.New("listener facts unavailable")

// ListenerSource supplies parsed listener facts. It deliberately accepts no
// command, path, or connection-string input: production collection has a
// fixed Linux implementation and tests inject only already-structured facts.
type ListenerSource interface {
	Capture(context.Context) (ListenerFacts, error)
}

// ListenerSourceFunc makes a task-local listener source convenient to test.
type ListenerSourceFunc func(context.Context) (ListenerFacts, error)

func (f ListenerSourceFunc) Capture(ctx context.Context) (ListenerFacts, error) {
	return f(ctx)
}

// RuntimePortSource supplies the currently expected application runtime ports.
// The listener probe always requires these ports on IPv4 loopback; a source
// cannot supply an address, a command, a path, or a DSN.
type RuntimePortSource interface {
	RuntimePorts(context.Context) ([]uint16, error)
}

// RuntimePortSourceFunc makes a task-local runtime-port source convenient to
// test.
type RuntimePortSourceFunc func(context.Context) ([]uint16, error)

func (f RuntimePortSourceFunc) RuntimePorts(ctx context.Context) ([]uint16, error) {
	return f(ctx)
}

// TCPListener is one listening TCP socket normalized from a Linux proc fact.
type TCPListener struct {
	Address netip.Addr
	Port    uint16
}

// ListenerFacts contains only facts needed for the Gate7 listener boundary.
// Unix sockets are names rather than arbitrary filesystem inputs: the probe
// recognizes exactly the fixed BuildKit socket below.
type ListenerFacts struct {
	TCP  []TCPListener
	Unix []string
}

// SSHListenerPolicy keeps the retained SSH exception explicit. It is a narrow
// policy seam, not a blanket allowance for unrecognized ports.
type SSHListenerPolicy interface {
	Allows(TCPListener) bool
}

// FixedSSHPort22Policy allows only TCP port 22. It is intentionally a value
// with no configurable port number so production cannot accidentally broaden
// the exception while wiring the probe.
type FixedSSHPort22Policy struct{}

func (FixedSSHPort22Policy) Allows(listener TCPListener) bool { return listener.Port == 22 }

var (
	publicPorts       = []uint16{80, 443}
	coreLoopbackPorts = []uint16{5432, 8080, 8092, 18481, 18482, 2019, 2020}
)

// One wildcard socket in either IP family satisfies each public port. Go's
// production Edge listener may be represented only in tcp6 when Linux
// dual-stack is enabled; external IPv4/IPv6 reachability remains a separate
// synthetic-monitor acceptance gate.

const buildkitSocket = "/run/open-card-buildkit/buildkitd.sock"

// NewListenerProbe checks the fixed Gate7 listener boundary. source and ports
// are injected to keep the check task-testable; ssh must be an explicit policy
// so that port 22 is never confused with a broad "ignore unknown ports" rule.
func NewListenerProbe(source ListenerSource, ports RuntimePortSource, ssh SSHListenerPolicy) (HostProbe, error) {
	if source == nil || ports == nil || ssh == nil {
		return HostProbe{}, errListenerFacts
	}
	return HostProbe{Kind: CheckListeners, Check: func(ctx context.Context) (HostFact, error) {
		if ctx == nil || ctx.Err() != nil {
			return emergencyListenerFact(), errLocalProbeFailed
		}
		facts, err := source.Capture(ctx)
		if err != nil || ctx.Err() != nil {
			if ctx.Err() != nil {
				return emergencyListenerFact(), errLocalProbeFailed
			}
			return emergencyListenerFact(), nil
		}
		dynamic, err := ports.RuntimePorts(ctx)
		if err != nil || ctx.Err() != nil {
			if ctx.Err() != nil {
				return emergencyListenerFact(), errLocalProbeFailed
			}
			return emergencyListenerFact(), nil
		}
		severity := listenerSeverity(facts, dynamic, ssh)
		return HostFact{Subject: listenerSubject, Severity: severity}, nil
	}}, nil
}

func emergencyListenerFact() HostFact {
	return HostFact{Subject: listenerSubject, Severity: SeverityEmergency}
}

func listenerSeverity(facts ListenerFacts, dynamic []uint16, ssh SSHListenerPolicy) Severity {
	if ssh == nil || !validListenerFacts(facts) || !validDynamicPorts(dynamic) {
		return SeverityEmergency
	}

	requiredLoopback := make(map[uint16]struct{}, len(coreLoopbackPorts)+len(dynamic))
	for _, port := range coreLoopbackPorts {
		requiredLoopback[port] = struct{}{}
	}
	for _, port := range dynamic {
		requiredLoopback[port] = struct{}{}
	}
	requiredPublic := map[uint16]bool{80: false, 443: false}
	requiredUnix := map[string]bool{buildkitSocket: false}

	for _, socket := range facts.Unix {
		if _, required := requiredUnix[socket]; required {
			requiredUnix[socket] = true
		}
	}
	for _, listener := range facts.TCP {
		if listener.Address.IsUnspecified() {
			if _, required := requiredLoopback[listener.Port]; required {
				// Every core and dynamic port is IPv4 loopback only. A wildcard
				// socket is an exposure even if the required loopback socket exists.
				return SeverityEmergency
			}
			if _, required := requiredPublic[listener.Port]; required {
				requiredPublic[listener.Port] = true
				continue
			}
			if ssh.Allows(listener) {
				continue
			}
			return SeverityEmergency
		}
		if listener.Address == netip.MustParseAddr("127.0.0.1") {
			if _, required := requiredLoopback[listener.Port]; required {
				delete(requiredLoopback, listener.Port)
				continue
			}
			if ssh.Allows(listener) {
				continue
			}
			return SeverityEmergency
		}
		if listener.Address.IsLoopback() {
			if ssh.Allows(listener) {
				continue
			}
			return SeverityEmergency
		}
		if ssh.Allows(listener) {
			continue
		}
		return SeverityEmergency
	}
	for _, present := range requiredPublic {
		if !present {
			return SeverityCritical
		}
	}
	if len(requiredLoopback) != 0 {
		return SeverityCritical
	}
	for _, present := range requiredUnix {
		if !present {
			return SeverityCritical
		}
	}
	return SeverityOK
}

func validListenerFacts(facts ListenerFacts) bool {
	seenTCP := make(map[TCPListener]struct{}, len(facts.TCP))
	for _, listener := range facts.TCP {
		if !listener.Address.IsValid() || listener.Port == 0 {
			return false
		}
		if _, found := seenTCP[listener]; found {
			return false
		}
		seenTCP[listener] = struct{}{}
	}
	seenUnix := make(map[string]struct{}, len(facts.Unix))
	for _, socket := range facts.Unix {
		if socket == "" {
			return false
		}
		if _, found := seenUnix[socket]; found {
			return false
		}
		seenUnix[socket] = struct{}{}
	}
	return true
}

func validDynamicPorts(ports []uint16) bool {
	seen := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		if port == 0 {
			return false
		}
		if _, found := seen[port]; found {
			return false
		}
		seen[port] = struct{}{}
	}
	return true
}

// parseLinuxListenerFacts parses the bounded contents of /proc/net/tcp,
// /proc/net/tcp6, and /proc/net/unix. It accepts only LISTEN TCP records and
// Unix stream sockets. Any malformed or duplicate input invalidates the whole
// snapshot rather than risking a partially trusted host fact.
func parseLinuxListenerFacts(tcp, tcp6, unix []byte) (ListenerFacts, error) {
	if len(tcp) > maxListenerFactBytes || len(tcp6) > maxListenerFactBytes || len(unix) > maxListenerFactBytes {
		return ListenerFacts{}, errListenerFacts
	}
	v4, err := parseProcTCP(tcp, false)
	if err != nil {
		return ListenerFacts{}, errListenerFacts
	}
	v6, err := parseProcTCP(tcp6, true)
	if err != nil {
		return ListenerFacts{}, errListenerFacts
	}
	unixSockets, err := parseProcUnix(unix)
	if err != nil {
		return ListenerFacts{}, errListenerFacts
	}
	facts := ListenerFacts{TCP: append(v4, v6...), Unix: unixSockets}
	if !validListenerFacts(facts) {
		return ListenerFacts{}, errListenerFacts
	}
	sort.Slice(facts.TCP, func(i, j int) bool {
		if facts.TCP[i].Address != facts.TCP[j].Address {
			return facts.TCP[i].Address.Less(facts.TCP[j].Address)
		}
		return facts.TCP[i].Port < facts.TCP[j].Port
	})
	sort.Strings(facts.Unix)
	return facts, nil
}

func parseProcTCP(raw []byte, ipv6 bool) ([]TCPListener, error) {
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, errListenerFacts
	}
	listeners := make([]TCPListener, 0, len(lines)-1)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 4 || fields[3] != "0A" {
			if len(fields) < 4 {
				return nil, errListenerFacts
			}
			continue
		}
		address, port, err := parseProcTCPAddress(fields[1], ipv6)
		if err != nil {
			return nil, errListenerFacts
		}
		listeners = append(listeners, TCPListener{Address: address, Port: port})
	}
	return listeners, nil
}

func parseProcTCPAddress(value string, ipv6 bool) (netip.Addr, uint16, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return netip.Addr{}, 0, errListenerFacts
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil || port == 0 {
		return netip.Addr{}, 0, errListenerFacts
	}
	decoded, err := hex.DecodeString(parts[0])
	if err != nil || len(decoded) != map[bool]int{false: 4, true: 16}[ipv6] {
		return netip.Addr{}, 0, errListenerFacts
	}
	if ipv6 {
		for offset := 0; offset < len(decoded); offset += 4 {
			decoded[offset], decoded[offset+1], decoded[offset+2], decoded[offset+3] = decoded[offset+3], decoded[offset+2], decoded[offset+1], decoded[offset]
		}
		var bytes16 [16]byte
		copy(bytes16[:], decoded)
		return netip.AddrFrom16(bytes16), uint16(port), nil
	}
	return netip.AddrFrom4([4]byte{decoded[3], decoded[2], decoded[1], decoded[0]}), uint16(port), nil
}

func parseProcUnix(raw []byte) ([]string, error) {
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, errListenerFacts
	}
	sockets := make([]string, 0)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 7 {
			return nil, errListenerFacts
		}
		// SOCK_STREAM (0001) + listening state (01) are the only facts that
		// can prove the BuildKit endpoint is accepting connections.
		if fields[4] != "0001" || fields[5] != "01" {
			continue
		}
		if len(fields) == 7 {
			continue
		}
		path := fields[7]
		if !strings.HasPrefix(path, "/") {
			continue
		}
		sockets = append(sockets, path)
	}
	return sockets, nil
}
