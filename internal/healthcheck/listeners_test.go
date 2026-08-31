package healthcheck

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestParseLinuxListenerFactsNormalizesIPv4IPv6AndUnix(t *testing.T) {
	tcp := []byte("sl local_address rem_address st\n0: 00000000:0050 00000000:0000 0A\n1: 0100007F:1538 00000000:0000 0A\n")
	tcp6 := []byte("sl local_address rem_address st\n0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A\n1: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A\n")
	unix := []byte("Num RefCount Protocol Flags Type St Inode Path\n0000000000000000: 00000002 00000000 00010000 0001 01 123 /run/open-card-buildkit/buildkitd.sock\n")
	facts, err := parseLinuxListenerFacts(tcp, tcp6, unix)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts.TCP) != 4 || len(facts.Unix) != 1 || facts.Unix[0] != buildkitSocket {
		t.Fatalf("facts=%+v", facts)
	}
	want := map[TCPListener]bool{
		{Address: netip.MustParseAddr("0.0.0.0"), Port: 80}:     false,
		{Address: netip.MustParseAddr("127.0.0.1"), Port: 5432}: false,
		{Address: netip.MustParseAddr("::"), Port: 443}:         false,
		{Address: netip.MustParseAddr("::1"), Port: 22}:         false,
	}
	for _, listener := range facts.TCP {
		if _, ok := want[listener]; !ok {
			t.Fatalf("unexpected listener=%+v", listener)
		}
		want[listener] = true
	}
	for listener, found := range want {
		if !found {
			t.Fatalf("missing listener=%+v", listener)
		}
	}
}

func TestParseLinuxListenerFactsRejectsMalformedOversizeAndDuplicate(t *testing.T) {
	validTCP := []byte("sl local_address rem_address st\n0: 00000000:0050 00000000:0000 0A\n")
	validTCP6 := []byte("sl local_address rem_address st\n")
	validUnix := []byte("Num RefCount Protocol Flags Type St Inode Path\n")
	for _, tc := range []struct {
		name string
		tcp  []byte
		tcp6 []byte
		unix []byte
	}{
		{name: "malformed tcp", tcp: []byte("sl local_address rem_address st\n0: broken 0 0A\n"), tcp6: validTCP6, unix: validUnix},
		{name: "malformed unix", tcp: validTCP, tcp6: validTCP6, unix: []byte("Num RefCount Protocol Flags Type St Inode Path\ninvalid\n")},
		{name: "duplicate", tcp: append(append([]byte(nil), validTCP...), []byte("1: 00000000:0050 00000000:0000 0A\n")...), tcp6: validTCP6, unix: validUnix},
		{name: "oversize", tcp: append(validTCP, bytesOfSize(maxListenerFactBytes+1)...), tcp6: validTCP6, unix: validUnix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseLinuxListenerFacts(tc.tcp, tc.tcp6, tc.unix); err == nil || err.Error() != errListenerFacts.Error() {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestListenerProbeBaselineMissingAndExposureRules(t *testing.T) {
	baseline := listenerBaseline(nil)
	for _, tc := range []struct {
		name     string
		facts    ListenerFacts
		want     Severity
		mutation string
	}{
		{name: "baseline", facts: baseline, want: SeverityOK},
		{name: "missing buildkit", facts: withoutUnix(baseline, buildkitSocket), want: SeverityCritical},
		{name: "missing public", facts: withoutTCP(baseline, TCPListener{Address: netip.MustParseAddr("0.0.0.0"), Port: 443}), want: SeverityCritical},
		{name: "duplicate fact", facts: appendTCP(baseline, loopbackTCP(5432)), want: SeverityEmergency},
		{name: "wildcard core", facts: appendTCP(baseline, TCPListener{Address: netip.MustParseAddr("0.0.0.0"), Port: 5432}), want: SeverityEmergency},
		{name: "unexpected public", facts: appendTCP(baseline, TCPListener{Address: netip.MustParseAddr("192.0.2.10"), Port: 9090}), want: SeverityEmergency},
		{name: "unexpected ipv6 public", facts: appendTCP(baseline, TCPListener{Address: netip.MustParseAddr("2001:db8::10"), Port: 9090}), want: SeverityEmergency},
		{name: "unexpected ipv4 loopback", facts: appendTCP(baseline, TCPListener{Address: netip.MustParseAddr("127.0.0.1"), Port: 40000}), want: SeverityEmergency},
		{name: "unexpected alternate loopback", facts: appendTCP(baseline, TCPListener{Address: netip.MustParseAddr("127.0.0.2"), Port: 40000}), want: SeverityEmergency},
		{name: "unexpected ipv6 loopback", facts: appendTCP(baseline, TCPListener{Address: netip.MustParseAddr("::1"), Port: 40000}), want: SeverityEmergency},
		{name: "ipv6 wildcard core", facts: appendTCP(baseline, TCPListener{Address: netip.MustParseAddr("::"), Port: 5432}), want: SeverityEmergency},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := listenerProbeForTest(t, tc.facts, nil, nil)
			fact, err := probe.Check(context.Background())
			if err != nil || fact.Severity != tc.want || fact.Subject != listenerSubject {
				t.Fatalf("fact=%+v err=%v", fact, err)
			}
		})
	}
}

func TestListenerProbeRequiresDynamicPortsAndRetainsOnlySSHException(t *testing.T) {
	facts := listenerBaseline([]uint16{30000, 30001})
	probe := listenerProbeForTest(t, facts, []uint16{30000, 30001}, nil)
	fact, err := probe.Check(context.Background())
	if err != nil || fact.Severity != SeverityOK {
		t.Fatalf("dynamic fact=%+v err=%v", fact, err)
	}
	probe = listenerProbeForTest(t, withoutTCP(facts, loopbackTCP(30001)), []uint16{30000, 30001}, nil)
	fact, err = probe.Check(context.Background())
	if err != nil || fact.Severity != SeverityCritical {
		t.Fatalf("missing dynamic fact=%+v err=%v", fact, err)
	}
	for _, ports := range [][]uint16{{0}, {30000, 30000}} {
		probe = listenerProbeForTest(t, facts, ports, nil)
		fact, err = probe.Check(context.Background())
		if err != nil || fact.Severity != SeverityEmergency {
			t.Fatalf("ports=%v fact=%+v err=%v", ports, fact, err)
		}
	}

	ssh := appendTCP(listenerBaseline(nil), TCPListener{Address: netip.MustParseAddr("0.0.0.0"), Port: 22})
	probe = listenerProbeForTest(t, ssh, nil, FixedSSHPort22Policy{})
	fact, err = probe.Check(context.Background())
	if err != nil || fact.Severity != SeverityOK {
		t.Fatalf("ssh exception fact=%+v err=%v", fact, err)
	}
	probe = listenerProbeForTest(t, appendTCP(listenerBaseline(nil), TCPListener{Address: netip.MustParseAddr("0.0.0.0"), Port: 2222}), nil, FixedSSHPort22Policy{})
	fact, err = probe.Check(context.Background())
	if err != nil || fact.Severity != SeverityEmergency {
		t.Fatalf("non-ssh fact=%+v err=%v", fact, err)
	}
}

func TestListenerProbePublicWildcardFamilyPolicy(t *testing.T) {
	facts := listenerBaseline(nil)
	facts = withoutTCP(facts, TCPListener{Address: netip.MustParseAddr("0.0.0.0"), Port: 80})
	facts = withoutTCP(facts, TCPListener{Address: netip.MustParseAddr("0.0.0.0"), Port: 443})
	facts = appendTCP(facts, TCPListener{Address: netip.MustParseAddr("::"), Port: 80})
	facts = appendTCP(facts, TCPListener{Address: netip.MustParseAddr("::"), Port: 443})
	probe := listenerProbeForTest(t, facts, nil, nil)
	if fact, err := probe.Check(context.Background()); err != nil || fact.Severity != SeverityOK {
		t.Fatalf("IPv6 public wildcard fact=%+v err=%v", fact, err)
	}
	mixed := appendTCP(listenerBaseline(nil), TCPListener{Address: netip.MustParseAddr("::"), Port: 80})
	probe = listenerProbeForTest(t, mixed, nil, nil)
	if fact, err := probe.Check(context.Background()); err != nil || fact.Severity != SeverityOK {
		t.Fatalf("mixed public wildcard fact=%+v err=%v", fact, err)
	}
}

func TestListenerProbeRedactsOperationalErrorsAndHonorsCancellation(t *testing.T) {
	secret := "postgresql://user:secret@example.invalid/private"
	probe, err := NewListenerProbe(ListenerSourceFunc(func(context.Context) (ListenerFacts, error) {
		return ListenerFacts{}, errors.New(secret)
	}), RuntimePortSourceFunc(func(context.Context) ([]uint16, error) { return nil, nil }), FixedSSHPort22Policy{})
	if err != nil {
		t.Fatal(err)
	}
	fact, err := probe.Check(context.Background())
	if err != nil || fact.Severity != SeverityEmergency || fact.Subject != listenerSubject || strings.Contains(fact.Subject, secret) {
		t.Fatalf("fact=%+v err=%v", fact, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fact, err = probe.Check(ctx)
	if err == nil || fact.Severity != SeverityEmergency || strings.Contains(err.Error(), secret) {
		t.Fatalf("cancel fact=%+v err=%v", fact, err)
	}
}

func TestListenerProbeSubjectIsDeterministic(t *testing.T) {
	first := listenerProbeForTest(t, listenerBaseline(nil), nil, nil)
	second := listenerProbeForTest(t, appendTCP(listenerBaseline(nil), TCPListener{Address: netip.MustParseAddr("127.0.0.1"), Port: 40000}), nil, nil)
	one, err := first.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	two, err := second.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if one.Subject != listenerSubject || one.Subject != two.Subject || two.Severity != SeverityEmergency {
		t.Fatalf("subjects=%q,%q", one.Subject, two.Subject)
	}
}

func listenerProbeForTest(t *testing.T, facts ListenerFacts, ports []uint16, policy SSHListenerPolicy) HostProbe {
	t.Helper()
	if policy == nil {
		policy = FixedSSHPort22Policy{}
	}
	probe, err := NewListenerProbe(
		ListenerSourceFunc(func(context.Context) (ListenerFacts, error) { return facts, nil }),
		RuntimePortSourceFunc(func(context.Context) ([]uint16, error) { return ports, nil }),
		policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	return probe
}

func listenerBaseline(dynamic []uint16) ListenerFacts {
	facts := ListenerFacts{Unix: []string{buildkitSocket}}
	for _, port := range publicPorts {
		facts.TCP = append(facts.TCP, TCPListener{Address: netip.MustParseAddr("0.0.0.0"), Port: port})
	}
	for _, port := range coreLoopbackPorts {
		facts.TCP = append(facts.TCP, loopbackTCP(port))
	}
	for _, port := range dynamic {
		facts.TCP = append(facts.TCP, loopbackTCP(port))
	}
	return facts
}

func loopbackTCP(port uint16) TCPListener {
	return TCPListener{Address: netip.MustParseAddr("127.0.0.1"), Port: port}
}

func appendTCP(facts ListenerFacts, listener TCPListener) ListenerFacts {
	facts.TCP = append(append([]TCPListener(nil), facts.TCP...), listener)
	return facts
}

func withoutTCP(facts ListenerFacts, remove TCPListener) ListenerFacts {
	next := ListenerFacts{Unix: append([]string(nil), facts.Unix...)}
	for _, listener := range facts.TCP {
		if listener != remove {
			next.TCP = append(next.TCP, listener)
		}
	}
	return next
}

func withoutUnix(facts ListenerFacts, remove string) ListenerFacts {
	next := ListenerFacts{TCP: append([]TCPListener(nil), facts.TCP...)}
	for _, socket := range facts.Unix {
		if socket != remove {
			next.Unix = append(next.Unix, socket)
		}
	}
	return next
}

func bytesOfSize(size int) []byte { return make([]byte, size) }
