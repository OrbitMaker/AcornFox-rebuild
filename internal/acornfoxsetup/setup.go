// Package acornfoxsetup generates a closed, in-memory first-run configuration.
// It never writes files, changes ownership, logs key material, or attests host
// isolation. Callers must persist private intent securely before publishing the
// files, and create /etc/acornfox/runtime as root:root 0755. Certificate renewal
// is a separate lifecycle: certificates expire 365 days after Inputs.Now and
// the CA private key is deliberately not retained.
// Both private key sources are root:root 0600. Callers must provision systemd
// LoadCredential entries so each service receives only its own private key.
package acornfoxsetup

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Role string

const (
	Root              Role = "root"
	Server            Role = "server" // acornfox group
	Agent             Role = "agent"  // acornfox-agent group
	RuntimeDirectory       = "/etc/acornfox/runtime"
	ServerEnvironment      = RuntimeDirectory + "/server.env"
	AgentEnvironment       = RuntimeDirectory + "/agent.env"
	GatewayName            = "acornfox-agent-gateway"
	InstanceID             = "acornfox-local"
	NodeID                 = "acornfox-node"
)

// Inputs is the caller's trusted generation intent. Preserve Now for replay
// validation; validation checks the original one-year lifetime, not wall time.
// Origin must be an exact HTTPS origin without a path or trailing slash.
// ResolverEndpoints must contain 2–8 distinct, canonical public IP:53 values.
type Inputs struct {
	Origin            string
	Version           string
	ResolverEndpoints []string
	Now               time.Time
}

// File has symbolic ownership and Unix permission bits, not host UIDs/GIDs.
// Data is deliberately omitted by JSON and all fmt verbs. Explicit Data access
// is sensitive and only intended for the caller's private persistence boundary.
type File struct {
	Path  string
	Mode  uint32
	Owner Role
	Group Role
	Data  []byte `json:"-"`
}

type Bundle struct{ Files []File }

func (File) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "acornfoxsetup.File{redacted}") }
func (Bundle) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "acornfoxsetup.Bundle{redacted}") }

var errInvalid = errors.New("invalid AcornFox setup bundle")

// Generate uses only the caller's random source. Supply crypto/rand.Reader in
// production. On any error it returns an empty bundle and no private material.
func Generate(input Inputs, randomness io.Reader) (Bundle, error) {
	if err := validateInputs(input); err != nil {
		return Bundle{}, err
	}
	if randomness == nil {
		return Bundle{}, errors.New("AcornFox setup randomness is required")
	}
	ca, caKey, err := generateCertificate(input.Now, "ca", nil, nil, randomness)
	if err != nil {
		return Bundle{}, errInvalid
	}
	server, serverKey, err := generateCertificate(input.Now, "server", ca, caKey, randomness)
	if err != nil {
		return Bundle{}, errInvalid
	}
	agent, agentKey, err := generateCertificate(input.Now, "agent", ca, caKey, randomness)
	if err != nil {
		return Bundle{}, errInvalid
	}
	bundle := Bundle{Files: fileSpecs()}
	bundle.Files[0].Data = serverEnv(input, agent.SerialNumber.String())
	bundle.Files[1].Data = agentEnv(input)
	bundle.Files[2].Data = certificatePEM(ca)
	bundle.Files[3].Data = certificatePEM(server)
	bundle.Files[4].Data = privatePEM(serverKey)
	bundle.Files[5].Data = certificatePEM(agent)
	bundle.Files[6].Data = privatePEM(agentKey)
	if err := Validate(bundle, input); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func fileSpecs() []File {
	return []File{
		{Path: ServerEnvironment, Mode: 0644, Owner: Root, Group: Root},
		{Path: AgentEnvironment, Mode: 0644, Owner: Root, Group: Root},
		{Path: RuntimeDirectory + "/ca.crt", Mode: 0644, Owner: Root, Group: Root},
		{Path: RuntimeDirectory + "/server.crt", Mode: 0644, Owner: Root, Group: Root},
		{Path: RuntimeDirectory + "/server.key", Mode: 0600, Owner: Root, Group: Root},
		{Path: RuntimeDirectory + "/agent.crt", Mode: 0644, Owner: Root, Group: Root},
		{Path: RuntimeDirectory + "/agent.key", Mode: 0600, Owner: Root, Group: Root},
	}
}

// Validate rejects extra, missing, duplicate, relocated or incorrectly owned
// files; noncanonical bytes; mismatched keys, certificate profiles, signatures,
// and env bindings. It validates consistency against trusted Inputs, not intent
// authenticity: the caller must protect persisted intent against replacement.
func Validate(bundle Bundle, input Inputs) error {
	if err := validateInputs(input); err != nil {
		return err
	}
	specs := fileSpecs()
	if len(bundle.Files) != len(specs) {
		return errInvalid
	}
	files := make(map[string][]byte, len(specs))
	for _, f := range bundle.Files {
		if _, exists := files[f.Path]; exists {
			return errInvalid
		}
		found := false
		for _, spec := range specs {
			if f.Path == spec.Path && f.Mode == spec.Mode && f.Owner == spec.Owner && f.Group == spec.Group {
				found = true
				break
			}
		}
		if !found || len(f.Data) == 0 || len(f.Data) > 16384 {
			return errInvalid
		}
		files[f.Path] = f.Data
	}
	ca, err := parseCertificate(files[RuntimeDirectory+"/ca.crt"])
	if err != nil {
		return errInvalid
	}
	server, err := parseCertificate(files[RuntimeDirectory+"/server.crt"])
	if err != nil {
		return errInvalid
	}
	agent, err := parseCertificate(files[RuntimeDirectory+"/agent.crt"])
	if err != nil {
		return errInvalid
	}
	if ca.SerialNumber.Cmp(server.SerialNumber) == 0 || ca.SerialNumber.Cmp(agent.SerialNumber) == 0 || server.SerialNumber.Cmp(agent.SerialNumber) == 0 {
		return errInvalid
	}
	if !validProfile(ca, ca, "ca", input.Now) || !validProfile(server, ca, "server", input.Now) || !validProfile(agent, ca, "agent", input.Now) {
		return errInvalid
	}
	if !validKey(files[RuntimeDirectory+"/server.key"], server) || !validKey(files[RuntimeDirectory+"/agent.key"], agent) {
		return errInvalid
	}
	if bytes.Equal(server.RawSubjectPublicKeyInfo, agent.RawSubjectPublicKeyInfo) || bytes.Equal(ca.RawSubjectPublicKeyInfo, server.RawSubjectPublicKeyInfo) || bytes.Equal(ca.RawSubjectPublicKeyInfo, agent.RawSubjectPublicKeyInfo) {
		return errInvalid
	}
	if !bytes.Equal(files[ServerEnvironment], serverEnv(input, agent.SerialNumber.String())) || !bytes.Equal(files[AgentEnvironment], agentEnv(input)) {
		return errInvalid
	}
	return nil
}

func template(now time.Time, kind string, serial *big.Int) *x509.Certificate {
	c := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "acornfox-" + kind}, NotBefore: now.UTC().Truncate(time.Second).Add(-5 * time.Minute), NotAfter: now.UTC().Truncate(time.Second).Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	switch kind {
	case "ca":
		c.IsCA = true
		c.MaxPathLenZero = true
		c.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	case "server":
		c.Subject.CommonName = GatewayName
		c.DNSNames = []string{GatewayName}
		c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "agent":
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	return c
}

func generateCertificate(now time.Time, kind string, parent *x509.Certificate, parentKey ed25519.PrivateKey, random io.Reader) (*x509.Certificate, ed25519.PrivateKey, error) {
	pub, key, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(random, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	serial.Add(serial, big.NewInt(1))
	c := template(now, kind, serial)
	if parent == nil {
		parent, parentKey = c, key
	}
	der, err := x509.CreateCertificate(random, c, parent, pub, parentKey)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	return parsed, key, err
}

func certificatePEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
func privatePEM(key ed25519.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(key) // Ed25519 always has PKCS#8 support.
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
func parseCertificate(data []byte) (*x509.Certificate, error) {
	b, rest := pem.Decode(data)
	if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 || len(rest) != 0 || !bytes.Equal(data, pem.EncodeToMemory(b)) {
		return nil, errInvalid
	}
	return x509.ParseCertificate(b.Bytes)
}
func validKey(data []byte, c *x509.Certificate) bool {
	b, rest := pem.Decode(data)
	if b == nil || b.Type != "PRIVATE KEY" || len(b.Headers) != 0 || len(rest) != 0 || !bytes.Equal(data, pem.EncodeToMemory(b)) {
		return false
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	key, ok := k.(ed25519.PrivateKey)
	pub, pubOK := c.PublicKey.(ed25519.PublicKey)
	return err == nil && ok && pubOK && bytes.Equal(key.Public().(ed25519.PublicKey), pub) && bytes.Equal(data, privatePEM(key))
}

// Recreating the deterministic Ed25519 TBS certificate from the exact profile
// detects arbitrary extension/subject/SAN/lifetime drift without a fragile
// hand-maintained list of parsed x509 fields. The dummy signing key is never a
// trust source; the original certificate's real signature is checked first.
func validProfile(c, ca *x509.Certificate, kind string, now time.Time) bool {
	if c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 || c.SerialNumber.Cmp(new(big.Int).Lsh(big.NewInt(1), 128)) > 0 || c.PublicKeyAlgorithm != x509.Ed25519 || c.SignatureAlgorithm != x509.PureEd25519 || c.CheckSignatureFrom(ca) != nil {
		return false
	}
	want := template(now, kind, c.SerialNumber)
	parent := ca
	if kind == "ca" {
		parent = want
	}
	dummy := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	// CreateCertificate requires signer and parent's public key to agree. Copy
	// the public parent metadata but substitute only its PublicKey for signing.
	copyParent := *parent
	copyParent.PublicKey = dummy.Public()
	der, err := x509.CreateCertificate(nil, want, &copyParent, c.PublicKey, dummy)
	if err != nil {
		return false
	}
	recreated, err := x509.ParseCertificate(der)
	return err == nil && bytes.Equal(c.RawTBSCertificate, recreated.RawTBSCertificate)
}

var safeVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$`)
var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var forbiddenNetworks = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "2620:4f:8000::/48", "3fff::/20", "5f00::/16"}

func validateInputs(in Inputs) error {
	if in.Now.IsZero() || in.Now.Year() < 2000 || in.Now.Year() > 9998 || !safeVersion.MatchString(in.Version) {
		return errors.New("invalid AcornFox setup version or generation time")
	}
	u, err := url.Parse(in.Origin)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || in.Origin != "https://"+u.Host {
		return errors.New("AcornFox setup requires an exact HTTPS origin")
	}
	host := u.Hostname()
	authority := host
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || ip.String() != host {
			return errInvalid
		}
		if ip.Is6() {
			authority = "[" + host + "]"
		}
	} else {
		if len(host) > 253 {
			return errInvalid
		}
		for _, label := range strings.Split(host, ".") {
			if !dnsLabel.MatchString(label) {
				return errInvalid
			}
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return errInvalid
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != port {
			return errInvalid
		}
		authority += ":" + port
	}
	if u.Host != authority {
		return errInvalid
	}
	if len(in.ResolverEndpoints) < 2 || len(in.ResolverEndpoints) > 8 {
		return errors.New("AcornFox setup requires 2 to 8 distinct public DNS endpoints")
	}
	seen := map[netip.Addr]bool{}
	for _, raw := range in.ResolverEndpoints {
		p, err := netip.ParseAddrPort(raw)
		if err != nil || p.String() != raw || p.Port() != 53 || !publicAddress(p.Addr()) || seen[p.Addr()] {
			return errors.New("invalid AcornFox setup public DNS endpoint")
		}
		seen[p.Addr()] = true
	}
	return nil
}
func publicAddress(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, raw := range forbiddenNetworks {
		if netip.MustParsePrefix(raw).Contains(ip) {
			return false
		}
	}
	return true
}

// Every value is single-quoted for systemd EnvironmentFile syntax, preserving
// JSON double quotes. Inputs forbid apostrophes, control bytes and expansion.
func environment(values map[string]string) []byte {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, k := range keys {
		out.WriteString("ACORNFOX_" + k + "='" + values[k] + "'\n")
	}
	return []byte(out.String())
}
func serverEnv(in Inputs, serial string) []byte {
	return environment(map[string]string{
		"RUNTIME_MODE": "clean", "M1_ENABLED": "true", "AUTH_ORIGIN": in.Origin, "AGENT_GATEWAY_ADDR": "127.0.0.1:8092",
		"SERVER_AGENT_TLS_CA": RuntimeDirectory + "/ca.crt", "SERVER_AGENT_TLS_CERT": RuntimeDirectory + "/server.crt", "SERVER_AGENT_TLS_KEY": "/run/credentials/acornfox-server.service/server.key",
		"AGENT_IDENTITIES_JSON":      `[{"certificate_id":"` + serial + `","instance_id":"` + InstanceID + `","node_id":"` + NodeID + `"}]`,
		"AGENT_DISPATCH_INSTANCE_ID": InstanceID, "AGENT_DISPATCH_NODE_ID": NodeID,
		"SOURCE_UPLOAD_ROOT": "/var/lib/acornfox/uploads", "SOURCE_WORKSPACE_ROOT": "/var/lib/acornfox/workspaces", "BUILD_WORK_ROOT": "/var/lib/acornfox/build-work", "LOG_ROOT": "/var/log/acornfox/server", "OCI_STORE_ROOT": "/var/lib/acornfox/oci", "SECRET_ROOT": "/var/lib/acornfox/secrets", "SECRET_MATERIAL_ROOT": "/var/lib/acornfox/secret-materials", "SECRET_MASTER_KEY": "/var/lib/acornfox/secrets/master.key", "SOURCE_GIT_RESOLVERS": strings.Join(in.ResolverEndpoints, ","),
		"BUILDKIT_COMMAND": "/opt/acornfox/current/bin/buildctl", "BUILDKIT_WORKER": "acornfox-installed", "BUILDKIT_ADDRESS": "unix:///run/acornfox-buildkit/buildkitd.sock",
	})
}
func agentEnv(in Inputs) []byte {
	return environment(map[string]string{
		"RUNTIME_MODE": "clean", "CONTROL_PLANE_URL": "https://127.0.0.1:8092", "CONTROL_PLANE_SERVER_NAME": GatewayName,
		"AGENT_TLS_CA": RuntimeDirectory + "/ca.crt", "AGENT_TLS_CERT": RuntimeDirectory + "/agent.crt", "AGENT_TLS_KEY": "/run/credentials/acornfox-agent.service/agent.key",
		"INSTANCE_ID": InstanceID, "NODE_ID": NodeID, "AGENT_VERSION": in.Version,
		"RUNTIME_ENABLED": "true", "WORKER_NETWORK_ISOLATED": "true", "OCI_STORE_ROOT": "/var/lib/acornfox/oci", "RUNTIME_WORK_ROOT": "/var/lib/acornfox/agent", "RUNTIME_TASK_PREFIX": "acornfox", "RUNTIME_NETWORK": "acornfox-network",
	})
}
