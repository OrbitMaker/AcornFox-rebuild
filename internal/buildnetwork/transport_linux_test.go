//go:build linux

package buildnetwork

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixAttestationBindsPeerAndRequest(t *testing.T) {
	// Unix socket paths are bounded by the kernel; test names can exceed that
	// bound when the caller supplies a secure, longer TMPDIR.
	root, err := os.MkdirTemp("", "af-attest-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	for _, scenario := range []string{"valid", "wrong-peer", "wrong-fingerprint", "unknown-field"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(root, "attest.sock")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := listener.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				var r AttestationRequest
				if json.NewDecoder(c).Decode(&r) != nil {
					return
				}
				receipt := map[string]any{"schema_version": 1, "policy_digest": r.PolicyDigest, "request_fingerprint": r.RequestFingerprint}
				if scenario == "wrong-fingerprint" {
					receipt["request_fingerprint"] = strings.Repeat("b", 64)
				}
				if scenario == "unknown-field" {
					receipt["unsafe"] = true
				}
				json.NewEncoder(c).Encode(receipt)
			}()
			uid := uint32(os.Geteuid())
			if scenario == "wrong-peer" {
				uid++
			}
			r := AttestationRequest{SchemaVersion: 1, PolicyDigest: "sha256:" + strings.Repeat("a", 64), RequestFingerprint: strings.Repeat("c", 64)}
			_, err = attestSocket(context.Background(), path, r, uid)
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("scenario=%s err=%v", scenario, err)
			}
			<-done
		})
	}
}

func TestKernelFingerprintIgnoresOnlyVolatileMetadata(t *testing.T) {
	a := []byte(`{"nftables":[{"metainfo":{"version":"a"}},{"rule":{"handle":1,"expr":[{"counter":{"packets":2,"bytes":3}},{"drop":null}]}}]}`)
	b := []byte(`{"nftables":[{"metainfo":{"version":"b"}},{"rule":{"handle":2,"expr":[{"counter":{"packets":20,"bytes":30}},{"drop":null}]}}]}`)
	x, _ := kernelHash(a)
	y, _ := kernelHash(b)
	if x != y {
		t.Fatal("counter changes broke identity")
	}
	z, _ := kernelHash([]byte(strings.Replace(string(b), "drop", "accept", 1)))
	if x == z {
		t.Fatal("policy action drift ignored")
	}
}

func TestIPRouteLinkAliasIsDecoded(t *testing.T) {
	var value linkInfo
	if err := json.Unmarshal([]byte(`{"ifindex":5,"ifname":"acornfox-bh","ifalias":"owned-token"}`), &value); err != nil || value.Alias != "owned-token" || value.Index != 5 {
		t.Fatal(value, err)
	}
}
