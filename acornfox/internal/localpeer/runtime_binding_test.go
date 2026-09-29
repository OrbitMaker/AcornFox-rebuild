package localpeer

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOptionalSourceBuildBindingPreservesTwoRoleProfile(t *testing.T) {
	b := RuntimePeerBinding{Version: BindingVersion1, InstallationID: "fixture", CoreUID: 1000, CorePID: 10, CoreExeSHA: strings.Repeat("a", 64), CoreStartTime: "100", ContainerUID: 1001, ContainerPID: 11, ContainerExeSHA: strings.Repeat("b", 64), ContainerStartTime: "101", ContainerSocket: "/run/acornfox/container.sock", AuthoritySocket: "/run/acornfox/authority.sock"}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(b)
	digest := b.Digest()
	if strings.Contains(string(raw), "source_build") {
		t.Fatal("old profile wire/digest changed")
	}
	parsed, err := ParseRuntimePeerBinding(raw)
	if err != nil || parsed.Digest() != digest || parsed.HasSourceBuild() {
		t.Fatal("old profile no longer roundtrips")
	}
	b.SourceBuildPID = 12
	if b.Validate() == nil {
		t.Fatal("partial source tuple accepted")
	}
	b.SourceBuildUID = 1002
	b.SourceBuildExeSHA = strings.Repeat("c", 64)
	b.SourceBuildStartTime = "102"
	b.SourceBuildSocket = "/run/acornfox/source.sock"
	b.SourceBuildAuthoritySocket = "/run/acornfox/source-authority.sock"
	raw, _ = json.Marshal(b)
	parsed, err = ParseRuntimePeerBinding(raw)
	if err != nil || !parsed.HasSourceBuild() || parsed.Digest() == digest {
		t.Fatal("complete source profile not bound")
	}
	b.SourceBuildSocket = "/run/acornfox/x/../container.sock"
	if b.Validate() == nil {
		t.Fatal("source socket lexical alias accepted")
	}
	b.SourceBuildSocket = "/run/acornfox/container.sock"
	b.ContainerSocket = "/run/acornfox/x/../container.sock"
	if b.Validate() == nil {
		t.Fatal("legacy container path lexical alias bypassed distinct source socket")
	}
	b.SourceBuildSocket = b.ContainerSocket
	if b.Validate() == nil {
		t.Fatal("source socket aliases container")
	}
}

func TestOptionalGatewayBindingRequiresWholeDistinctPeer(t *testing.T) {
	b := RuntimePeerBinding{Version: BindingVersion1, InstallationID: "fixture", CoreUID: 1000, CorePID: 10, CoreExeSHA: strings.Repeat("a", 64), CoreStartTime: "100", ContainerUID: 1001, ContainerPID: 11, ContainerExeSHA: strings.Repeat("b", 64), ContainerStartTime: "101", ContainerSocket: "/run/acornfox/container-ipc/container.sock", AuthoritySocket: "/run/acornfox/core-ipc/container-authority.sock"}
	oldDigest := b.Digest()
	if b.Validate() != nil || b.HasGateway() {
		t.Fatal("old binding profile changed")
	}
	b.GatewayPID = 12
	if b.Validate() == nil {
		t.Fatal("partial Gateway PID accepted")
	}
	b.GatewayUID = 1003
	b.GatewayExeSHA = strings.Repeat("c", 64)
	b.GatewayStartTime = "102"
	b.GatewaySocket = "/run/acornfox/gateway-ipc/gateway.sock"
	b.GatewayAuthoritySocket = "/run/acornfox/core-ipc/gateway-authority.sock"
	if err := b.Validate(); err != nil || !b.HasGateway() || b.Digest() == oldDigest {
		t.Fatalf("complete Gateway tuple failed: %v", err)
	}
	raw, _ := json.Marshal(b)
	if parsed, err := ParseRuntimePeerBinding(raw); err != nil || !parsed.HasGateway() || parsed.Digest() != b.Digest() {
		t.Fatal("Gateway binding did not roundtrip")
	}
	b.GatewayAuthoritySocket = b.ContainerSocket
	if b.Validate() == nil {
		t.Fatal("Gateway authority aliased Container socket")
	}
	b.GatewayAuthoritySocket = "/run/acornfox/core-ipc/gateway-authority.sock"
	b.GatewayPID = b.CorePID
	if b.Validate() == nil {
		t.Fatal("Gateway PID aliased Core")
	}
}
