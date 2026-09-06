package runtimenetwork

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

type fakeHost struct {
	intent, runtime, table, network []byte
	bridge                          bool
	mutations                       []string
	failAt                          string
	failAfter                       bool
}

func (f *fakeHost) readIntent() ([]byte, error) {
	if f.intent == nil {
		return nil, os.ErrNotExist
	}
	return f.intent, nil
}
func (f *fakeHost) writeIntent(raw []byte, create bool) error {
	if create && f.intent != nil {
		panic("overwrote intent")
	}
	f.mutations = append(f.mutations, "intent")
	f.intent = append([]byte{}, raw...)
	return nil
}
func (f *fakeHost) readRuntime() ([]byte, error) {
	if f.runtime == nil {
		return nil, os.ErrNotExist
	}
	return f.runtime, nil
}
func (f *fakeHost) writeRuntime(raw []byte, create bool) error {
	if create && f.runtime != nil {
		panic("overwrote runtime state")
	}
	f.mutations = append(f.mutations, "runtime")
	f.runtime = append([]byte{}, raw...)
	return nil
}
func (f *fakeHost) ready(context.Context) error { return nil }
func (f *fakeHost) random(raw []byte) error {
	for i := range raw {
		raw[i] = 1
	}
	return nil
}
func (f *fakeHost) close() error { return nil }
func (f *fakeHost) run(_ context.Context, path string, args []string, input []byte) ([]byte, error) {
	action := strings.Join(args, " ")
	if f.failAt != "" && strings.Contains(action, f.failAt) && !f.failAfter {
		return nil, errors.New("credential-canary")
	}
	switch path {
	case "/usr/bin/docker":
		switch args[1] {
		case "ls":
			if f.network == nil {
				return nil, nil
			}
			var n []dockerNetwork
			_ = json.Unmarshal(f.network, &n)
			return []byte(n[0].ID + "\n"), nil
		case "inspect":
			if f.network == nil {
				return nil, ErrUnavailable
			}
			return f.network, nil
		case "create":
			if f.network != nil {
				panic("network replacement")
			}
			i, err := parseIntent(f.intent)
			if err != nil {
				return nil, err
			}
			// Verify that every explicit option/label was passed and no global flag.
			required := map[string]string{}
			for k, v := range dockerOptions() {
				required[k] = v
			}
			for k, v := range dockerLabels(i.Owner) {
				required[k] = v
			}
			for k, v := range required {
				if !strings.Contains(action, k+"="+v) {
					panic("missing network option")
				}
			}
			if len(f.table) == 0 {
				panic("network created before filtering")
			}
			f.network = networkFixture(i.Owner)
			f.bridge = true
			f.mutations = append(f.mutations, "network")
			if f.failAfter && strings.Contains(action, f.failAt) {
				return nil, errors.New("credential-canary")
			}
			return []byte(strings.Repeat("a", 64)), nil
		}
	case "/usr/sbin/ip":
		if args[2] == "link" {
			if f.bridge {
				return []byte(`[{"ifindex":7,"ifname":"acornfox-r0","linkinfo":{"info_kind":"bridge","info_data":{"stp_state":0}}}]`), nil
			}
			return []byte(`[]`), nil
		}
		return []byte(`[{"ifname":"acornfox-r0","addr_info":[{"family":"inet","local":"10.203.254.1","prefixlen":24}]}]`), nil
	case "/usr/sbin/nft":
		if reflect.DeepEqual(args, []string{"-j", "list", "tables"}) {
			if f.table != nil {
				return []byte(`{"nftables":[{"metainfo":{"version":"1.0.9"}},{"table":{"family":"inet","name":"acornfox_runtime_guard","handle":10}}]}`), nil
			}
			return []byte(`{"nftables":[]}`), nil
		}
		if args[1] == "-f" {
			if f.table != nil {
				panic("table replacement")
			}
			var doc struct {
				NFTables []map[string]json.RawMessage `json:"nftables"`
			}
			if json.Unmarshal(input, &doc) != nil {
				panic("bad policy")
			}
			entries := []json.RawMessage{}
			for i, entry := range doc.NFTables {
				verb := "add"
				if i == 0 {
					verb = "create"
				}
				if len(entry) != 1 || entry[verb] == nil {
					panic("not atomic create")
				}
				entries = append(entries, entry[verb])
			}
			f.table, _ = json.Marshal(object{"nftables": entries})
			f.mutations = append(f.mutations, "firewall")
			if f.failAfter && strings.Contains(action, f.failAt) {
				return nil, errors.New("credential-canary")
			}
			return nil, nil
		}
		if f.table == nil {
			return nil, ErrUnavailable
		}
		return f.table, nil
	}
	panic("unexpected command " + path + " " + action)
}
func networkFixture(owner string) []byte {
	raw, _ := json.Marshal([]object{{
		"Name": Network, "Id": strings.Repeat("a", 64), "Created": "2026-09-06T01:02:03Z", "Scope": "local", "Driver": "bridge", "EnableIPv6": false, "Internal": false, "Attachable": false, "Ingress": false, "ConfigOnly": false,
		"IPAM":    object{"Driver": "default", "Options": nil, "Config": []object{{"Subnet": Subnet, "Gateway": Gateway}}},
		"Options": dockerOptions(), "Labels": dockerLabels(owner), "Containers": object{},
	}})
	return raw
}

func TestEnsureThenReadOnlyVerifyAndRebootRecovery(t *testing.T) {
	f := &fakeHost{}
	receipt, err := reconcile(context.Background(), f, true)
	if err != nil || receipt.NetworkID != strings.Repeat("a", 64) || receipt.SchemaVersion != 1 {
		t.Fatalf("receipt=%+v error=%v", receipt, err)
	}
	if !reflect.DeepEqual(f.mutations, []string{"intent", "firewall", "network", "intent", "runtime"}) {
		t.Fatalf("order=%v", f.mutations)
	}
	f.mutations = nil
	if _, err := reconcile(context.Background(), f, false); err != nil || len(f.mutations) != 0 {
		t.Fatalf("verify: %v mutations=%v", err, f.mutations)
	}
	if _, err := reconcile(context.Background(), f, true); err != nil || len(f.mutations) != 0 {
		t.Fatalf("replay: %v mutations=%v", err, f.mutations)
	}
	// Docker retains the network across reboot; nft and /run do not persist.
	f.table = nil
	f.runtime = nil
	if _, err := reconcile(context.Background(), f, false); err == nil || len(f.mutations) != 0 {
		t.Fatal("Verify repaired absent protection")
	}
	again, err := reconcile(context.Background(), f, true)
	if err != nil || again != receipt || !reflect.DeepEqual(f.mutations, []string{"firewall", "runtime"}) {
		t.Fatalf("reboot=%+v err=%v mutations=%v", again, err, f.mutations)
	}
}

func TestHalfSuccessfulCreationsRemainReplayable(t *testing.T) {
	for _, action := range []string{"-f", "network create"} {
		t.Run(action, func(t *testing.T) {
			f := &fakeHost{failAt: action, failAfter: true}
			if _, err := reconcile(context.Background(), f, true); err == nil || strings.Contains(err.Error(), "canary") {
				t.Fatalf("error=%v", err)
			}
			f.failAt = ""
			f.failAfter = false
			if _, err := reconcile(context.Background(), f, true); err != nil {
				t.Fatal(err)
			}
			if bytes.Count([]byte(strings.Join(f.mutations, " ")), []byte("firewall")) != 1 || bytes.Count([]byte(strings.Join(f.mutations, " ")), []byte("network")) != 1 {
				t.Fatalf("recreated resources: %v", f.mutations)
			}
		})
	}
}

func TestForeignResourcesAreNeverAdoptedOrOverwritten(t *testing.T) {
	for _, foreign := range []string{"network", "bridge", "table"} {
		t.Run(foreign, func(t *testing.T) {
			f := &fakeHost{}
			switch foreign {
			case "network":
				f.network = networkFixture(strings.Repeat("f", 64))
				f.bridge = true
			case "bridge":
				f.bridge = true
			case "table":
				f.table = []byte(`{"nftables":[]}`)
			}
			if _, err := reconcile(context.Background(), f, true); !errors.Is(err, ErrConflict) || len(f.mutations) != 0 {
				t.Fatalf("err=%v mutations=%v", err, f.mutations)
			}
		})
	}
}
func TestManagedResourceDriftAndMissingNetworkFailClosed(t *testing.T) {
	for _, change := range []string{"rule", "network-owner", "network-id", "intent-policy", "runtime-owner", "network-missing"} {
		t.Run(change, func(t *testing.T) {
			f := &fakeHost{}
			if _, err := reconcile(context.Background(), f, true); err != nil {
				t.Fatal(err)
			}
			f.mutations = nil
			switch change {
			case "rule":
				f.table = bytes.Replace(f.table, []byte(`"drop":null`), []byte(`"accept":null`), 1)
			case "network-owner":
				f.network = bytes.Replace(f.network, []byte(strings.Repeat("01", 32)), []byte(strings.Repeat("02", 32)), 1)
			case "network-id":
				f.network = bytes.Replace(f.network, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("b", 64)), 1)
			case "intent-policy":
				f.intent = bytes.Replace(f.intent, []byte(originDigest()), []byte(strings.Repeat("f", 64)), 1)
			case "runtime-owner":
				f.runtime = bytes.Replace(f.runtime, []byte(strings.Repeat("01", 32)), []byte(strings.Repeat("f", 64)), 1)
			case "network-missing":
				f.network = nil
				f.bridge = false
			}
			if _, err := reconcile(context.Background(), f, true); !errors.Is(err, ErrConflict) || len(f.mutations) != 0 {
				t.Fatalf("accepted drift: %v %v", err, f.mutations)
			}
		})
	}
}
func TestInventoryFailuresDoNotMeanAbsent(t *testing.T) {
	for _, action := range []string{"network ls", "link show", "list tables"} {
		t.Run(action, func(t *testing.T) {
			f := &fakeHost{failAt: action}
			if _, err := reconcile(context.Background(), f, true); err != ErrUnavailable || len(f.mutations) != 0 || strings.Contains(err.Error(), "canary") {
				t.Fatalf("err=%v writes=%v", err, f.mutations)
			}
		})
	}
}
func TestMalformedStateCannotSelectCommands(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"owner":"$(credential-canary)"}`), []byte(`{"schema_version":1,"schema_version":2}`)} {
		f := &fakeHost{intent: raw}
		if _, err := reconcile(context.Background(), f, true); err != ErrConflict || len(f.mutations) != 0 {
			t.Fatal(err)
		}
	}
	f := &fakeHost{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reconcile(ctx, f, true); err != ErrUnavailable || len(f.mutations) != 0 {
		t.Fatal(err)
	}
}
