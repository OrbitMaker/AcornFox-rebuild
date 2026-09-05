package runtimenetwork

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"time"
)

type intent struct {
	SchemaVersion int    `json:"schema_version"`
	Owner         string `json:"owner"`
	PolicySHA256  string `json:"policy_sha256"`
	NetworkID     string `json:"network_id,omitempty"`
}
type runtimeState struct {
	Owner   string  `json:"owner"`
	Receipt Receipt `json:"receipt"`
}
type backend interface {
	run(context.Context, string, []string, []byte) ([]byte, error)
	readIntent() ([]byte, error)
	writeIntent([]byte, bool) error
	readRuntime() ([]byte, error)
	writeRuntime([]byte, bool) error
	ready(context.Context) error
	random([]byte) error
	close() error
}

// Ensure creates only absent owned resources and resumes its own incomplete
// creation. Missing firewall rules may be restored after reboot; a surviving
// table must match the entire compiled policy. Drift is never overwritten.
func Ensure(ctx context.Context) (Receipt, error) { return runProduction(ctx, true) }

// Verify leaves managed network and policy state unchanged. It uses the same
// existing lock and a private temporary CLI home, but never repairs resources.
func Verify(ctx context.Context) error { _, err := runProduction(ctx, false); return err }

func runProduction(ctx context.Context, create bool) (Receipt, error) {
	if ctx == nil || ctx.Err() != nil {
		return Receipt{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	b, err := productionBackend(create)
	if err != nil {
		return Receipt{}, ErrUnavailable
	}
	defer b.close()
	receipt, err := reconcile(ctx, b, create)
	if b.close() != nil {
		return Receipt{}, ErrUnavailable
	}
	return receipt, err
}
func encode(v any) []byte { raw, _ := json.Marshal(v); return append(raw, '\n') }
func parseIntent(raw []byte) (intent, error) {
	var i intent
	if decode(raw, &i) != nil || !bytes.Equal(raw, encode(i)) || i.SchemaVersion != 1 || !digestOK(i.Owner) || i.PolicySHA256 != originDigest() || (i.NetworkID != "" && !digestOK(i.NetworkID)) {
		return intent{}, ErrConflict
	}
	return i, nil
}
func parseRuntime(raw []byte, i intent) error {
	var s runtimeState
	if decode(raw, &s) != nil || !bytes.Equal(raw, encode(s)) || s.Owner != i.Owner || s.Receipt.SchemaVersion != 1 || s.Receipt.PolicySHA256 != i.PolicySHA256 || !digestOK(s.Receipt.NetworkID) || (i.NetworkID != "" && s.Receipt.NetworkID != i.NetworkID) {
		return ErrConflict
	}
	want, err := policyFingerprint(i.Owner)
	if err != nil || s.Receipt.FirewallSHA256 != want {
		return ErrConflict
	}
	return nil
}

func reconcile(ctx context.Context, b backend, create bool) (Receipt, error) {
	fail := func(err error) (Receipt, error) {
		if errors.Is(err, ErrConflict) {
			return Receipt{}, ErrConflict
		}
		return Receipt{}, ErrUnavailable
	}
	if ctx == nil || ctx.Err() != nil {
		return fail(ErrUnavailable)
	}
	if err := b.ready(ctx); err != nil {
		return fail(err)
	}
	raw, err := b.readIntent()
	absent := errors.Is(err, os.ErrNotExist)
	var i intent
	if err != nil && !absent {
		return fail(err)
	}
	if !absent {
		if i, err = parseIntent(raw); err != nil {
			return fail(err)
		}
	}
	prior, priorErr := b.readRuntime()
	if priorErr != nil && !errors.Is(priorErr, os.ErrNotExist) {
		return fail(priorErr)
	}
	if priorErr == nil && (absent || parseRuntime(prior, i) != nil) {
		return fail(ErrConflict)
	}
	// Successful inventory commands distinguish absence from tool failure.
	raw, err = b.run(ctx, "/usr/bin/docker", []string{"network", "ls", "--no-trunc", "--filter", "name=^" + Network + "$", "--format", "{{.ID}}"}, nil)
	if err != nil {
		return fail(err)
	}
	networkID := strings.TrimSpace(string(raw))
	if networkID != "" && !digestOK(networkID) {
		return fail(ErrConflict)
	}
	raw, err = b.run(ctx, "/usr/sbin/ip", []string{"-j", "-d", "link", "show"}, nil)
	if err != nil {
		return fail(err)
	}
	bridgePresent, err := findBridge(raw)
	if err != nil {
		return fail(err)
	}
	raw, err = b.run(ctx, "/usr/sbin/nft", []string{"-j", "list", "tables"}, nil)
	if err != nil {
		return fail(err)
	}
	tablePresent, err := hasTable(raw)
	if err != nil {
		return fail(err)
	}
	if absent {
		if networkID != "" || bridgePresent || tablePresent {
			return fail(ErrConflict)
		}
		if !create {
			return fail(ErrUnavailable)
		}
		entropy := make([]byte, 32)
		if b.random(entropy) != nil {
			return fail(ErrUnavailable)
		}
		i = intent{SchemaVersion: 1, Owner: hex.EncodeToString(entropy), PolicySHA256: originDigest()}
		if err := b.writeIntent(encode(i), true); err != nil {
			return fail(err)
		}
	}
	if networkID == "" && (bridgePresent || i.NetworkID != "") {
		return fail(ErrConflict)
	}
	if networkID != "" {
		raw, err = b.run(ctx, "/usr/bin/docker", []string{"network", "inspect", Network}, nil)
		if err != nil {
			return fail(err)
		}
		observed, e := inspectNetwork(raw, i.Owner, i.NetworkID)
		if e != nil || observed != networkID {
			return fail(ErrConflict)
		}
		if !bridgePresent {
			return fail(ErrUnavailable)
		}
	}
	want, err := policyFingerprint(i.Owner)
	if err != nil {
		return fail(err)
	}
	if !tablePresent {
		if !create {
			return fail(ErrUnavailable)
		}
		// Atomic create refuses an intervening foreign table instead of appending.
		if _, err = b.run(ctx, "/usr/sbin/nft", []string{"-j", "-f", "-"}, policyCommands(i.Owner)); err != nil {
			return fail(err)
		}
	}
	if err = verifyTable(ctx, b, want); err != nil {
		return fail(err)
	}
	if networkID == "" {
		if !create {
			return fail(ErrUnavailable)
		}
		args := []string{"network", "create", "--driver", "bridge", "--ipv6=false", "--subnet", Subnet, "--gateway", Gateway}
		for _, pair := range []struct {
			flag   string
			values map[string]string
		}{{"--opt", dockerOptions()}, {"--label", dockerLabels(i.Owner)}} {
			keys := make([]string, 0, len(pair.values))
			for key := range pair.values {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				args = append(args, pair.flag, key+"="+pair.values[key])
			}
		}
		args = append(args, Network)
		raw, err = b.run(ctx, "/usr/bin/docker", args, nil)
		if err != nil {
			return fail(err)
		}
		networkID = strings.TrimSpace(string(raw))
		if !digestOK(networkID) {
			return fail(ErrConflict)
		}
	}
	// Always reread the actual network and bridge after preparation.
	raw, err = b.run(ctx, "/usr/bin/docker", []string{"network", "inspect", Network}, nil)
	if err != nil {
		return fail(err)
	}
	observed, err := inspectNetwork(raw, i.Owner, networkID)
	if err != nil {
		return fail(err)
	}
	raw, err = b.run(ctx, "/usr/sbin/ip", []string{"-j", "-d", "link", "show"}, nil)
	if err != nil {
		return fail(err)
	}
	found, err := findBridge(raw)
	if err != nil || !found {
		return fail(ErrConflict)
	}
	raw, err = b.run(ctx, "/usr/sbin/ip", []string{"-j", "-4", "address", "show", "dev", Bridge}, nil)
	if err != nil {
		return fail(err)
	}
	if verifyBridgeAddress(raw) != nil {
		return fail(ErrConflict)
	}
	if err = b.ready(ctx); err != nil {
		return fail(err)
	}
	if err = verifyTable(ctx, b, want); err != nil {
		return fail(err)
	}
	if ctx.Err() != nil {
		return fail(ErrUnavailable)
	}
	receipt := Receipt{SchemaVersion: 1, PolicySHA256: i.PolicySHA256, NetworkID: observed, FirewallSHA256: want}
	if create {
		if i.NetworkID == "" {
			i.NetworkID = observed
			if err = b.writeIntent(encode(i), false); err != nil {
				return fail(err)
			}
		}
		next := encode(runtimeState{Owner: i.Owner, Receipt: receipt})
		if !bytes.Equal(prior, next) {
			if err = b.writeRuntime(next, errors.Is(priorErr, os.ErrNotExist)); err != nil {
				return fail(err)
			}
		}
	} else if i.NetworkID != observed || priorErr != nil {
		return fail(ErrUnavailable)
	}
	return receipt, nil
}

func verifyTable(ctx context.Context, b backend, want string) error {
	raw, err := b.run(ctx, "/usr/sbin/nft", []string{"-j", "list", "table", "inet", Table}, nil)
	if err != nil {
		return ErrUnavailable
	}
	got, err := fingerprint(raw)
	if err != nil || got != want {
		return ErrConflict
	}
	return nil
}
