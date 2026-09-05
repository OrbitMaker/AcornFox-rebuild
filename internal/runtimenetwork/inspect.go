package runtimenetwork

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
)

const maxOutput = 1 << 20

// JSON values are bounded and duplicate keys are rejected before decoding.
func decode(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > maxOutput {
		return ErrConflict
	}
	scan := json.NewDecoder(bytes.NewReader(raw))
	scan.UseNumber()
	if err := scanJSON(scan, 0); err != nil {
		return ErrConflict
	}
	var extra any
	if scan.Decode(&extra) != io.EOF {
		return ErrConflict
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(out) != nil {
		return ErrConflict
	}
	return nil
}
func scanJSON(d *json.Decoder, depth int) error {
	if depth > 64 {
		return ErrConflict
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	keys := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := key.(string)
			if !ok || keys[s] {
				return ErrConflict
			}
			keys[s] = true
		}
		if err := scanJSON(d, depth+1); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}

func fingerprint(raw []byte) (string, error) {
	var root map[string]json.RawMessage
	if decode(raw, &root) != nil || len(root) != 1 {
		return "", ErrConflict
	}
	var entries []map[string]any
	if decode(root["nftables"], &entries) != nil {
		return "", ErrConflict
	}
	clean := []map[string]any{}
	for _, entry := range entries {
		if len(entry) != 1 {
			return "", ErrConflict
		}
		if _, ok := entry["metainfo"]; ok {
			continue
		}
		normalizeNFT(entry)
		clean = append(clean, entry)
	}
	out, err := json.Marshal(clean)
	if err != nil {
		return "", ErrConflict
	}
	return hashBytes(out), nil
}
func normalizeNFT(value any) {
	switch v := value.(type) {
	case map[string]any:
		delete(v, "handle")
		if counter, ok := v["counter"].(map[string]any); ok {
			delete(counter, "packets")
			delete(counter, "bytes")
			if len(counter) == 0 {
				v["counter"] = nil
			}
		}
		for _, child := range v {
			normalizeNFT(child)
		}
	case []any:
		for _, child := range v {
			normalizeNFT(child)
		}
	}
}

func hasTable(raw []byte) (bool, error) {
	var root struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if decode(raw, &root) != nil || root.NFTables == nil {
		return false, ErrConflict
	}
	found := false
	for _, entry := range root.NFTables {
		if info, ok := entry["table"]; ok {
			var t struct{ Family, Name string }
			if decode(info, &t) != nil {
				return false, ErrConflict
			}
			if t.Family == "inet" && t.Name == Table {
				if found {
					return false, ErrConflict
				}
				found = true
			}
		}
	}
	return found, nil
}

type dockerNetwork struct {
	Name                                      string
	ID                                        string `json:"Id"`
	Driver, Scope                             string
	EnableIPv4                                *bool
	EnableIPv6, Internal, Attachable, Ingress bool
	ConfigOnly                                bool
	ConfigFrom                                struct{ Network string }
	Options, Labels                           map[string]string
	IPAM                                      struct {
		Driver  string
		Options map[string]string
		Config  []struct {
			Subnet, IPRange, Gateway string
			AuxAddress               map[string]string `json:"AuxiliaryAddresses"`
		}
	}
}

func inspectNetwork(raw []byte, owner, expectedID string) (string, error) {
	var items []dockerNetwork
	if decode(raw, &items) != nil || len(items) != 1 {
		return "", ErrConflict
	}
	n := items[0]
	if n.Name != Network || !digestOK(n.ID) || (expectedID != "" && n.ID != expectedID) || n.Driver != "bridge" || n.Scope != "local" || n.EnableIPv6 || n.Internal || n.Attachable || n.Ingress || n.ConfigOnly || n.ConfigFrom.Network != "" || (n.EnableIPv4 != nil && !*n.EnableIPv4) || !reflect.DeepEqual(n.Options, dockerOptions()) || !reflect.DeepEqual(n.Labels, dockerLabels(owner)) || n.IPAM.Driver != "default" || len(n.IPAM.Options) != 0 || len(n.IPAM.Config) != 1 {
		return "", ErrConflict
	}
	ipam := n.IPAM.Config[0]
	if ipam.Subnet != Subnet || ipam.Gateway != Gateway || ipam.IPRange != "" || len(ipam.AuxAddress) != 0 {
		return "", ErrConflict
	}
	return n.ID, nil
}

func findBridge(raw []byte) (bool, error) {
	var links []struct {
		Index    int    `json:"ifindex"`
		Name     string `json:"ifname"`
		LinkInfo struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if decode(raw, &links) != nil || links == nil {
		return false, ErrConflict
	}
	found := false
	for _, link := range links {
		if link.Name == Bridge {
			if found || link.Index <= 0 || link.LinkInfo.Kind != "bridge" {
				return false, ErrConflict
			}
			found = true
		}
	}
	return found, nil
}
func verifyBridgeAddress(raw []byte) error {
	var links []struct {
		Name      string `json:"ifname"`
		Addresses []struct {
			Family, Local string
			Prefix        int `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if decode(raw, &links) != nil || len(links) != 1 || links[0].Name != Bridge || len(links[0].Addresses) != 1 {
		return ErrConflict
	}
	a := links[0].Addresses[0]
	if a.Family != "inet" || a.Local != Gateway || a.Prefix != 24 {
		return ErrConflict
	}
	return nil
}
