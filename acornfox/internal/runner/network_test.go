package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNetworkRemovalRejectsForeignOrConnectedResources(t *testing.T) {
	for _, tc := range []struct {
		name, id, networkName string
		labels                map[string]string
		connected             bool
	}{
		{name: "unlabeled", id: "id", networkName: "af-shop"},
		{name: "other-app", id: "id", networkName: "af-shop", labels: map[string]string{LabelManaged: "1", LabelApp: "other"}},
		{name: "not-managed", id: "id", networkName: "af-shop", labels: map[string]string{LabelManaged: "0", LabelApp: "shop"}},
		{name: "wrong-name", id: "id", networkName: "af-other", labels: map[string]string{LabelManaged: "1", LabelApp: "shop"}},
		{name: "connected", id: "id", networkName: "af-shop", labels: map[string]string{LabelManaged: "1", LabelApp: "shop"}, connected: true},
		{name: "missing-id", networkName: "af-shop", labels: map[string]string{LabelManaged: "1", LabelApp: "shop"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deletes := 0
			d := observationDocker(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					deletes++
					w.WriteHeader(http.StatusNoContent)
					return
				}
				endpoints := map[string]any{}
				if tc.connected {
					endpoints["external-container"] = map[string]string{"Name": "external"}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"Name": tc.networkName, "Id": tc.id, "Labels": tc.labels, "Containers": endpoints})
			})
			var remote *RemoteError
			if err := d.RemoveNetwork(context.Background(), "shop"); !errors.As(err, &remote) {
				t.Fatalf("must refuse unsafe removal: %v", err)
			}
			if deletes != 0 {
				t.Fatal("unsafe network deletion was attempted")
			}
		})
	}
}

func TestNetworkRemovalUsesInspectedIDAndIsIdempotent(t *testing.T) {
	for _, missing := range []string{"", "inspect", "delete"} {
		t.Run(missing, func(t *testing.T) {
			deletes := 0
			d := observationDocker(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					if missing == "inspect" {
						w.WriteHeader(404)
						_, _ = w.Write([]byte(`{"message":"not found"}`))
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"Name": "af-shop", "Id": "inspected-id", "Labels": map[string]string{LabelManaged: "1", LabelApp: "shop"}, "Containers": map[string]any{}})
					return
				}
				deletes++
				if r.Method != http.MethodDelete || !strings.HasSuffix(r.URL.Path, "/networks/inspected-id") {
					t.Errorf("deletion must use inspected ID: %s %s", r.Method, r.URL.Path)
				}
				if missing == "delete" {
					w.WriteHeader(404)
					_, _ = w.Write([]byte(`{"message":"not found"}`))
				} else {
					w.WriteHeader(http.StatusNoContent)
				}
			})
			if err := d.RemoveNetwork(context.Background(), "shop"); err != nil {
				t.Fatal(err)
			}
			if missing == "inspect" && deletes != 0 {
				t.Fatal("missing network must not invoke deletion")
			}
		})
	}
}

func TestNetworkEnsureRejectsUnmanagedNameCollision(t *testing.T) {
	d := observationDocker(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("must not create or change foreign network: %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Name": "af-shop", "Id": "foreign-id", "Labels": map[string]string{}})
	})
	var remote *RemoteError
	if err := d.ensureNetwork(context.Background(), "shop"); !errors.As(err, &remote) || remote.Code != "refused" {
		t.Fatalf("unmanaged network must not be used: %v", err)
	}
}

func TestNetworkEnsureRechecksConcurrentNameOwner(t *testing.T) {
	inspections := 0
	d := observationDocker(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"message":"network already exists"}`))
			return
		}
		inspections++
		if inspections == 1 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Name": "af-shop", "Id": "foreign-id", "Labels": map[string]string{}})
	})
	var remote *RemoteError
	if err := d.ensureNetwork(context.Background(), "shop"); !errors.As(err, &remote) || remote.Code != "refused" || inspections != 2 {
		t.Fatalf("concurrent foreign owner was not rejected: inspections=%d err=%v", inspections, err)
	}
}

type networkTestAPI struct {
	fakeAPI
	app string
}

func (n *networkTestAPI) RemoveNetwork(_ context.Context, app string) error {
	n.app = app
	return nil
}

func TestNetworkRemovalRouteIsTypedAndValidated(t *testing.T) {
	api := &networkTestAPI{}
	handler := NewServer(api, t.TempDir())
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"app":"shop"}`, http.StatusOK},
		{`{"app":"../other"}`, http.StatusBadRequest},
		{`{"app":""}`, http.StatusBadRequest},
		{`invalid`, http.StatusBadRequest},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, PathNetworkRemove, bytes.NewBufferString(tc.body)))
		if w.Code != tc.status {
			t.Fatalf("status %d for %s: %s", w.Code, tc.body, w.Body)
		}
	}
	if api.app != "shop" {
		t.Fatalf("invalid request reached API: %q", api.app)
	}
}
