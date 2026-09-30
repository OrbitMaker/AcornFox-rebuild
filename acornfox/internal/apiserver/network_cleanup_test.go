package apiserver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/acornfox/acornfox/internal/state"
)

func TestDeleteAppRemovesNetworkEvenWhenKeepingVolumes(t *testing.T) {
	for _, suffix := range []string{"", "?volumes=true"} {
		h, _, _, rn := addonTestServer(t)
		w := do(t, h, http.MethodDelete, "/v1/apps/shop"+suffix, nil, nil)
		if w.Code != http.StatusOK || len(rn.removedNetworks) != 1 || rn.removedNetworks[0] != "shop" {
			t.Fatalf("network not removed: %d %s %v", w.Code, w.Body, rn.removedNetworks)
		}
	}
}

func TestNetworkCleanupFailureKeepsAppForRetry(t *testing.T) {
	h, st, _, rn := addonTestServer(t)
	rn.removeNetworkErr = errors.New("foreign endpoint")
	w := do(t, h, http.MethodDelete, "/v1/apps/shop", nil, nil)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "network_removal_failed") {
		t.Fatalf("missing failure: %d %s", w.Code, w.Body)
	}
	if _, err := st.GetApp(context.Background(), "shop"); err != nil {
		t.Fatalf("failed cleanup must retain app: %v", err)
	}
	rn.removeNetworkErr = nil
	w = do(t, h, http.MethodDelete, "/v1/apps/shop", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("retry: %d %s", w.Code, w.Body)
	}
	if _, err := st.GetApp(context.Background(), "shop"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("app not removed after cleanup: %v", err)
	}
}
