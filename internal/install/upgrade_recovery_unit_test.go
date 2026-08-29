package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestProductionUpgradeRecoveryUnitsAreExactAndDigested(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		get  func() []byte
		dig  func() string
		want string
	}{
		{"recover", []byte(productionUpgradeRecoveryUnitText), ProductionUpgradeRecoveryUnitBytes, ProductionUpgradeRecoveryUnitSHA256, "42d4c3c68ac471f82d3935afb8b7043f29e005d2e8642dcbc5fdfe56fa4df806"},
		{"safe", []byte(productionUpgradeSafeBootTargetText), ProductionUpgradeSafeBootTargetBytes, ProductionUpgradeSafeBootTargetSHA256, "0de4a37d59566971cf11606f9e584ca2d9325bf6d8ca217325d382f796960cfd"},
		{"finalizer", []byte(productionUpgradeFinalizeUnitText), ProductionUpgradeFinalizeUnitBytes, ProductionUpgradeFinalizeUnitSHA256, "0fbbda51c9c1b1c2c2600ee09b0cf4e05e99db26e500a6e2c6fe34ec31c5aa63"},
		{"edge-dropin", []byte(productionUpgradeEdgeMarkerDropInText), ProductionUpgradeEdgeMarkerDropInBytes, ProductionUpgradeEdgeMarkerDropInSHA256, "af0cf74314389ca5c9c2a3ca541679f65670ea95eebb12a0ce75eba71a72fbd8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, second := tc.get(), tc.get()
			if string(first) != string(tc.raw) || string(second) != string(tc.raw) {
				t.Fatalf("unit drifted: %q", first)
			}
			first[0] = '!'
			if string(tc.get()) != string(tc.raw) {
				t.Fatal("unit bytes are not defensive")
			}
			digest := sha256.Sum256(tc.raw)
			if got := tc.dig(); got != hex.EncodeToString(digest[:]) || got != tc.want {
				t.Fatalf("unit digest=%s", got)
			}
		})
	}
}

func TestDeployBootArtifactsMatchCanonicalBytes(t *testing.T) {
	for _, tc := range []struct {
		path string
		want []byte
	}{
		{"open-card-upgrade-recover.service", ProductionUpgradeRecoveryUnitBytes()},
		{"open-card-upgrade-safe.target", ProductionUpgradeSafeBootTargetBytes()},
		{"open-card-upgrade-finalize.service", ProductionUpgradeFinalizeUnitBytes()},
		{filepath.Join("open-card-edge.service.d", "10-upgrade-marker.conf"), ProductionUpgradeEdgeMarkerDropInBytes()},
	} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", tc.path))
		if err != nil || !bytes.Equal(raw, tc.want) {
			t.Fatalf("deploy artifact %s drifted: %v", tc.path, err)
		}
	}
}
