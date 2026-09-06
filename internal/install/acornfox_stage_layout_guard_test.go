package install

import "testing"

func TestAcornFoxStageGuardAllowsOnlyFixedProductionState(t *testing.T) {
	for _, tc := range []struct {
		name      string
		layout    acornFoxInstallLayout
		forbidden bool
	}{
		{"fixed production", acornFoxInstallLayout{mode: acornFoxInstallLayoutProduction, hostRootPath: "/", stateRootPath: "/var/lib/acornfox/install"}, false},
		{"task cannot enter production", acornFoxInstallLayout{mode: acornFoxInstallLayoutTask, hostRootPath: "/", stateRootPath: "/var/lib/acornfox/install"}, true},
		{"production cannot select other data", acornFoxInstallLayout{mode: acornFoxInstallLayoutProduction, hostRootPath: "/", stateRootPath: "/var/lib/acornfox/other"}, true},
		{"production cannot select config", acornFoxInstallLayout{mode: acornFoxInstallLayoutProduction, hostRootPath: "/", stateRootPath: "/etc/acornfox"}, true},
		{"foreign host cannot enter production", acornFoxInstallLayout{mode: acornFoxInstallLayoutProduction, hostRootPath: "/somewhere", stateRootPath: "/var/lib/acornfox/install"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := forbiddenAcornFoxLayoutStageRoot(tc.layout); got != tc.forbidden {
				t.Fatalf("forbidden=%v want=%v", got, tc.forbidden)
			}
		})
	}
}
