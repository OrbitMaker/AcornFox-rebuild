//go:build !linux

package healthcheck

import "testing"

func TestProductionListenerSourceFailsClosedOffLinux(t *testing.T) {
	if source, err := NewProductionListenerSource(); err == nil || source != nil {
		t.Fatalf("source=%v err=%v", source, err)
	}
}
