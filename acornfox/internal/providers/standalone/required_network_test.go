package standalone

import (
	"context"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

func TestRequiredNetworkNeverFallsBackToUnguardedCreation(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "changed"} {
		t.Run(mode, func(t *testing.T) {
			r := &fakeRunner{run: func(args []string, out io.Writer) error {
				if !reflect.DeepEqual(args, []string{"network", "inspect", "opencard-m1-network"}) {
					t.Fatalf("unexpected network effect: %v", args)
				}
				if mode == "missing" {
					return errors.New("network missing")
				}
				_, err := io.WriteString(out, mode)
				return err
			}}
			p := testProvider(t, r, &fixedPorts{})
			p.config.ExistingNetworkValidator = func(raw []byte) error {
				if string(raw) != "valid" {
					return errors.New("changed")
				}
				return nil
			}
			err := p.ensureNetwork(context.Background(), contracts.OperationContext{IdempotencyKey: "network-check"})
			if (err == nil) != (mode == "valid") {
				t.Fatalf("mode=%s err=%v", mode, err)
			}
		})
	}
}

func TestRuntimeDNSIsPassedAsSeparateDockerArguments(t *testing.T) {
	p := testProvider(t, &fakeRunner{}, &fixedPorts{})
	p.config.DNS = []string{"223.5.5.5", "223.6.6.6"}
	args := p.runArgs("container", domain.Deployment{}, contracts.RuntimeSpec{Image: testImage()}, 0)
	found := []string{}
	for i, arg := range args {
		if arg == "--dns" {
			if i+1 >= len(args) {
				t.Fatal("missing DNS value")
			}
			found = append(found, args[i+1])
		}
	}
	if !reflect.DeepEqual(found, p.config.DNS) {
		t.Fatalf("DNS argv=%v", found)
	}
}
