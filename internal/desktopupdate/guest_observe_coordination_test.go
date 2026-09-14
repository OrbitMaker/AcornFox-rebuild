package desktopupdate

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestGuestBackendActiveWorkerDoesNotInspectInstallation(t *testing.T) {
	for _, state := range []string{"queued", "running", "recovering"} {
		t.Run(state, func(t *testing.T) {
			f := newGuestFixture(t)
			receipt := f.receipt
			receipt.State = state
			observed := 0
			g := guestAdapter(t, f, func(_ context.Context, c GuestCommand, _ io.Reader, out io.Writer) (int, error) {
				switch c.Arguments()[0] {
				case "status":
					return guestWrite(out, receipt)
				case "observe":
					observed++
					obs := f.observation
					obs.AttemptState = "running"
					return guestWrite(out, obs)
				default:
					t.Fatal("unexpected operation")
					return 1, nil
				}
			})
			result, err := g.Observe(context.Background(), f.intent.AttemptID)
			if !errors.Is(err, ErrHostPending) || result != (BackendObservation{}) || observed != 0 {
				t.Fatalf("worker=%s observe_calls=%d pending=%v", state, observed, errors.Is(err, ErrHostPending))
			}
		})
	}
}
