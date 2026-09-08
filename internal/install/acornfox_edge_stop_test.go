package install

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func edgeStopState(active, sub string, pid int) []byte {
	return []byte(fmt.Sprintf("Id=acornfox-edge.service\nLoadState=loaded\nActiveState=%s\nSubState=%s\nMainPID=%d\n", active, sub, pid))
}
func TestAcornFoxEdgeStopBoundedLegacyFallback(t *testing.T) {
	stopped, signaled := false, false
	var calls [][]string
	command := func(_ context.Context, path string, args ...string) ([]byte, error) {
		if path != "/usr/bin/systemctl" {
			t.Fatal("foreign executable")
		}
		calls = append(calls, append([]string(nil), args...))
		switch args[0] {
		case "show":
			if signaled {
				return edgeStopState("inactive", "dead", 0), nil
			}
			if stopped {
				return edgeStopState("deactivating", "stop-sigterm", 123), nil
			}
			return edgeStopState("active", "running", 123), nil
		case "stop":
			if !reflect.DeepEqual(args, []string{"stop", "--no-block", acornFoxEdgeUnit}) {
				t.Fatal("unexpected stop target")
			}
			stopped = true
			return nil, nil
		case "kill":
			if !reflect.DeepEqual(args, []string{"kill", "--kill-whom=main", "--signal=QUIT", acornFoxEdgeUnit}) {
				t.Fatal("unexpected signal target")
			}
			signaled = true
			return nil, nil
		default:
			t.Fatal("unexpected command")
			return nil, nil
		}
	}
	if err := stopAcornFoxEdge(context.Background(), command, true, 100*time.Millisecond, time.Millisecond); err != nil || !stopped || !signaled {
		t.Fatal("bounded legacy stop failed", err, calls)
	}
}
func TestAcornFoxEdgeStopRequiresVerifiedTerminalState(t *testing.T) {
	for _, state := range []string{"active", "deactivating", "activating"} {
		t.Run(state, func(t *testing.T) {
			calls := 0
			command := func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if args[0] == "show" {
					return edgeStopState(state, "running", 123), nil
				}
				if args[0] == "kill" {
					calls++
				}
				return nil, nil
			}
			if err := stopAcornFoxEdge(context.Background(), command, false, 25*time.Millisecond, time.Millisecond); err == nil {
				t.Fatal("running edge accepted")
			}
			if state != "deactivating" && calls != 0 {
				t.Fatal("signaled outside a stop job")
			}
		})
	}
}
func TestAcornFoxEdgeStopRejectsMalformedAndForeignState(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte("Id=foreign.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\n"),
		[]byte("Id=acornfox-edge.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=00\n"),
		append(edgeStopState("inactive", "dead", 0), []byte("MainPID=0\n")...),
	} {
		if _, err := parseAcornFoxEdgeStopState(raw); err == nil {
			t.Fatal("invalid state accepted")
		}
	}
	if _, err := parseAcornFoxEdgeStopState([]byte(strings.Repeat("x", 4097))); err == nil {
		t.Fatal("oversized state accepted")
	}
}
func TestAcornFoxEdgeStopAlreadyStoppedAndNormalDrain(t *testing.T) {
	for _, already := range []bool{true, false} {
		t.Run(fmt.Sprint(already), func(t *testing.T) {
			stop := false
			observations := 0
			command := func(_ context.Context, _ string, args ...string) ([]byte, error) {
				switch args[0] {
				case "show":
					observations++
					if already || stop && observations > 2 {
						return edgeStopState("inactive", "dead", 0), nil
					}
					return edgeStopState("active", "running", 123), nil
				case "stop":
					stop = true
					return nil, nil
				default:
					return nil, errors.New("unexpected signal")
				}
			}
			if err := stopAcornFoxEdge(context.Background(), command, false, 100*time.Millisecond, time.Millisecond); err != nil {
				t.Fatal(err)
			}
			if already && stop {
				t.Fatal("stopped service mutated")
			}
		})
	}
}
