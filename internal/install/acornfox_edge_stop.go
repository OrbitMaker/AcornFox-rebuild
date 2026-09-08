package install

import (
	"context"
	"strconv"
	"strings"
	"time"
)

const acornFoxEdgeUnit = "acornfox-edge.service"
const acornFoxEdgeStopBudget = 20 * time.Second

type acornFoxEdgeStopState struct {
	active, sub string
	pid         uint64
}

func parseAcornFoxEdgeStopState(raw []byte) (acornFoxEdgeStopState, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return acornFoxEdgeStopState{}, ErrAcornFoxUpgradeUnknown
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return acornFoxEdgeStopState{}, ErrAcornFoxUpgradeUnknown
		}
		if _, exists := values[key]; exists {
			return acornFoxEdgeStopState{}, ErrAcornFoxUpgradeUnknown
		}
		values[key] = value
	}
	pid, err := strconv.ParseUint(values["MainPID"], 10, 31)
	if err != nil || strconv.FormatUint(pid, 10) != values["MainPID"] || len(values) != 5 || values["Id"] != acornFoxEdgeUnit || values["LoadState"] != "loaded" {
		return acornFoxEdgeStopState{}, ErrAcornFoxUpgradeUnknown
	}
	return acornFoxEdgeStopState{values["ActiveState"], values["SubState"], pid}, nil
}
func (s acornFoxEdgeStopState) stopped() bool {
	return s.active == "inactive" && s.sub == "dead" && s.pid == 0
}

type acornFoxEdgeStopCommand func(context.Context, string, ...string) ([]byte, error)

func stopAcornFoxEdge(ctx context.Context, command acornFoxEdgeStopCommand, legacy bool, budget, poll time.Duration) error {
	if ctx == nil || ctx.Err() != nil || command == nil || budget <= 0 || poll <= 0 {
		return ErrAcornFoxUpgradeUnknown
	}
	bounded, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	call := func(args ...string) ([]byte, error) {
		step, done := context.WithTimeout(bounded, 3*time.Second)
		defer done()
		return command(step, "/usr/bin/systemctl", args...)
	}
	observe := func() (acornFoxEdgeStopState, error) {
		raw, err := call("show", acornFoxEdgeUnit, "--property=Id,LoadState,ActiveState,SubState,MainPID")
		if err != nil {
			return acornFoxEdgeStopState{}, err
		}
		return parseAcornFoxEdgeStopState(raw)
	}
	state, err := observe()
	if err != nil {
		return err
	}
	if state.stopped() {
		return nil
	}

	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	if legacy && state.pid > 0 {
		// SIGTERM would occupy Caddy's POSIX signal goroutine while an old
		// unlimited HTTP grace waits. Send QUIT before entering that handler.
		if state.active != "active" || state.sub != "running" {
			return ErrAcornFoxUpgradeUnknown
		}
		if _, err := call("kill", "--kill-whom=main", "--signal=QUIT", acornFoxEdgeUnit); err != nil {
			return ErrAcornFoxUpgradeUnknown
		}
		for state.pid > 0 {
			select {
			case <-bounded.Done():
				return ErrAcornFoxUpgradeUnknown
			case <-ticker.C:
			}
			state, err = observe()
			if err != nil {
				return err
			}
		}
	}
	// Cancel any queued Restart after legacy QUIT, then require systemd's
	// terminal stopped state. The maintenance marker also prevents restart.
	if _, err := call("stop", "--no-block", acornFoxEdgeUnit); err != nil {
		return err
	}

	for {
		state, err = observe()
		if err != nil {
			return err
		}
		if state.stopped() {
			return nil
		}

		select {
		case <-bounded.Done():
			return ErrAcornFoxUpgradeUnknown
		case <-ticker.C:
		}
	}
}
