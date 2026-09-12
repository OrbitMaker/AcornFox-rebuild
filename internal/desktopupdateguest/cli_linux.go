//go:build linux

package desktopupdateguest

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
)

// Command is a closed JSON/stdin protocol. submit is one JSON header line followed
// by exactly PayloadSize bytes and EOF; no filename or trust override is accepted.
func (x *Executor) Command(ctx context.Context, args []string, input io.Reader, output io.Writer) int {
	var value any
	var err error
	switch {
	case len(args) == 1 && args[0] == "collect":
		err = x.Collect(ctx)
	case len(args) == 1 && args[0] == "submit":
		reader := bufio.NewReaderSize(input, 2<<20)
		header, e := reader.ReadSlice('\n')
		if e != nil {
			return writeResult(output, nil, ErrConflict)
		}
		var request SubmitRequest
		if decode(header, &request) != nil {
			return writeResult(output, nil, ErrConflict)
		}
		value, err = x.Submit(ctx, request, reader)
	case (len(args) == 1 || len(args) == 2) && args[0] == "observe":
		id := ""
		if len(args) == 2 {
			id = args[1]
		}
		value, err = x.Observe(ctx, id)
	case len(args) == 2 && args[0] == "status":
		value, err = x.Status(args[1])
	case len(args) == 2 && args[0] == "recover":
		var j JobReceipt
		j, err = x.Status(args[1])
		value = j
		if err == nil {
			if j.State == "absent" {
				err = ErrConflict
			} else if j.State == "queued" || j.State == "running" || j.State == "recovering" || j.State == "unknown" {
				if processAlive(j.Process) {
					err = ErrBusy
				} else {
					err = x.spawn(args[1])
				}
			}
		}
	case len(args) == 2 && args[0] == "run":
		if x.paths.executable == ExecutablePath {
			group, e := syscall.Getpgid(0)
			if e != nil || group != os.Getpid() {
				return writeResult(output, nil, ErrConflict)
			}
		}
		err = x.Run(ctx, args[1], false)
		if err == nil {
			value, _ = x.Status(args[1])
		}
	default:
		err = ErrConflict
	}
	return writeResult(output, value, err)
}
func writeResult(out io.Writer, value any, err error) int {
	code := "ok"
	exit := 0
	if err != nil {
		exit = 1
		code = "update-conflict"
		if errors.Is(err, ErrNotConfigured) {
			code = "not-configured"
			exit = 0
		}
		if errors.Is(err, ErrBusy) {
			code = "reconciliation-required"
		}
		if errors.Is(err, ErrCapacity) {
			code = "retention-full"
		}
	}
	_ = json.NewEncoder(out).Encode(struct {
		OK     bool   `json:"ok"`
		Code   string `json:"code"`
		Result any    `json:"result,omitempty"`
	}{err == nil, code, value})
	return exit
}

// RunCommand loads production trust before handling any command. Policy absence
// is an explicit non-error status and never bootstraps a fixture trust key.
func RunCommand(ctx context.Context, args []string, input io.Reader, output io.Writer) int {
	x, e := Open()
	if e != nil {
		return writeResult(output, nil, e)
	}
	return x.Command(ctx, args, input, output)
}
