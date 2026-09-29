// acornfox is the API-only command line client for the first AcornFox release.
// It deliberately contains no database, Docker, cloud, or DNS code.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const apiBase = "/api/v1/acornfox"

type cli struct {
	in       io.Reader
	out, err io.Writer
	env      func(string) string
	client   *http.Client
	json     bool
	secrets  []string
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv)) }

func run(args []string, in io.Reader, out, errOut io.Writer, env func(string) string) int {
	c := &cli{in: in, out: out, err: errOut, env: env, client: &http.Client{Timeout: 30 * time.Second}}
	clean, jsonOutput, err := consumeGlobalJSON(args)
	if err != nil {
		return c.fail("usage", 0, "usage", err.Error())
	}
	c.json = jsonOutput
	if len(clean) == 0 {
		return c.fail("usage", 0, "usage", "command is required")
	}
	if err := c.command(clean); err != nil {
		var reported reportedCLIResult
		if errors.As(err, &reported) {
			return reported.code
		}
		var responseErr apiError
		if errors.As(err, &responseErr) {
			return c.fail(responseErr.class(), responseErr.status, responseErr.Code, responseErr.Message)
		}
		return c.fail("usage", 0, "usage", err.Error())
	}
	return 0
}

type apiError struct {
	status        int
	Code, Message string
	network       bool
	contract      bool
}

func (e apiError) Error() string { return e.Message }
func (e apiError) class() string {
	switch {
	case e.contract:
		return "contract"
	case e.network || e.status == http.StatusServiceUnavailable:
		return "unavailable"
	case e.status == http.StatusUnauthorized || e.status == http.StatusTooManyRequests:
		return "authentication"
	case e.status == http.StatusConflict:
		return "conflict"
	case e.status >= 500:
		return "contract"
	default:
		return "usage"
	}
}

func (c *cli) fail(class string, status int, code, message string) int {
	for _, secret := range c.secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	exit := map[string]int{"usage": 2, "authentication": 3, "conflict": 4, "unavailable": 5, "contract": 6}[class]
	if c.json {
		_ = json.NewEncoder(c.out).Encode(map[string]any{"ok": false, "error": map[string]any{"code": code, "message": message, "class": class, "http_status": nullableStatus(status)}})
	} else {
		fmt.Fprintln(c.err, message)
	}
	return exit
}
func nullableStatus(status int) any {
	if status == 0 {
		return nil
	}
	return status
}

func (c *cli) emit(value any) error {
	if c.json {
		return json.NewEncoder(c.out).Encode(value)
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(c.out, string(encoded))
	return err
}
