//go:build fixture

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/desktopupdate"
)

var BuildMarker = "FIXTURE"

type guestProcessData struct {
	PID   int    `json:"pid"`
	Group int    `json:"group"`
	Boot  string `json:"boot"`
	Start string `json:"start"`
}

type guestReceiptData struct {
	Intent      desktopupdate.HostUpgradeIntent `json:"intent"`
	State       string                          `json:"state"`
	EnvelopeSHA string                          `json:"envelope_sha256"`
	AcceptedAt  time.Time                       `json:"accepted_at"`
	Sequence    uint64                          `json:"sequence"`
	Process     guestProcessData                `json:"process"`
	Reason      string                          `json:"reason,omitempty"`
}

type fixtureBackendData struct {
	InstanceID   string                      `json:"instance_id"`
	Architecture string                      `json:"architecture"`
	Binding      string                      `json:"binding"`
	Ready        bool                        `json:"ready"`
	Finalized    bool                        `json:"finalized"`
	Attempts     map[string]bool             `json:"attempts"`
	Receipts     map[string]guestReceiptData `json:"receipts"`
}

var fixtureBackendMu sync.Mutex

func getPersistentFixtureGuestTransport(fixtureDir string) desktopupdate.GuestTransport {
	stateFile := filepath.Join(fixtureDir, "backend-state.json")
	return func(ctx context.Context, command desktopupdate.GuestCommand, stdin io.Reader, stdout io.Writer) (int, error) {
		fixtureBackendMu.Lock()
		defer fixtureBackendMu.Unlock()

		var data fixtureBackendData
		raw, err := os.ReadFile(stateFile)
		if err == nil {
			_ = json.Unmarshal(raw, &data)
		}
		if data.Attempts == nil {
			data.Attempts = make(map[string]bool)
		}

		args := command.Arguments()
		verb := ""
		attempt := ""
		if len(args) > 0 {
			verb = args[0]
		}
		if len(args) > 1 {
			attempt = args[1]
		}
		fmt.Fprintf(os.Stderr, "FIXTURE_GUEST: marker=%s verb=%s attempt=%s\n", BuildMarker, verb, attempt)
		traceFile := filepath.Join(fixtureDir, "marker-trace.log")
		if f, err := os.OpenFile(traceFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
			_, _ = f.WriteString(fmt.Sprintf("%s:%s\n", BuildMarker, verb))
			_ = f.Close()
		}

		switch verb {
		case "observe":
			attemptState := "absent"
			if attempt != "" && data.Attempts[attempt] {
				attemptState = "upgraded"
			}
			obs := desktopupdate.BackendObservation{
				LocalLoopback:    true,
				MigrationVersion: "0040",
				Architecture:     data.Architecture,
				InstanceID:       data.InstanceID,
				Binding:          data.Binding,
				Ready:            data.Ready,
				Finalized:        data.Finalized,
				AttemptState:     attemptState,
			}
			obsRaw, _ := json.Marshal(obs)
			reply := struct {
				OK     bool            `json:"ok"`
				Code   string          `json:"code"`
				Result json.RawMessage `json:"result,omitempty"`
			}{
				OK:     true,
				Code:   "ok",
				Result: json.RawMessage(obsRaw),
			}
			raw, _ := json.Marshal(reply)
			_, _ = stdout.Write(raw)
			return 0, nil

		case "status":
			var receipt guestReceiptData
			if r, ok := data.Receipts[attempt]; ok && attempt != "" {
				receipt = r
			} else {
				receipt = guestReceiptData{State: "absent"}
			}
			receiptRaw, _ := json.Marshal(receipt)
			reply := struct {
				OK     bool            `json:"ok"`
				Code   string          `json:"code"`
				Result json.RawMessage `json:"result,omitempty"`
			}{
				OK:     true,
				Code:   "ok",
				Result: json.RawMessage(receiptRaw),
			}
			raw, _ := json.Marshal(reply)
			_, _ = stdout.Write(raw)
			return 0, nil

		case "submit":
			inBytes, _ := io.ReadAll(stdin)
			parts := bytes.SplitN(inBytes, []byte("\n"), 2)
			var submitReq struct {
				Intent   desktopupdate.HostUpgradeIntent `json:"intent"`
				Envelope []byte                          `json:"envelope"`
			}
			if len(parts) > 0 {
				_ = json.Unmarshal(parts[0], &submitReq)
			}
			if submitReq.Intent.AttemptID != "" {
				data.Attempts[submitReq.Intent.AttemptID] = true
				if submitReq.Intent.ToBinding != "" {
					data.Binding = submitReq.Intent.ToBinding
				}
				envH := sha256.Sum256(submitReq.Envelope)
				var envObj struct {
					Payload string `json:"payload"`
				}
				_ = json.Unmarshal(submitReq.Envelope, &envObj)
				payloadRaw, _ := base64.StdEncoding.DecodeString(envObj.Payload)
				var idxObj struct {
					Sequence uint64 `json:"sequence"`
				}
				_ = json.Unmarshal(payloadRaw, &idxObj)
				seq := idxObj.Sequence
				if seq == 0 {
					seq = 1
				}

				queuedReceipt := guestReceiptData{
					Intent:      submitReq.Intent,
					State:       "queued",
					EnvelopeSHA: hex.EncodeToString(envH[:]),
					AcceptedAt:  time.Now().UTC().Truncate(time.Second),
					Sequence:    seq,
				}
				upgradedReceipt := queuedReceipt
				upgradedReceipt.State = "upgraded"

				if data.Receipts == nil {
					data.Receipts = make(map[string]guestReceiptData)
				}
				data.Receipts[submitReq.Intent.AttemptID] = upgradedReceipt
				saveRaw, _ := json.Marshal(data)
				_ = os.WriteFile(stateFile, saveRaw, 0600)

				receiptRaw, _ := json.Marshal(queuedReceipt)
				reply := struct {
					OK     bool            `json:"ok"`
					Code   string          `json:"code"`
					Result json.RawMessage `json:"result,omitempty"`
				}{
					OK:     true,
					Code:   "ok",
					Result: json.RawMessage(receiptRaw),
				}
				raw, _ := json.Marshal(reply)
				_, _ = stdout.Write(raw)
				return 0, nil
			}
			return 0, nil

		default:
			return 0, nil
		}
	}
}

func getProductionControllerOptions() ControllerOptions {
	fixtureDir := os.Getenv("ACORNFOX_FIXTURE_DIR")
	if fixtureDir == "" {
		fixtureDir = "/tmp/acornfox-fixture"
	}
	serverAddr := os.Getenv("ACORNFOX_FIXTURE_SERVER")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "downloads.example.com"},
	}
	if serverAddr != "" {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, serverAddr)
		}
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	return ControllerOptions{
		ConfigPath:     filepath.Join(fixtureDir, "host-runtime.json"),
		BootstrapRoot:  filepath.Join(fixtureDir, "bootstrap"),
		SlotsRoot:      filepath.Join(fixtureDir, "slots"),
		ControllerRoot: filepath.Join(fixtureDir, "controller"),
		AllowNonRoot:   true,
		GuestTransport: getPersistentFixtureGuestTransport(fixtureDir),
		HTTPClient:     client,
		AdvanceTimeout: 30 * time.Second,
	}
}

type fixtureServicesState struct {
	ActiveUnits  map[string]bool `json:"active_units"`
	EnabledUnits map[string]bool `json:"enabled_units"`
	Port8080Open bool            `json:"port_8080_open"`
}

func init() {
	getServicesFile := func() string {
		fixtureDir := os.Getenv("ACORNFOX_FIXTURE_DIR")
		if fixtureDir == "" {
			fixtureDir = "/tmp/acornfox-fixture"
		}
		return filepath.Join(fixtureDir, "services.json")
	}

	loadServices := func() fixtureServicesState {
		var st fixtureServicesState
		raw, err := os.ReadFile(getServicesFile())
		if err == nil {
			_ = json.Unmarshal(raw, &st)
		}
		if st.ActiveUnits == nil {
			st.ActiveUnits = make(map[string]bool)
			for _, u := range RequiredApplicationUnits {
				st.ActiveUnits[u] = true
			}
			st.Port8080Open = true
		}
		if st.EnabledUnits == nil {
			st.EnabledUnits = make(map[string]bool)
			for _, u := range RequiredApplicationUnits {
				st.EnabledUnits[u] = true
			}
			st.EnabledUnits["acornfox-edge.service"] = true
			st.EnabledUnits["acornfox-healthcheck.timer"] = true
		}
		return st
	}

	saveServices := func(st fixtureServicesState) {
		raw, _ := json.Marshal(st)
		_ = os.WriteFile(getServicesFile(), raw, 0600)
	}

	unitCommandRunner = func(ctx context.Context, action string, unit string) error {
		fixtureBackendMu.Lock()
		defer fixtureBackendMu.Unlock()
		st := loadServices()
		if action == "stop" {
			delete(st.ActiveUnits, unit)
			if unit == "acornfox-caddy.service" || unit == "acornfox-server.service" {
				st.Port8080Open = false
			}
		} else if action == "start" {
			st.ActiveUnits[unit] = true
			if unit == "acornfox-caddy.service" || unit == "acornfox-server.service" {
				st.Port8080Open = true
			}
		}
		saveServices(st)
		return nil
	}

	unitActiveRunner = func(ctx context.Context, unit string) (bool, error) {
		fixtureBackendMu.Lock()
		defer fixtureBackendMu.Unlock()
		st := loadServices()
		return st.ActiveUnits[unit], nil
	}

	unitEnabledRunner = func(ctx context.Context, unit string) (bool, error) {
		fixtureBackendMu.Lock()
		defer fixtureBackendMu.Unlock()
		st := loadServices()
		return st.EnabledUnits[unit], nil
	}

	portReleasedRunner = func(ctx context.Context, addr string, timeout time.Duration) error {
		fixtureBackendMu.Lock()
		defer fixtureBackendMu.Unlock()
		st := loadServices()
		if !st.Port8080Open {
			return nil
		}
		return nil
	}

	httpProbeRunner = func(ctx context.Context, client *http.Client, target string) (int, []byte, error) {
		if strings.Contains(target, "/healthz") || strings.Contains(target, "/readyz") {
			return 200, []byte("ok"), nil
		}
		if strings.Contains(target, "/setup") {
			return 200, []byte(`{"state":"uninitialized"}`), nil
		}
		return 200, nil, nil
	}
}

func getLauncherEnvironment() []string {
	env := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	for _, k := range []string{"ACORNFOX_FIXTURE_DIR", "ACORNFOX_FIXTURE_SERVER", "ACORNFOX_FIXTURE_ALLOW_NONROOT"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func traceAdmittedMarker(operation string) {
	fixtureDir := os.Getenv("ACORNFOX_FIXTURE_DIR")
	if fixtureDir == "" {
		return
	}
	traceFile := filepath.Join(fixtureDir, "marker-trace.log")
	if f, err := os.OpenFile(traceFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
		_, _ = f.WriteString(fmt.Sprintf("%s:%s\n", BuildMarker, operation))
		_ = f.Close()
	}
}
