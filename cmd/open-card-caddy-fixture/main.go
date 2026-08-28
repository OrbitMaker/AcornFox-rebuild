package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxBody = 4 << 20

var (
	safeID        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type fault struct {
	RolloutID string `json:"rollout_id"`
	Digest    string `json:"route_set_digest"`
	Mode      string `json:"mode"`
}
type fixture struct {
	mu                sync.Mutex
	fault             *fault
	token, taskPrefix string
	listen            string
	upstream          *url.URL
	evidence          string
	client            *http.Client
}

func main() {
	listen := flag.String("listen", "127.0.0.1:2020", "loopback listen address")
	upstream := flag.String("upstream", "http://127.0.0.1:2019", "fixed loopback Caddy admin URL")
	tokenFile := flag.String("token-file", "", "0600 control token file")
	taskPrefix := flag.String("task-prefix", "", "exact clean-worker task prefix")
	evidence := flag.String("evidence-file", "", "task-scoped evidence NDJSON")
	flag.Parse()
	h, err := newFixture(*listen, *upstream, *tokenFile, *taskPrefix, *evidence)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(64)
	}
	server := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "fixture server failed")
		os.Exit(1)
	}
}

func newFixture(listen, upstreamRaw, tokenFile, taskPrefix, evidence string) (*fixture, error) {
	if !safeID.MatchString(taskPrefix) || !strings.HasPrefix(taskPrefix, "opencard-mvp-") {
		return nil, errors.New("task prefix is invalid")
	}
	if err := loopbackAddress(listen); err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	upstream, err := url.Parse(upstreamRaw)
	if err != nil || upstream.Scheme != "http" || upstream.User != nil || upstream.Path != "" || upstream.RawQuery != "" || upstream.Fragment != "" {
		return nil, errors.New("upstream must be a plain loopback HTTP origin")
	}
	if err := loopbackAddress(upstream.Host); err != nil {
		return nil, fmt.Errorf("upstream: %w", err)
	}
	info, err := os.Lstat(tokenFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("token file must be a private regular file")
	}
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, errors.New("token file is unreadable")
	}
	token := strings.TrimSpace(string(tokenBytes))
	if len(token) < 24 || len(token) > 4096 {
		return nil, errors.New("control token length is invalid")
	}
	root := filepath.Clean(filepath.Join("/var/lib", taskPrefix))
	evidence = filepath.Clean(evidence)
	if !strings.HasPrefix(evidence, root+string(os.PathSeparator)) {
		return nil, errors.New("evidence file is outside task scope")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &fixture{token: token, taskPrefix: taskPrefix, listen: listen, upstream: upstream, evidence: evidence, client: &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func loopbackAddress(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || port == "" {
		return errors.New("explicit host and port are required")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("address must be a literal loopback IP")
	}
	return nil
}

func (f *fixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remote, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(remote); ip == nil || !ip.IsLoopback() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/__fixture/ready":
		if r.Method != http.MethodGet {
			http.Error(w, "method", 405)
			return
		}
		w.WriteHeader(204)
		return
	case "/__fixture/fault":
		f.control(w, r)
		return
	case "/load", "/config/":
		f.proxy(w, r)
		return
	default:
		http.NotFound(w, r)
	}
}

func (f *fixture) control(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("X-Open-Card-Task-Scope") != f.taskPrefix || !constantToken(r.Header.Get("Authorization"), f.token) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var requested fault
	decoder := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&requested) != nil || !safeID.MatchString(requested.RolloutID) || !digestPattern.MatchString(requested.Digest) || (requested.Mode != "load" && requested.Mode != "observe") {
		http.Error(w, "invalid fault scope", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fault != nil {
		http.Error(w, "fault already armed", http.StatusConflict)
		return
	}
	f.fault = &requested
	writeJSON(w, 200, map[string]any{"armed": true, "rollout_id": requested.RolloutID, "route_set_digest": requested.Digest, "mode": requested.Mode})
}

func constantToken(header, token string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	provided := strings.TrimPrefix(header, prefix)
	return len(provided) == len(token) && subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1
}

func (f *fixture) proxy(w http.ResponseWriter, r *http.Request) {
	if (r.URL.Path == "/load" && r.Method != http.MethodPost) || (r.URL.Path == "/config/" && r.Method != http.MethodGet) {
		http.Error(w, "method", 405)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		http.Error(w, "body too large", 413)
		return
	}
	if r.URL.Path == "/load" {
		body, err = f.normalizeAdminListen(body)
		if err != nil {
			http.Error(w, "invalid Caddy admin scope", http.StatusBadRequest)
			return
		}
	}
	rolloutID, digest := r.Header.Get("X-Open-Card-Rollout-ID"), r.Header.Get("X-Open-Card-Route-Digest")
	mode := "load"
	if r.URL.Path == "/config/" {
		mode = "observe"
	}
	f.mu.Lock()
	armed := f.fault != nil && f.fault.RolloutID == rolloutID && f.fault.Digest == digest && f.fault.Mode == mode
	if armed {
		consumed := *f.fault
		if err := f.record(consumed, r.URL.Path); err != nil {
			f.mu.Unlock()
			http.Error(w, "fixture evidence unavailable", http.StatusInternalServerError)
			return
		}
		f.fault = nil
		f.mu.Unlock()
		writeJSON(w, 503, map[string]any{"error": "task-scoped Caddy fault injected", "mode": mode, "rollout_id": rolloutID, "route_set_digest": digest})
		return
	}
	f.mu.Unlock()
	target := *f.upstream
	target.Path = r.URL.Path
	request, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "upstream request", 500)
		return
	}
	request.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	request.Header.Set("X-Open-Card-Rollout-ID", rolloutID)
	request.Header.Set("X-Open-Card-Route-Digest", digest)
	response, err := f.client.Do(request)
	if err != nil {
		http.Error(w, "upstream unavailable", 502)
		return
	}
	defer response.Body.Close()
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(response.Body, maxBody))
}

func (f *fixture) normalizeAdminListen(body []byte) ([]byte, error) {
	var document map[string]any
	if json.Unmarshal(body, &document) != nil {
		return nil, errors.New("Caddy config is invalid JSON")
	}
	admin, ok := document["admin"].(map[string]any)
	if !ok {
		return nil, errors.New("Caddy config omits admin")
	}
	listen, ok := admin["listen"].(string)
	if !ok || (listen != f.listen && listen != f.upstream.Host) {
		return nil, errors.New("Caddy admin listen is outside fixture scope")
	}
	admin["listen"] = f.upstream.Host
	return json.Marshal(document)
}

func (f *fixture) record(value fault, path string) error {
	if err := os.MkdirAll(filepath.Dir(f.evidence), 0o750); err != nil {
		return err
	}
	file, err := os.OpenFile(f.evidence, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(map[string]any{"at": time.Now().UTC(), "rollout_id": value.RolloutID, "route_set_digest": value.Digest, "mode": value.Mode, "path": path, "consumed": true})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
