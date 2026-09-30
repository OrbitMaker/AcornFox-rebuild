package apiserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

// logCursor counts records at the boundary timestamp, never matching on text:
// two identical lines at the same instant remain two distinct log events.
type logCursor struct {
	Deployment string `json:"deployment"`
	Timestamp  string `json:"timestamp"`
	Offset     int    `json:"offset"`
}

type logBatchView struct {
	Lines   []string `json:"lines"`
	Cursor  string   `json:"cursor"`
	HasMore bool     `json:"has_more"`
	Reset   bool     `json:"reset"`
}

func (s *server) logSecrets(ctx context.Context, app string) ([]string, error) {
	vars, err := s.store.ListEnv(ctx, app)
	if err != nil {
		return nil, err
	}
	var secrets []string
	for _, v := range vars {
		if v.Secret && len(v.Value) >= 4 {
			secrets = append(secrets, v.Value)
		}
	}
	active, err := s.store.ListAddons(ctx, app)
	if err != nil {
		return nil, err
	}
	removed, err := s.store.ListRemovedAddons(ctx, app)
	if err != nil {
		return nil, err
	}
	for _, addon := range append(active, removed...) {
		creds, err := addon.DecodeCredentials()
		if err != nil {
			return nil, err
		}
		for _, value := range []string{creds.URL, creds.Password, creds.RootPassword} {
			if len(value) >= 4 {
				secrets = append(secrets, value)
			}
		}
	}
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	return secrets, nil
}

func redactObservedLines(lines, secrets []string) []string {
	// Redaction happens only after complete Docker frames/lines are buffered,
	// and joining also protects secret values containing a newline.
	joined := strings.Join(lines, "\n")
	for _, secret := range secrets {
		joined = strings.ReplaceAll(joined, secret, "******")
	}
	if len(lines) == 0 {
		return []string{}
	}
	return strings.Split(joined, "\n")
}

func logTail(r *http.Request) (int, error) {
	tail := 100
	if raw := r.URL.Query().Get("tail"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			return 0, fmt.Errorf("tail 必须是正整数")
		}
		if value > 1000 {
			value = 1000
		}
		tail = value
	}
	return tail, nil
}

// observedLogs keeps the original tail-only response while supporting the
// polling protocol when follow/since/cursor is requested. Short requests do
// not monopolize the single SSH connection used by a CLI command.
func (s *server) observedLogs(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("follow") == "true" || r.URL.Query().Get("since") != "" || r.URL.Query().Get("cursor") != "" {
		s.appLogBatch(w, r)
		return
	}
	ctx := r.Context()
	app := r.PathValue("app")
	if !state.ValidAppName(app) {
		writeError(w, 400, "invalid_app", "应用名不合法")
		return
	}
	tail, err := logTail(r)
	if err != nil {
		writeError(w, 400, "invalid_tail", err.Error())
		return
	}
	a, err := s.store.GetApp(ctx, app)
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	if a.CurrentDeployment == "" {
		writeError(w, 404, "no_live_deployment", "该应用没有上线版本")
		return
	}
	secrets, err := s.logSecrets(ctx, app)
	if err != nil {
		writeError(w, 503, "redaction_unavailable", "无法安全读取日志：密钥脱敏配置不可用")
		return
	}
	lines, err := s.runner.Logs(ctx, app, runner.ContainerName(app, a.CurrentDeployment), tail)
	if err != nil {
		s.logReadError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": redactObservedLines(lines, secrets)})
}

func (s *server) logReadError(w http.ResponseWriter, err error) {
	if errors.Is(err, runner.ErrNotFound) {
		writeError(w, 404, "no_live_deployment", "该应用没有正在运行的容器")
		return
	}
	writeError(w, 503, "runner_unavailable", "无法读取容器日志，请稍后重试")
}

func (s *server) appLogBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app := r.PathValue("app")
	if !state.ValidAppName(app) {
		writeError(w, 400, "invalid_app", "应用名不合法")
		return
	}
	tail, err := logTail(r)
	if err != nil {
		writeError(w, 400, "invalid_tail", err.Error())
		return
	}
	var cursor logCursor
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		if len(raw) > 2048 {
			writeError(w, 400, "invalid_cursor", "日志游标不合法")
			return
		}
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || json.Unmarshal(decoded, &cursor) != nil || cursor.Offset < 0 || cursor.Offset > 1000000 || !runner.ValidDeploymentID(cursor.Deployment) {
			writeError(w, 400, "invalid_cursor", "日志游标不合法")
			return
		}
		if cursor.Timestamp != "" {
			if _, err := time.Parse(time.RFC3339Nano, cursor.Timestamp); err != nil {
				writeError(w, 400, "invalid_cursor", "日志游标时间不合法")
				return
			}
		}
	}
	since := r.URL.Query().Get("since")
	if since != "" {
		if _, err := time.Parse(time.RFC3339Nano, since); err != nil {
			writeError(w, 400, "invalid_since", "since 必须是 RFC3339 时间（例如 2026-09-30T10:00:00Z）")
			return
		}
	}
	a, err := s.store.GetApp(ctx, app)
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	if a.CurrentDeployment == "" {
		writeError(w, 404, "no_live_deployment", "该应用没有上线版本")
		return
	}
	reset := cursor.Deployment != "" && cursor.Deployment != a.CurrentDeployment
	if reset {
		cursor = logCursor{}
		since = ""
	}
	secrets, err := s.logSecrets(ctx, app)
	if err != nil {
		writeError(w, 503, "redaction_unavailable", "无法安全读取日志：密钥脱敏配置不可用")
		return
	}
	reader, ok := s.runner.(runner.LogBatchReader)
	if !ok {
		writeError(w, 501, "logs_follow_unsupported", "执行器不支持日志跟随，请升级后重试")
		return
	}
	if cursor.Timestamp != "" {
		since = cursor.Timestamp
	}
	// Ask one nanosecond before the inclusive boundary, then filter precisely:
	// both inclusive and exclusive Docker log drivers include that boundary.
	querySince := since
	if since != "" {
		stamp, _ := time.Parse(time.RFC3339Nano, since)
		querySince = stamp.Add(-time.Nanosecond).Format(time.RFC3339Nano)
	}
	batch, err := reader.LogBatch(ctx, app, runner.ContainerName(app, a.CurrentDeployment), tail, querySince)
	if err != nil {
		s.logReadError(w, err)
		return
	}
	view := pageLogRecords(batch.Records, cursor, a.CurrentDeployment, since, tail)
	if since == "" && cursor.Timestamp == "" && batch.BoundaryOffset > 0 && len(batch.Records) > 0 && !view.HasMore {
		last := batch.Records[len(batch.Records)-1].Timestamp
		raw, _ := json.Marshal(logCursor{Deployment: a.CurrentDeployment, Timestamp: last, Offset: batch.BoundaryOffset})
		view.Cursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	view.Reset = reset
	view.Lines = redactObservedLines(view.Lines, secrets)
	writeJSON(w, 200, view)
}

func pageLogRecords(records []runner.LogRecord, cursor logCursor, deployment, since string, limit int) logBatchView {
	out := logBatchView{Lines: []string{}}
	next := cursor
	next.Deployment = deployment
	boundarySkipped := 0
	for _, record := range records {
		stamp, err := time.Parse(time.RFC3339Nano, record.Timestamp)
		if err != nil {
			continue
		} // production runner validates every timestamp
		if since != "" {
			lower, _ := time.Parse(time.RFC3339Nano, since)
			if stamp.Before(lower) {
				continue
			}
		}
		if cursor.Timestamp != "" && record.Timestamp == cursor.Timestamp && boundarySkipped < cursor.Offset {
			boundarySkipped++
			continue
		}
		if len(out.Lines) >= limit {
			out.HasMore = true
			break
		}
		out.Lines = append(out.Lines, record.Text)
		if next.Timestamp == record.Timestamp {
			next.Offset++
		} else {
			next.Timestamp = record.Timestamp
			next.Offset = 1
		}
	}
	if next.Timestamp == "" && since != "" {
		next.Timestamp = since
	}
	raw, _ := json.Marshal(next)
	out.Cursor = base64.RawURLEncoding.EncodeToString(raw)
	return out
}
