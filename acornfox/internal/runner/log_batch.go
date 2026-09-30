package runner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

const PathContainerLogBatch = "/v1/containers/log-batch"

// LogBatchReader is optional so older runner implementations can retain the
// tail-only API. Production Docker and socket clients implement this interface.
type LogBatchReader interface {
	LogBatch(ctx context.Context, app, name string, tail int, since string) (LogBatchResponse, error)
}

type LogRecord struct {
	Timestamp string `json:"timestamp"`
	Text      string `json:"text"`
}

type LogBatchResponse struct {
	Records        []LogRecord `json:"records"`
	BoundaryOffset int         `json:"boundary_offset,omitempty"`
}

type logBatchRequest struct {
	App   string `json:"app"`
	Name  string `json:"name"`
	Tail  int    `json:"tail"`
	Since string `json:"since,omitempty"`
}

func (d *Docker) LogBatch(ctx context.Context, app, name string, tail int, since string) (LogBatchResponse, error) {
	c, err := d.managedContainer(ctx, app, name)
	if err != nil {
		return LogBatchResponse{}, err
	}
	if since != "" {
		if _, err := time.Parse(time.RFC3339Nano, since); err != nil {
			return LogBatchResponse{}, fmt.Errorf("invalid log timestamp")
		}
	}
	if tail <= 0 {
		tail = 100
	}
	if tail > 1000 {
		tail = 1000
	}
	// Count the complete timestamp boundary before trimming the initial tail.
	// Docker timestamps alone are not unique: starting from a suffix must not
	// replay earlier records sharing its last timestamp on the next poll.
	tailArg := "all"
	rc, err := d.cli.ContainerLogs(ctx, c.ID, client.ContainerLogsOptions{
		ShowStdout: true, ShowStderr: true, Timestamps: true, Tail: tailArg, Since: since,
	})
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return LogBatchResponse{}, ErrNotFound
		}
		return LogBatchResponse{}, err
	}
	defer rc.Close()
	// Never advance a cursor over a silently truncated buffer.
	const maxBytes = 32 << 20
	raw, err := io.ReadAll(io.LimitReader(rc, maxBytes+1))
	if err != nil {
		return LogBatchResponse{}, err
	}
	if len(raw) > maxBytes {
		return LogBatchResponse{}, fmt.Errorf("log batch exceeds 32 MiB; request a more recent since timestamp")
	}
	var decoded bytes.Buffer
	if c.Config.Tty {
		decoded.Write(raw)
	} else if _, err := stdcopy.StdCopy(&decoded, &decoded, bytes.NewReader(raw)); err != nil {
		return LogBatchResponse{}, err
	}
	records, err := parseLogRecords(decoded.Bytes())
	if err != nil {
		return LogBatchResponse{}, err
	}
	batch := LogBatchResponse{Records: records}
	if since != "" && len(records) > tail+1 {
		batch.Records = records[:tail+1]
	}
	if since == "" && len(records) > 0 {
		last := records[len(records)-1].Timestamp
		for i := len(records) - 1; i >= 0 && records[i].Timestamp == last; i-- {
			batch.BoundaryOffset++
		}
		if len(records) > tail {
			batch.Records = records[len(records)-tail:]
		}
	}
	return batch, nil
}

func parseLogRecords(data []byte) ([]LogRecord, error) {
	var records []LogRecord
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 4096), 1<<20)
	for sc.Scan() {
		ts, text, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			return nil, fmt.Errorf("Docker log record missing timestamp")
		}
		stamp, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, fmt.Errorf("Docker log timestamp invalid")
		}
		records = append(records, LogRecord{Timestamp: stamp.UTC().Format(time.RFC3339Nano), Text: ansiPattern.ReplaceAllString(strings.TrimSuffix(text, "\r"), "")})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// stdout/stderr Docker frames may arrive grouped. Equal timestamps retain
	// their original order; content is never used as an identity or dedupe key.
	sort.SliceStable(records, func(i, j int) bool {
		a, _ := time.Parse(time.RFC3339Nano, records[i].Timestamp)
		b, _ := time.Parse(time.RFC3339Nano, records[j].Timestamp)
		return a.Before(b)
	})
	return records, nil
}

func (c *Client) LogBatch(ctx context.Context, app, name string, tail int, since string) (LogBatchResponse, error) {
	var out LogBatchResponse
	err := c.call(ctx, c.standard, PathContainerLogBatch, logBatchRequest{App: app, Name: name, Tail: tail, Since: since}, clientLargeBound, &out)
	return out, err
}

func (s *Server) handleLogBatch(w http.ResponseWriter, r *http.Request) {
	var req logBatchRequest
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	if !validContainerName(w, req.App, req.Name) {
		return
	}
	if req.Since != "" {
		if _, err := time.Parse(time.RFC3339Nano, req.Since); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid since timestamp")
			return
		}
	}
	reader, ok := s.api.(LogBatchReader)
	if !ok {
		writeError(w, http.StatusNotImplemented, "unsupported", "timestamped logs not supported")
		return
	}
	batch, err := reader.LogBatch(r.Context(), req.App, req.Name, req.Tail, req.Since)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if batch.Records == nil {
		batch.Records = []LogRecord{}
	}
	writeJSON(w, http.StatusOK, batch)
}
