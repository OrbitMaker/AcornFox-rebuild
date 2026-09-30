package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

// LogBatchAPI is optional for clients that only support a one-shot tail.
// Following is short polling: each response releases the shared SSH transport.
type LogBatchAPI interface {
	LogBatch(ctx context.Context, app string, tail int, since, cursor string) (LogBatch, error)
}

type LogBatch struct {
	Lines   []string `json:"lines"`
	Cursor  string   `json:"cursor"`
	HasMore bool     `json:"has_more"`
	Reset   bool     `json:"reset"`
}

func (c *Client) LogBatch(ctx context.Context, app string, tail int, since, cursor string) (LogBatch, error) {
	query := url.Values{"tail": {strconv.Itoa(tail)}}
	if since != "" {
		query.Set("since", since)
	}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	var batch LogBatch
	_, err := c.doJSON(ctx, http.MethodGet, "/v1/apps/"+url.PathEscape(app)+"/log-batch?"+query.Encode(), nil, &batch)
	return batch, err
}
