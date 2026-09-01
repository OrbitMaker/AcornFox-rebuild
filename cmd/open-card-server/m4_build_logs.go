package main

import (
	"context"
	"fmt"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/observability"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type m4BuildLogSink struct {
	store *postgres.Store
	logs  *observability.LogStore
	clock func() time.Time
}

func (s *m4BuildLogSink) StoreBuildLog(ctx context.Context, request contracts.BuildRequest, content string) (string, error) {
	if s == nil || s.store == nil || s.logs == nil {
		return "", fmt.Errorf("M4 build log sink is unavailable")
	}
	stream := "build-" + request.BuildID.String()
	file, err := s.logs.AppendRecord(observability.LogCategoryBuild, stream, []byte(content))
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if s.clock != nil {
		now = s.clock().UTC()
	}
	if err := s.store.AppendLogIndex(ctx, postgres.LogIndex{ID: m4AdapterID("log", stream+fmt.Sprint(file.Sequence)), ApplicationID: request.Source.ApplicationID, ServiceName: request.Plan.ServiceName, Category: postgres.LogIndexBuild, Path: file.Path, Segment: file.Sequence, ByteSize: file.Bytes, CreatedAt: now}, now); err != nil {
		return "", err
	}
	if err := m4ReconcileOrdinaryLogIndexes(ctx, s.store, s.logs, now); err != nil {
		return "", err
	}
	return file.Path, nil
}
