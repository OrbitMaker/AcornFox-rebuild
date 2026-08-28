//go:build integration

package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/application"
)

func TestM4OutboxUsesDatabaseGlobalSequenceUnderConcurrency(t *testing.T) {
	dsn := os.Getenv("OPEN_CARD_TEST_DATABASE_URL")
	if strings.TrimSpace(dsn) == "" {
		t.Skip("OPEN_CARD_TEST_DATABASE_URL is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	const writers = 12
	start := make(chan struct{})
	errorsByWriter := make(chan error, writers)
	var wait sync.WaitGroup
	for index := 0; index < writers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			tx, err := db.BeginTx(ctx, nil)
			if err == nil {
				event := application.Event{OperationID: fmt.Sprintf("op_m4_outbox_%02d", index), ApplicationID: "app_m4_outbox", Kind: "operations.test.succeeded", Status: "succeeded", Message: "concurrent sequence test"}
				err = appendM4OutboxTx(ctx, tx, event, time.Now().UTC())
			}
			if err == nil {
				err = tx.Commit()
			} else if tx != nil {
				_ = tx.Rollback()
			}
			errorsByWriter <- err
		}(index)
	}
	close(start)
	wait.Wait()
	close(errorsByWriter)
	for err := range errorsByWriter {
		if err != nil {
			t.Fatalf("concurrent M4 outbox append failed: %v", err)
		}
	}
	var count, distinct int
	if err := db.QueryRowContext(ctx, `SELECT count(*),count(DISTINCT stream_sequence) FROM outbox_events WHERE aggregate_type='operation' AND aggregate_id LIKE 'op_m4_outbox_%'`).Scan(&count, &distinct); err != nil {
		t.Fatal(err)
	}
	if count != writers || distinct != writers {
		t.Fatalf("global outbox sequence collision: count=%d distinct=%d", count, distinct)
	}
}
