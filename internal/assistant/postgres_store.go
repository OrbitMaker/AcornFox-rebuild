package assistant

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

const assistantWriterLease = "acornfox-assistant-writer-v1"

var ErrWriterLeaseHeld = errors.New("assistant writer lease is already held")

type PostgresStore struct {
	db            *sql.DB
	writer        *sql.Conn
	mu            sync.Mutex
	broken        bool
	done          chan struct{}
	doneOnce      sync.Once
	monitorCancel context.CancelFunc
	monitorWG     sync.WaitGroup
	heartbeat     time.Duration
}

func NewPostgresStore(ctx context.Context, db *sql.DB) (*PostgresStore, error) {
	return newPostgresStore(ctx, db, 2*time.Second)
}

func newPostgresStore(ctx context.Context, db *sql.DB, heartbeat time.Duration) (*PostgresStore, error) {
	if db == nil || heartbeat <= 0 {
		return nil, ErrUnavailable
	}
	// A pinned writer consumes one pool connection. Reject an explicit one-slot
	// pool instead of silently deadlocking pool-backed reads.
	if maximum := db.Stats().MaxOpenConnections; maximum == 1 {
		return nil, ErrUnavailable
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	var acquired bool
	if err = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, assistantWriterLease).Scan(&acquired); err != nil || !acquired {
		if err != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
		_ = conn.Close()
		if err == nil {
			return nil, ErrWriterLeaseHeld
		}
		return nil, ErrUnavailable
	}
	monitorCtx, cancel := context.WithCancel(context.Background())
	store := &PostgresStore{db: db, writer: conn, done: make(chan struct{}), monitorCancel: cancel, heartbeat: heartbeat}
	store.monitorWG.Add(1)
	go store.monitor(monitorCtx)
	return store, nil
}

func (s *PostgresStore) Done() <-chan struct{} {
	if s == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return s.done
}

func (s *PostgresStore) Close() error {
	if s == nil {
		return nil
	}
	s.monitorCancel()
	s.monitorWG.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writer == nil {
		s.signalDoneLocked()
		return nil
	}
	var unlocked bool
	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	err := s.writer.QueryRowContext(closeCtx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, assistantWriterLease).Scan(&unlocked)
	cancel()
	if err != nil || !unlocked {
		s.discardWriterLocked()
	} else {
		_ = s.writer.Close()
		s.writer = nil
	}
	s.broken = true
	s.signalDoneLocked()
	if err != nil || !unlocked {
		return ErrUnavailable
	}
	return nil
}

func (s *PostgresStore) monitor(ctx context.Context) {
	defer s.monitorWG.Done()
	ticker := time.NewTicker(s.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			if s.broken || s.writer == nil {
				s.mu.Unlock()
				return
			}
			pingCtx, cancel := context.WithTimeout(ctx, s.heartbeat)
			var one int
			err := s.writer.QueryRowContext(pingCtx, `SELECT 1`).Scan(&one)
			cancel()
			if err != nil || one != 1 {
				s.discardWriterLocked()
				s.broken = true
				s.signalDoneLocked()
				s.mu.Unlock()
				return
			}
			s.mu.Unlock()
		}
	}
}

func (s *PostgresStore) write(ctx context.Context, operation func(*sql.Conn) error) error {
	if s == nil {
		return ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken || s.writer == nil {
		return ErrUnavailable
	}
	err := operation(s.writer)
	if err != nil && !knownStoreError(err) {
		probeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		var one int
		probeErr := s.writer.QueryRowContext(probeCtx, `SELECT 1`).Scan(&one)
		cancel()
		if probeErr != nil || one != 1 {
			s.discardWriterLocked()
			s.broken = true
			s.signalDoneLocked()
		}
	}
	return err
}

func (s *PostgresStore) discardWriterLocked() {
	if s.writer == nil {
		return
	}
	_ = s.writer.Raw(func(any) error { return driver.ErrBadConn })
	_ = s.writer.Close()
	s.writer = nil
}
func (s *PostgresStore) signalDoneLocked() { s.doneOnce.Do(func() { close(s.done) }) }
func knownStoreError(err error) bool {
	return errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrIdempotencyConflict) || errors.Is(err, ErrSessionLimit) || errors.Is(err, ErrRunLimit) || errors.Is(err, ErrCursorExpired) || errors.Is(err, ErrEventLimit)
}

func (s *PostgresStore) CreateSession(ctx context.Context, actor Actor, session Session) error {
	if !validActor(actor) || session.ID.Empty() || session.ownerID != actor.AdminID || session.Scope.Validate() != nil {
		return ErrInvalidInput
	}
	return s.write(ctx, func(conn *sql.Conn) error {
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM acornfox_assistant_sessions WHERE owner_admin_id=$1`, actor.AdminID.String()).Scan(&count); err != nil {
			return err
		}
		if count >= MaxSessionsPerOwner {
			return ErrSessionLimit
		}
		var app any
		if !session.Scope.AppID.Empty() {
			app = session.Scope.AppID.String()
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO acornfox_assistant_sessions(id,owner_admin_id,scope_kind,app_id,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$5)`, session.ID.String(), actor.AdminID.String(), string(session.Scope.Kind), app, session.CreatedAt.UTC())
		if err != nil {
			return err
		}
		return tx.Commit()
	})
}

func (s *PostgresStore) ListSessions(ctx context.Context, actor Actor) ([]Session, error) {
	if !validActor(actor) {
		return nil, ErrUnauthorized
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,owner_admin_id,scope_kind,app_id,created_at,updated_at FROM acornfox_assistant_sessions WHERE owner_admin_id=$1 ORDER BY created_at,id`, actor.AdminID.String())
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	result := []Session{}
	for rows.Next() {
		session, e := scanSession(rows)
		if e != nil {
			return nil, ErrUnavailable
		}
		result = append(result, session)
	}
	if err = rows.Err(); err != nil {
		return nil, ErrUnavailable
	}
	return result, nil
}

func (s *PostgresStore) GetSession(ctx context.Context, actor Actor, id domain.ID) (Session, error) {
	if !validActor(actor) || id.Empty() {
		return Session{}, ErrNotFound
	}
	session, err := scanSession(s.db.QueryRowContext(ctx, `SELECT id,owner_admin_id,scope_kind,app_id,created_at,updated_at FROM acornfox_assistant_sessions WHERE id=$1 AND owner_admin_id=$2`, id.String(), actor.AdminID.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, ErrUnavailable
	}
	return session, nil
}

func (s *PostgresStore) CreateOrReplayRun(ctx context.Context, actor Actor, sessionID domain.ID, key, digest string, run Run, at time.Time) (stored Run, replay bool, err error) {
	if !validActor(actor) || sessionID.Empty() || !validIdempotencyKey(key) || len(digest) != 64 || !validMessage(run.message) {
		return Run{}, false, ErrInvalidInput
	}
	err = s.write(ctx, func(conn *sql.Conn) error {
		tx, e := conn.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		var owner string
		var runCount int
		var messageBytes int64
		e = tx.QueryRowContext(ctx, `SELECT owner_admin_id,run_count,message_bytes FROM acornfox_assistant_sessions WHERE id=$1 FOR UPDATE`, sessionID.String()).Scan(&owner, &runCount, &messageBytes)
		if errors.Is(e, sql.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		if owner != actor.AdminID.String() {
			return ErrNotFound
		}
		existing, e := scanRun(tx.QueryRowContext(ctx, `SELECT r.id,r.session_id,r.idempotency_key,r.request_digest,r.message,r.status,r.created_at,r.updated_at,s.owner_admin_id FROM acornfox_assistant_runs r JOIN acornfox_assistant_sessions s ON s.id=r.session_id WHERE r.session_id=$1 AND r.idempotency_key=$2`, sessionID.String(), key))
		if e == nil {
			if subtle.ConstantTimeCompare([]byte(existing.requestDigest), []byte(digest)) != 1 {
				return ErrIdempotencyConflict
			}
			stored, replay = existing, true
			return tx.Commit()
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		var queued int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM acornfox_assistant_runs WHERE session_id=$1 AND status IN ('accepted','running')`, sessionID.String()).Scan(&queued); e != nil {
			return e
		}
		if runCount >= MaxRunsPerSession || queued >= MaxQueuedRunsPerSession || messageBytes+int64(len(run.message)) > MaxRunMessageBytesPerSession {
			return ErrRunLimit
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO acornfox_assistant_runs(id,session_id,idempotency_key,request_digest,message,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'accepted',$6,$6)`, run.ID.String(), sessionID.String(), key, digest, run.message, at.UTC())
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `UPDATE acornfox_assistant_sessions SET run_count=run_count+1,message_bytes=message_bytes+$2,updated_at=$3 WHERE id=$1`, sessionID.String(), len(run.message), at.UTC())
		if e != nil {
			return e
		}
		run.ownerID, run.SessionID, run.requestDigest, run.idempotencyKey, run.Status = actor.AdminID, sessionID, digest, key, RunAccepted
		if _, e = appendEventTx(ctx, tx, sessionID, run.ID, EventRunAccepted, run.message, at); e != nil {
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
		stored = run
		return nil
	})
	return
}

func (s *PostgresStore) ClaimNextRun(ctx context.Context, sessionID domain.ID, at time.Time) (claimed Run, found bool, err error) {
	err = s.write(ctx, func(conn *sql.Conn) error {
		tx, e := conn.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		var running bool
		if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM acornfox_assistant_runs WHERE session_id=$1 AND status='running')`, sessionID.String()).Scan(&running); e != nil {
			return e
		}
		if running {
			return nil
		}
		run, e := scanRun(tx.QueryRowContext(ctx, `SELECT r.id,r.session_id,r.idempotency_key,r.request_digest,r.message,r.status,r.created_at,r.updated_at,s.owner_admin_id FROM acornfox_assistant_runs r JOIN acornfox_assistant_sessions s ON s.id=r.session_id WHERE r.session_id=$1 AND r.status='accepted' ORDER BY r.created_at,r.id FOR UPDATE OF r SKIP LOCKED LIMIT 1`, sessionID.String()))
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE acornfox_assistant_runs SET status='running',updated_at=$2 WHERE id=$1`, run.ID.String(), at.UTC()); e != nil {
			return e
		}
		if _, e = appendEventTx(ctx, tx, sessionID, run.ID, EventRunStarted, "", at); e != nil {
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
		run.Status, run.UpdatedAt = RunRunning, at.UTC()
		claimed, found = run, true
		return nil
	})
	return
}

func (s *PostgresStore) AppendEvent(ctx context.Context, sessionID, runID domain.ID, kind EventType, text string, at time.Time) (event Event, err error) {
	if kind != EventAssistantDelta && kind != EventAssistantMessage || !validEventText(text) {
		return Event{}, ErrInvalidInput
	}
	err = s.write(ctx, func(conn *sql.Conn) error {
		tx, e := conn.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		var status string
		e = tx.QueryRowContext(ctx, `SELECT status FROM acornfox_assistant_runs WHERE id=$1 AND session_id=$2 FOR UPDATE`, runID.String(), sessionID.String()).Scan(&status)
		if errors.Is(e, sql.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		if RunStatus(status) != RunRunning {
			return ErrNotFound
		}
		if kind == EventAssistantMessage {
			if e = compactRunDeltasTx(ctx, tx, sessionID, runID); e != nil {
				return e
			}
		}
		event, e = appendEventTx(ctx, tx, sessionID, runID, kind, text, at)
		if e != nil {
			return e
		}
		return tx.Commit()
	})
	return
}

func compactRunDeltasTx(ctx context.Context, tx *sql.Tx, sessionID, runID domain.ID) error {
	rows, err := tx.QueryContext(ctx, `DELETE FROM acornfox_assistant_events WHERE session_id=$1 AND run_id=$2 AND event_type='assistant.delta' RETURNING byte_size`, sessionID.String(), runID.String())
	if err != nil {
		return err
	}
	removed := 0
	for rows.Next() {
		var size int
		if err = rows.Scan(&size); err != nil {
			rows.Close()
			return err
		}
		removed += size
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	if removed > 0 {
		_, err = tx.ExecContext(ctx, `UPDATE acornfox_assistant_sessions SET event_bytes=event_bytes-$2 WHERE id=$1`, sessionID.String(), removed)
	}
	return err
}

func (s *PostgresStore) FinishRun(ctx context.Context, sessionID, runID domain.ID, status RunStatus, at time.Time) (finished Run, err error) {
	if !terminalRunStatus(status) {
		return Run{}, ErrInvalidInput
	}
	err = s.write(ctx, func(conn *sql.Conn) error {
		tx, e := conn.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		run, e := scanRun(tx.QueryRowContext(ctx, `SELECT r.id,r.session_id,r.idempotency_key,r.request_digest,r.message,r.status,r.created_at,r.updated_at,s.owner_admin_id FROM acornfox_assistant_runs r JOIN acornfox_assistant_sessions s ON s.id=r.session_id WHERE r.id=$1 AND r.session_id=$2 FOR UPDATE OF r`, runID.String(), sessionID.String()))
		if errors.Is(e, sql.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		if terminalRunStatus(run.Status) {
			finished = run
			return nil
		}
		if run.Status != RunRunning {
			return ErrInvalidInput
		}
		_, e = tx.ExecContext(ctx, `UPDATE acornfox_assistant_runs SET status=$2,updated_at=$3 WHERE id=$1`, runID.String(), string(status), at.UTC())
		if e != nil {
			return e
		}
		kind := map[RunStatus]EventType{RunCompleted: EventRunCompleted, RunFailed: EventRunFailed, RunAborted: EventRunAborted, RunUnknown: EventRunUnknown}[status]
		if _, e = appendEventTx(ctx, tx, sessionID, runID, kind, "", at); e != nil {
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
		run.Status, run.UpdatedAt = status, at.UTC()
		finished = run
		return nil
	})
	return
}

func (s *PostgresStore) AbortSessionRuns(ctx context.Context, actor Actor, sessionID domain.ID, at time.Time) (count int, err error) {
	err = s.write(ctx, func(conn *sql.Conn) error {
		tx, e := conn.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		var owner string
		e = tx.QueryRowContext(ctx, `SELECT owner_admin_id FROM acornfox_assistant_sessions WHERE id=$1 FOR UPDATE`, sessionID.String()).Scan(&owner)
		if errors.Is(e, sql.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		if owner != actor.AdminID.String() {
			return ErrNotFound
		}
		rows, e := tx.QueryContext(ctx, `UPDATE acornfox_assistant_runs SET status='aborted',updated_at=$2 WHERE session_id=$1 AND status IN ('accepted','running') RETURNING id`, sessionID.String(), at.UTC())
		if e != nil {
			return e
		}
		ids := []domain.ID{}
		for rows.Next() {
			var id domain.ID
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return e
			}
			ids = append(ids, id)
		}
		if e = rows.Err(); e != nil {
			rows.Close()
			return e
		}
		if e = rows.Close(); e != nil {
			return e
		}
		for _, id := range ids {
			if _, e = appendEventTx(ctx, tx, sessionID, id, EventRunAborted, "", at); e != nil {
				return e
			}
		}
		if e = tx.Commit(); e != nil {
			return e
		}
		count = len(ids)
		return nil
	})
	return
}

func (s *PostgresStore) EventsAfter(ctx context.Context, actor Actor, sessionID domain.ID, after uint64, limit int) (EventSnapshot, error) {
	if limit <= 0 || limit > DefaultEventPageSize {
		limit = DefaultEventPageSize
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return EventSnapshot{}, ErrUnavailable
	}
	defer tx.Rollback()
	var latest, oldest uint64
	var owner string
	err = tx.QueryRowContext(ctx, `SELECT owner_admin_id,next_cursor FROM acornfox_assistant_sessions WHERE id=$1`, sessionID.String()).Scan(&owner, &latest)
	if errors.Is(err, sql.ErrNoRows) {
		return EventSnapshot{}, ErrNotFound
	}
	if err != nil {
		return EventSnapshot{}, ErrUnavailable
	}
	if owner != actor.AdminID.String() {
		return EventSnapshot{}, ErrNotFound
	}
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(min(cursor),$2+1) FROM acornfox_assistant_events WHERE session_id=$1`, sessionID.String(), latest).Scan(&oldest); err != nil {
		return EventSnapshot{}, ErrUnavailable
	}
	if after > latest {
		return EventSnapshot{}, ErrInvalidInput
	}
	if latest > 0 && after+1 < oldest {
		return EventSnapshot{Status: CursorExpired, OldestCursor: oldest, LatestCursor: latest, Events: []Event{}}, ErrCursorExpired
	}
	rows, err := tx.QueryContext(ctx, `SELECT cursor,run_id,event_type,text,occurred_at FROM acornfox_assistant_events WHERE session_id=$1 AND cursor>$2 ORDER BY cursor LIMIT $3`, sessionID.String(), after, limit+1)
	if err != nil {
		return EventSnapshot{}, ErrUnavailable
	}
	events := []Event{}
	for rows.Next() {
		var event Event
		var kind string
		if err = rows.Scan(&event.Cursor, &event.RunID, &kind, &event.Text, &event.OccurredAt); err != nil {
			rows.Close()
			return EventSnapshot{}, ErrUnavailable
		}
		event.Type = EventType(kind)
		events = append(events, event)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return EventSnapshot{}, ErrUnavailable
	}
	if err = rows.Close(); err != nil {
		return EventSnapshot{}, ErrUnavailable
	}
	if err = tx.Commit(); err != nil {
		return EventSnapshot{}, ErrUnavailable
	}
	status := CursorOK
	if len(events) > limit {
		events = events[:limit]
		status = CursorSlowConsumer
	}
	return EventSnapshot{Status: status, OldestCursor: oldest, LatestCursor: latest, Events: events}, nil
}

func (s *PostgresStore) RecoverInterrupted(ctx context.Context, at time.Time) (count int, err error) {
	err = s.write(ctx, func(conn *sql.Conn) error {
		tx, e := conn.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		rows, e := tx.QueryContext(ctx, `UPDATE acornfox_assistant_runs SET status='unknown',updated_at=$1 WHERE status IN ('accepted','running') RETURNING session_id,id`, at.UTC())
		if e != nil {
			return e
		}
		type pair struct{ s, r domain.ID }
		pairs := []pair{}
		for rows.Next() {
			var p pair
			if e = rows.Scan(&p.s, &p.r); e != nil {
				rows.Close()
				return e
			}
			pairs = append(pairs, p)
		}
		if e = rows.Err(); e != nil {
			rows.Close()
			return e
		}
		if e = rows.Close(); e != nil {
			return e
		}
		for _, p := range pairs {
			if _, e = appendEventTx(ctx, tx, p.s, p.r, EventRunUnknown, "", at); e != nil {
				return e
			}
		}
		if e = tx.Commit(); e != nil {
			return e
		}
		count = len(pairs)
		return nil
	})
	return
}

func appendEventTx(ctx context.Context, tx *sql.Tx, sessionID, runID domain.ID, kind EventType, text string, at time.Time) (Event, error) {
	size := len(text) + 128
	if size > MaxEventTextBytes+128 {
		return Event{}, ErrEventLimit
	}
	var cursor uint64
	err := tx.QueryRowContext(ctx, `UPDATE acornfox_assistant_sessions SET next_cursor=next_cursor+1,event_bytes=event_bytes+$2,updated_at=GREATEST(updated_at,$3) WHERE id=$1 RETURNING next_cursor`, sessionID.String(), size, at.UTC()).Scan(&cursor)
	if err != nil {
		return Event{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO acornfox_assistant_events(session_id,cursor,run_id,event_type,text,byte_size,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID.String(), cursor, runID.String(), string(kind), text, size, at.UTC())
	if err != nil {
		return Event{}, err
	}
	for {
		var count, total int
		err = tx.QueryRowContext(ctx, `SELECT count(*),event_bytes FROM acornfox_assistant_events e JOIN acornfox_assistant_sessions s ON s.id=e.session_id WHERE e.session_id=$1 GROUP BY s.event_bytes`, sessionID.String()).Scan(&count, &total)
		if err != nil {
			return Event{}, err
		}
		if count <= defaultMaxEventsPerSession && total <= defaultMaxEventBytesPerSession {
			break
		}
		var removed int
		err = tx.QueryRowContext(ctx, `DELETE FROM acornfox_assistant_events WHERE session_id=$1 AND cursor=(SELECT min(cursor) FROM acornfox_assistant_events WHERE session_id=$1) RETURNING byte_size`, sessionID.String()).Scan(&removed)
		if err != nil {
			return Event{}, err
		}
		_, err = tx.ExecContext(ctx, `UPDATE acornfox_assistant_sessions SET event_bytes=event_bytes-$2 WHERE id=$1`, sessionID.String(), removed)
		if err != nil {
			return Event{}, err
		}
	}
	return Event{Cursor: cursor, RunID: runID, Type: kind, OccurredAt: at.UTC(), Text: text}, nil
}

type rowScanner interface{ Scan(...any) error }

func scanSession(row rowScanner) (Session, error) {
	var s Session
	var owner, kind string
	var app sql.NullString
	err := row.Scan(&s.ID, &owner, &kind, &app, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return Session{}, err
	}
	s.ownerID = domain.ID(owner)
	s.Scope.Kind = ScopeKind(kind)
	if app.Valid {
		s.Scope.AppID = domain.ID(app.String)
	}
	return s, nil
}
func scanRun(row rowScanner) (Run, error) {
	var r Run
	var status, owner string
	err := row.Scan(&r.ID, &r.SessionID, &r.idempotencyKey, &r.requestDigest, &r.message, &status, &r.CreatedAt, &r.UpdatedAt, &owner)
	if err != nil {
		return Run{}, err
	}
	r.Status = RunStatus(status)
	r.ownerID = domain.ID(owner)
	return r, nil
}

var _ Store = (*PostgresStore)(nil)
