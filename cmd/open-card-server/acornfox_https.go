package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
	"github.com/open-card/open-card/internal/providers/acornfoxroute"
)

type acornFoxTLSAllowHandler struct {
	root  string
	allow func(context.Context, string) (bool, error)
}

func (h *acornFoxTLSAllowHandler) Handle(w http.ResponseWriter, r *http.Request) {
	deny := func() { w.WriteHeader(http.StatusForbidden) }
	if h == nil || h.allow == nil || r.Method != http.MethodGet || !tlsAllowLoopback(r.RemoteAddr) || len(r.URL.RawQuery) > 1024 {
		deny()
		return
	}
	query, err := urlQuery(r)
	if err != nil || len(query) != 1 || len(query["domain"]) != 1 {
		deny()
		return
	}
	host := query["domain"][0]
	if host == "" || host != strings.ToLower(host) || strings.ContainsAny(host, "/:* \\%\r\n") || !strings.HasSuffix(host, ".apps."+h.root) {
		deny()
		return
	}
	label := strings.TrimSuffix(host, ".apps."+h.root)
	if !strings.HasPrefix(label, "delivery-") || len(label) != len("delivery-")+20 || strings.Trim(strings.TrimPrefix(label, "delivery-"), "0123456789abcdef") != "" {
		deny()
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	allowed, err := h.allow(ctx, host)
	if err != nil || !allowed {
		deny()
		return
	}
	w.WriteHeader(http.StatusOK)
}
func urlQuery(r *http.Request) (map[string][]string, error) { return url.ParseQuery(r.URL.RawQuery) }

func (s *Server) handleAcornFoxHTTPSBoundary(w http.ResponseWriter, r *http.Request) bool {
	if s.legacyRoutesEnabled {
		return false
	}
	// Authentication establishes trusted actor state later. Never allow a
	// public caller or intermediary to supply historical internal authority.
	for name := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-open-card-") {
			delete(r.Header, name)
		}
	}
	if r.URL.Path != acornfoxroute.PermissionPath {
		return false
	}
	s.acornFoxTLSAllow.Handle(w, r)
	return true
}

func cleanPublicAccessEnabled(clean, m1, m3 bool, origin, root string) (bool, error) {
	if !clean || root == "" {
		return false, nil
	}
	expected, err := acornfoxroute.AuthorizedRoot(origin)
	if err != nil || root != expected || !m1 || m3 {
		return false, errors.New("clean public access configuration conflicts")
	}
	return true, nil
}

type cleanPublicRouteSource struct {
	store *postgres.Store
	root  string
}

func (s cleanPublicRouteSource) WithRoutes(ctx context.Context, apply func([]acornfoxroute.RouteState, func() error) error) error {
	tx, err := s.store.DB().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Share the existing route-writer lock key: an active legacy convergence
	// writer or another clean process must cause refusal, never a second cache.
	var held bool
	if err = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, "open-card:m3-domain-convergence:v1").Scan(&held); err != nil {
		return err
	}
	if !held {
		return application.ErrAcornFoxPublicAccessConflict
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT application_id,deployment_id FROM acornfox_public_access_commands WHERE route_id IS NOT NULL ORDER BY application_id,deployment_id LIMIT 1025`)
	if err != nil {
		return err
	}
	var ids [][2]domain.ID
	for rows.Next() {
		var pair [2]domain.ID
		if err = rows.Scan(&pair[0], &pair[1]); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, pair)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	if len(ids) > 1024 {
		return application.ErrAcornFoxPublicAccessUnavailable
	}
	states := make([]acornfoxroute.RouteState, 0, len(ids))
	for _, pair := range ids {
		intent, found, e := s.store.GetAcornFoxPublicRouteIntent(ctx, pair[0], pair[1])
		if e != nil {
			return e
		}
		if !found {
			return application.ErrAcornFoxPublicAccessOwnershipConflict
		}
		fact, found, e := s.store.GetAcornFoxPublicAccess(ctx, pair[0], pair[1])
		if e != nil {
			return e
		}
		if !found || fact.Validate() != nil || fact.Hostname != intent.Hostname || acornfoxroute.ValidateIntent(s.root, intent) != nil {
			return application.ErrAcornFoxPublicAccessOwnershipConflict
		}
		states = append(states, acornfoxroute.RouteState{Intent: intent, Enabled: fact.DesiredPublic})
	}
	checkLock := func() error { var alive int; return tx.QueryRowContext(ctx, "SELECT 1").Scan(&alive) }
	if err = apply(states, checkLock); err != nil {
		return err
	}
	return tx.Commit()
}
func (s cleanPublicRouteSource) allow(ctx context.Context, hostname string) (bool, error) {
	var app, dep domain.ID
	err := s.store.DB().QueryRowContext(ctx, `SELECT application_id,deployment_id FROM m3_desired_routes WHERE hostname=$1 AND desired_state='active' AND verified=true AND serving=false`, hostname).Scan(&app, &dep)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	fact, found, err := s.store.GetAcornFoxPublicAccess(ctx, app, dep)
	if err != nil || !found || !fact.DesiredPublic || fact.Validate() != nil {
		return false, err
	}
	intent, found, err := s.store.GetAcornFoxPublicRouteIntent(ctx, app, dep)
	if err != nil || !found || intent.Hostname != hostname || fact.Hostname != hostname || acornfoxroute.ValidateIntent(s.root, intent) != nil {
		return false, err
	}
	return true, nil
}

func (s *Server) configureCleanPublicAccess(ctx context.Context, store *postgres.Store, origin, root string, m1, m3 bool) (func(), error) {
	enabled, err := cleanPublicAccessEnabled(!s.legacyRoutesEnabled, m1, m3, origin, root)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return func() {}, nil
	}
	if store == nil {
		return nil, application.ErrAcornFoxPublicAccessUnavailable
	}
	source := cleanPublicRouteSource{store: store, root: root}
	checkCtx, checkCancel := context.WithTimeout(ctx, 5*time.Second)
	checkErr := source.WithRoutes(checkCtx, func(_ []acornfoxroute.RouteState, checkLock func() error) error { return checkLock() })
	checkCancel()
	if checkErr != nil {
		return nil, checkErr
	}
	router, err := acornfoxroute.New(acornfoxroute.Config{AuthorizedRoot: root, Source: source})
	if err != nil {
		return nil, err
	}
	s.SetAcornFoxPublicAccess(&AcornFoxPublicAccessHTTPHandler{Service: &application.AcornFoxPublicAccessService{Store: store, Router: router, Config: application.AcornFoxPublicAccessConfig{AuthorizedRoot: root}}})
	s.acornFoxTLSAllow = &acornFoxTLSAllowHandler{root: root, allow: source.allow}
	runCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		reconcile := func() {
			bounded, done := context.WithTimeout(runCtx, 10*time.Second)
			defer done()
			if router.Reconcile(bounded) != nil {
				return
			}
			// Recover provider outcomes separately from configured routes; completed
			// records are rebuilt too, including after an Edge-only restart.
			_ = reconcileAcornFoxPublicAccess(bounded, store, root, router, 10)
		}
		reconcile()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				reconcile()
			}
		}
	}()
	return func() { cancel(); workers.Wait(); router.Close() }, nil
}

var _ application.AcornFoxPublicAccessRouter = (*acornfoxroute.Provider)(nil)
