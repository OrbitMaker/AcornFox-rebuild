package main

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/assistant"
	"github.com/open-card/open-card/internal/assistantactions"
	"github.com/open-card/open-card/internal/assistanttools"
)

// The optional assistant is composed only from operator-controlled paths and
// the existing database. The browser receives no worker bearer or credential.
func (s *Server) configureAcornFoxAssistant(ctx context.Context, db *sql.DB, workerSocket, toolSocket string) (func(), error) {
	if db == nil || !assistantRuntimePath(workerSocket) || !assistantRuntimePath(toolSocket) {
		return nil, errors.New("assistant configuration unavailable")
	}
	store, err := assistant.NewPostgresStore(ctx, db)
	if err != nil {
		return nil, errors.New("assistant persistence unavailable")
	}
	registry := assistanttools.NewRegistry()
	runner, err := assistant.NewPiRunner(assistant.PiRunnerConfig{SocketPath: workerSocket, Grant: func(run assistant.RunnerRun, expires time.Time) (string, func(), error) {
		token, grantErr := registry.Grant(assistanttools.GrantInput{Actor: run.Actor.AdminID.String(), SessionID: run.SessionID.String(), RunID: run.RunID.String(), Scope: assistanttools.Scope{Admin: run.Scope.Kind == assistant.ScopeHost, ApplicationID: run.Scope.AppID.String()}, ExpiresAt: expires})
		return token, func() { registry.Revoke(token) }, grantErr
	}})
	if err != nil {
		_ = store.Close()
		return nil, errors.New("assistant runner unavailable")
	}
	service, err := assistant.NewService(assistant.Config{Store: store, Runner: runner})
	if err != nil {
		_ = store.Close()
		return nil, errors.New("assistant service unavailable")
	}
	if _, err = service.Recover(ctx); err != nil {
		service.Close()
		_ = store.Close()
		return nil, errors.New("assistant recovery unavailable")
	}
	if _, err = os.Lstat(toolSocket); !errors.Is(err, os.ErrNotExist) {
		service.Close()
		_ = store.Close()
		return nil, errors.New("assistant tool socket unavailable")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: toolSocket, Net: "unix"})
	if err != nil {
		service.Close()
		_ = store.Close()
		return nil, errors.New("assistant tool socket unavailable")
	}
	listener.SetUnlinkOnClose(false)
	socketInfo, statErr := os.Lstat(toolSocket)
	if statErr != nil || os.Chmod(toolSocket, 0660) != nil {
		listener.Close()
		service.Close()
		store.Close()
		return nil, errors.New("assistant tool socket unavailable")
	}
	toolServer := &http.Server{Handler: &assistanttools.Handler{Registry: registry, Execute: newAcornFoxAssistantToolExecutor(s, s.acornFoxHostMetrics)}, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 4096}
	var operationReader acornFoxOperationReader
	if s.acornFoxOperation != nil {
		operationReader = s.acornFoxOperation.Store
	}
	actionStore := assistantactions.NewPostgresStore(db)
	actionService, actionErr := assistantactions.NewService(assistantactions.Config{Store: actionStore, Resolver: actionStore, Executor: acornFoxAssistantActionExecutor{Command: s.acornFoxDeliveryCommand}, Verifier: acornFoxAssistantActionVerifier{Reader: operationReader}})
	if actionErr != nil {
		listener.Close()
		service.Close()
		store.Close()
		return nil, errors.New("assistant action configuration unavailable")
	}
	s.acornFoxAssistantActions = &AcornFoxAssistantActionsHTTPHandler{Service: actionService}
	s.acornFoxAssistant = &assistant.Handler{Service: service}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = toolServer.Close()
			_ = listener.Close()
			service.Close()
			_ = store.Close()
			if current, statErr := os.Lstat(toolSocket); statErr == nil && os.SameFile(socketInfo, current) {
				_ = os.Remove(toolSocket)
			}
		})
	}
	go func() {
		if serveErr := toolServer.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			stop()
		}
	}()
	go func() {
		select {
		case <-ctx.Done():
		case <-store.Done():
		}
		stop()
	}()
	return stop, nil
}

func assistantRuntimePath(path string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	directory := filepath.Dir(path)
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil || canonical != directory {
		return false
	}
	info, err := os.Lstat(directory)
	return err == nil && info.IsDir() && info.Mode().Perm()&0002 == 0
}
