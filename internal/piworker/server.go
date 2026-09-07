package piworker

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/pirpc"
)

type relayProcess interface {
	Stdin() io.WriteCloser
	Stdout() io.ReadCloser
	Done() <-chan struct{}
	Close(context.Context) error
}

type processStarter func(context.Context, pirpc.ProcessConfig) (relayProcess, error)
type credentialLoader func(string, string) (string, error)

const maxBusyRejectors = 8

// Server accepts one active control-plane connection and owns exactly one Pi
// child for its lifetime. It stores no database handle and executes no host
// operation or tool callback.
type Server struct {
	config        Config
	credentialDir string
	start         processStarter
	loadKey       credentialLoader
	active        atomic.Bool
	childrenMu    sync.Mutex
	children      int
	handlers      sync.WaitGroup
	connectionsMu sync.Mutex
	connections   map[net.Conn]struct{}
	rejectSlots   chan struct{}
}

func NewServer(config Config, credentialDirectory string) (*Server, error) {
	if config.Validate() != nil || !absoluteCleanPath(credentialDirectory) {
		return nil, ErrInvalidConfig
	}
	return &Server{
		config: config, credentialDir: credentialDirectory,
		start: func(ctx context.Context, config pirpc.ProcessConfig) (relayProcess, error) {
			return pirpc.StartRelay(ctx, config)
		},
		loadKey: loadCredential, connections: make(map[net.Conn]struct{}), rejectSlots: make(chan struct{}, maxBusyRejectors),
	}, nil
}

// ListenAndServe creates the configured Unix socket. The systemd runtime
// directory must already exist; the worker never creates broader host paths.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if _, err := os.Lstat(s.config.SocketPath); err == nil {
		return errors.New("piworker: socket already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("piworker: socket path unavailable")
	}
	address := &net.UnixAddr{Name: s.config.SocketPath, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return errors.New("piworker: listen failed")
	}
	defer func() {
		_ = listener.Close()
		if info, statErr := os.Lstat(s.config.SocketPath); statErr == nil && info.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(s.config.SocketPath)
		}
	}()
	mode, _ := strconv.ParseUint(s.config.SocketMode, 8, 32)
	if err := os.Chmod(s.config.SocketPath, os.FileMode(mode)); err != nil {
		return errors.New("piworker: set socket mode failed")
	}
	return s.Serve(ctx, listener)
}

// Serve is separated from socket creation for deterministic tests.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s == nil || s.config.Validate() != nil || listener == nil {
		return ErrInvalidConfig
	}
	serveContext, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-serveContext.Done()
		_ = listener.Close()
		s.closeConnections()
	}()
	var serveErr error
	for {
		connection, err := listener.Accept()
		if err != nil {
			if serveContext.Err() == nil {
				serveErr = errors.New("piworker: accept failed")
			}
			break
		}
		if serveContext.Err() != nil {
			_ = connection.Close()
			break
		}
		s.trackConnection(connection)
		if serveContext.Err() != nil {
			s.untrackConnection(connection)
			_ = connection.Close()
			break
		}
		if !s.active.CompareAndSwap(false, true) {
			select {
			case s.rejectSlots <- struct{}{}:
				s.handlers.Add(1)
				go func(busyConnection net.Conn) {
					defer s.handlers.Done()
					defer func() { <-s.rejectSlots }()
					defer s.untrackConnection(busyConnection)
					s.rejectBusy(busyConnection)
				}(connection)
			default:
				s.untrackConnection(connection)
				_ = connection.Close()
			}
			continue
		}
		s.handlers.Add(1)
		go func(activeConnection net.Conn) {
			defer s.handlers.Done()
			defer s.untrackConnection(activeConnection)
			defer s.active.Store(false)
			s.handle(serveContext, activeConnection)
		}(connection)
	}
	cancel()
	s.closeConnections()
	s.handlers.Wait()
	return serveErr
}

func (s *Server) rejectBusy(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(s.config.HandshakeTimeout()))
	reader := bufio.NewReaderSize(connection, MaxHandshakeBytes+1)
	if _, err := readFrame(reader, MaxHandshakeBytes); err != nil {
		return
	}
	_ = writeHandshake(connection, handshakeResponse{Protocol: ProtocolVersion, Type: "error", Code: "busy"})
}

func (s *Server) handle(serverContext context.Context, connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(s.config.HandshakeTimeout()))
	reader := bufio.NewReaderSize(connection, MaxHandshakeBytes+1)
	frame, err := readFrame(reader, MaxHandshakeBytes)
	if err != nil {
		_ = writeHandshake(connection, handshakeResponse{Protocol: ProtocolVersion, Type: "error", Code: "invalid_handshake"})
		return
	}
	var request OpenRequest
	if decodeStrict(frame, &request) != nil || request.Validate() != nil {
		_ = writeHandshake(connection, handshakeResponse{Protocol: ProtocolVersion, Type: "error", Code: "invalid_handshake"})
		return
	}
	_ = connection.SetDeadline(time.Time{})

	var sessionFile string
	if s.config.PersistSessions {
		sessionFile, err = bindSession(s.config.SessionRoot, request)
		if err != nil {
			code := "start_failed"
			if errors.Is(err, ErrScopeMismatch) {
				code = "scope_mismatch"
			}
			_ = writeHandshake(connection, handshakeResponse{Protocol: ProtocolVersion, Type: "error", Code: code})
			return
		}
	}
	apiKey, err := s.loadKey(s.credentialDir, s.config.CredentialName)
	if err != nil {
		_ = writeHandshake(connection, handshakeResponse{Protocol: ProtocolVersion, Type: "error", Code: "start_failed"})
		return
	}
	defer zeroString(&apiKey)

	runContext, cancel := context.WithTimeout(serverContext, s.config.RunTimeout())
	defer cancel()
	child, err := s.start(runContext, s.config.processConfig(request, apiKey, sessionFile))
	if err != nil {
		_ = writeHandshake(connection, handshakeResponse{Protocol: ProtocolVersion, Type: "error", Code: "start_failed"})
		return
	}
	s.childrenMu.Lock()
	s.children++
	s.childrenMu.Unlock()
	defer func() {
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), s.config.ShutdownTimeout())
		defer shutdownCancel()
		_ = child.Close(shutdownContext)
		s.childrenMu.Lock()
		s.children--
		s.childrenMu.Unlock()
	}()
	if writeHandshake(connection, handshakeResponse{Protocol: ProtocolVersion, Type: "ready", RunID: request.RunID}) != nil {
		return
	}

	copyDone := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(child.Stdin(), reader)
		copyDone <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(connection, child.Stdout())
		copyDone <- struct{}{}
	}()
	select {
	case <-copyDone:
	case <-child.Done():
	case <-runContext.Done():
	}
	cancel()
	_ = connection.Close()
}

func loadCredential(directory, name string) (string, error) {
	if !absoluteCleanPath(directory) || name != CredentialName || strings.ContainsAny(name, `/\\\x00`) {
		return "", ErrStartFailed
	}
	path := filepath.Join(directory, name)
	if filepath.Dir(path) != directory {
		return "", ErrStartFailed
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", ErrStartFailed
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 || info.Size() <= 0 || info.Size() > 16<<10 {
		return "", ErrStartFailed
	}
	raw, err := io.ReadAll(io.LimitReader(file, (16<<10)+1))
	if err != nil || len(raw) > 16<<10 {
		return "", ErrStartFailed
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if value == "" || len(value) > 16<<10 || strings.ContainsAny(value, "\r\n\x00") {
		return "", ErrStartFailed
	}
	return value, nil
}

func zeroString(value *string) {
	if value != nil {
		*value = ""
	}
}

func (s *Server) activeChildren() int {
	s.childrenMu.Lock()
	defer s.childrenMu.Unlock()
	return s.children
}

func (s *Server) trackConnection(connection net.Conn) {
	s.connectionsMu.Lock()
	s.connections[connection] = struct{}{}
	s.connectionsMu.Unlock()
}

func (s *Server) untrackConnection(connection net.Conn) {
	s.connectionsMu.Lock()
	delete(s.connections, connection)
	s.connectionsMu.Unlock()
}

func (s *Server) closeConnections() {
	s.connectionsMu.Lock()
	for connection := range s.connections {
		_ = connection.Close()
	}
	s.connectionsMu.Unlock()
}
