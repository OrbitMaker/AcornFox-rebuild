package piworker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"time"
)

var (
	idPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)
)

type Scope struct {
	Kind          string `json:"kind"`
	ApplicationID string `json:"application_id,omitempty"`
}

func (s Scope) Validate() error {
	switch s.Kind {
	case "host":
		if s.ApplicationID != "" {
			return ErrInvalidHandshake
		}
	case "app":
		if !idPattern.MatchString(s.ApplicationID) {
			return ErrInvalidHandshake
		}
	default:
		return ErrInvalidHandshake
	}
	return nil
}

type OpenRequest struct {
	Protocol  string `json:"protocol"`
	Type      string `json:"type"`
	RunToken  string `json:"run_token"`
	RunID     string `json:"run_id"`
	SessionID string `json:"session_id"`
	Scope     Scope  `json:"scope"`
}

func (r OpenRequest) Validate() error {
	if r.Protocol != ProtocolVersion || r.Type != "open" || !tokenPattern.MatchString(r.RunToken) || !idPattern.MatchString(r.RunID) || !idPattern.MatchString(r.SessionID) {
		return ErrInvalidHandshake
	}
	return r.Scope.Validate()
}

type Ready struct {
	Protocol string `json:"protocol"`
	Type     string `json:"type"`
	RunID    string `json:"run_id"`
}

type handshakeResponse struct {
	Protocol string `json:"protocol"`
	Type     string `json:"type"`
	RunID    string `json:"run_id,omitempty"`
	Code     string `json:"code,omitempty"`
}

// OpenError exposes only a stable code, never a subprocess/config/credential
// error or path.
type OpenError struct{ Code string }

func (e *OpenError) Error() string { return "piworker: open failed: " + e.Code }

// Dial performs the worker handshake and returns a buffered net.Conn suitable
// for pirpc.NewTransport. The wrapper preserves any bytes coalesced after the
// ready frame.
func Dial(ctx context.Context, socketPath string, request OpenRequest, timeout time.Duration) (net.Conn, Ready, error) {
	if !absoluteCleanPath(socketPath) || request.Validate() != nil || timeout <= 0 {
		return nil, Ready{}, ErrInvalidHandshake
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, Ready{}, errors.New("piworker: dial failed")
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	frame, err := json.Marshal(request)
	if err != nil || len(frame)+1 > MaxHandshakeBytes || writeFull(connection, append(frame, '\n')) != nil {
		_ = connection.Close()
		return nil, Ready{}, ErrInvalidHandshake
	}
	reader := bufio.NewReaderSize(connection, MaxHandshakeBytes+1)
	responseFrame, err := readFrame(reader, MaxHandshakeBytes)
	if err != nil {
		_ = connection.Close()
		return nil, Ready{}, errors.New("piworker: handshake failed")
	}
	var response handshakeResponse
	if decodeStrict(responseFrame, &response) != nil || response.Protocol != ProtocolVersion {
		_ = connection.Close()
		return nil, Ready{}, errors.New("piworker: handshake failed")
	}
	if response.Type == "error" {
		_ = connection.Close()
		if !validOpenErrorCode(response.Code) {
			return nil, Ready{}, errors.New("piworker: handshake failed")
		}
		return nil, Ready{}, &OpenError{Code: response.Code}
	}
	if response.Type != "ready" || response.RunID != request.RunID {
		_ = connection.Close()
		return nil, Ready{}, errors.New("piworker: handshake failed")
	}
	_ = connection.SetDeadline(time.Time{})
	return &bufferedConn{Conn: connection, reader: reader}, Ready{Protocol: response.Protocol, Type: response.Type, RunID: response.RunID}, nil
}

func validOpenErrorCode(code string) bool {
	switch code {
	case "busy", "invalid_handshake", "scope_mismatch", "start_failed":
		return true
	default:
		return false
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(target []byte) (int, error) { return c.reader.Read(target) }

func readFrame(reader *bufio.Reader, max int) ([]byte, error) {
	var frame bytes.Buffer
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > 0 {
			if frame.Len()+len(fragment) > max {
				return nil, ErrInvalidHandshake
			}
			_, _ = frame.Write(fragment)
		}
		if err == nil {
			data := frame.Bytes()
			data = data[:len(data)-1]
			if len(data) > 0 && data[len(data)-1] == '\r' {
				data = data[:len(data)-1]
			}
			if len(data) == 0 {
				return nil, ErrInvalidHandshake
			}
			return append([]byte(nil), data...), nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, ErrInvalidHandshake
		}
	}
}

func decodeStrict(frame []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidHandshake
	}
	return nil
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrNoProgress
		}
		data = data[count:]
	}
	return nil
}

func writeHandshake(writer io.Writer, response handshakeResponse) error {
	frame, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("piworker: encode handshake: %w", err)
	}
	return writeFull(writer, append(frame, '\n'))
}
