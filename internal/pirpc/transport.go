package pirpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

type pendingRequest struct {
	command string
	result  chan requestResult
}

type requestResult struct {
	response wireResponse
	err      error
}

type outboundFrame struct {
	data []byte
	ack  chan error
}

type subscriber struct {
	events chan Event
	done   chan error
}

// Transport owns JSONL framing, serialized writes, response correlation and
// event fan-out. Callers normally use Client for the command allowlist.
type Transport struct {
	reader io.Reader
	writer io.Writer
	close  func() error
	opts   Options

	outbound chan outboundFrame
	done     chan struct{}
	stopOnce sync.Once
	errMu    sync.Mutex
	err      error

	requestSeq atomic.Uint64
	mu         sync.Mutex
	pending    map[string]pendingRequest
	uiPending  map[string]UIMethod
	subs       map[uint64]*subscriber
	subSeq     uint64
}

// NewTransport adapts a single duplex stream such as a Unix socket.
func NewTransport(rw io.ReadWriteCloser, opts Options) *Transport {
	return newTransport(rw, rw, rw.Close, opts)
}

// NewPipeTransport adapts separately owned stdout/stdin pipes. Close closes
// both pipes and propagates shutdown to outstanding requests.
func NewPipeTransport(stdout io.ReadCloser, stdin io.WriteCloser, opts Options) *Transport {
	var once sync.Once
	closeBoth := func() error {
		var joined error
		once.Do(func() {
			joined = errors.Join(stdin.Close(), stdout.Close())
		})
		return joined
	}
	return newTransport(stdout, stdin, closeBoth, opts)
}

func newTransport(reader io.Reader, writer io.Writer, closeFn func() error, opts Options) *Transport {
	opts = opts.normalized()
	t := &Transport{
		reader:    reader,
		writer:    writer,
		close:     closeFn,
		opts:      opts,
		outbound:  make(chan outboundFrame, opts.MaxPending+opts.MaxUIRequests),
		done:      make(chan struct{}),
		pending:   make(map[string]pendingRequest),
		uiPending: make(map[string]UIMethod),
		subs:      make(map[uint64]*subscriber),
	}
	go t.writeLoop()
	go t.readLoop()
	return t
}

// Options returns the effective, normalized limits.
func (t *Transport) Options() Options { return t.opts }

// Done closes when EOF, a protocol error, an I/O failure or Close stops the
// transport.
func (t *Transport) Done() <-chan struct{} { return t.done }

// Err reports a stable, content-free terminal error.
func (t *Transport) Err() error {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return t.err
}

// Close terminates the transport and wakes all outstanding callers.
func (t *Transport) Close() error {
	closeErr := t.close()
	t.stop(ErrClosed)
	return closeErr
}

// Subscribe creates an independent bounded event queue.
func (t *Transport) Subscribe() *Subscription {
	s := &subscriber{events: make(chan Event, t.opts.EventQueue), done: make(chan error, 1)}
	t.mu.Lock()
	if t.isDoneLocked() {
		err := t.Err()
		if err == nil {
			err = ErrClosed
		}
		s.done <- err
		close(s.done)
		close(s.events)
		t.mu.Unlock()
		return &Subscription{Events: s.events, Done: s.done}
	}
	t.subSeq++
	id := t.subSeq
	t.subs[id] = s
	t.mu.Unlock()
	return &Subscription{
		Events: s.events,
		Done:   s.done,
		cancel: func() { t.removeSubscriber(id, ErrClosed) },
	}
}

func (t *Transport) request(ctx context.Context, command string, fields map[string]any) (wireResponse, error) {
	id := fmt.Sprintf("acornfox-%d", t.requestSeq.Add(1))
	commandObject := make(map[string]any, len(fields)+2)
	commandObject["id"] = id
	commandObject["type"] = command
	for key, value := range fields {
		if key == "id" || key == "type" {
			return wireResponse{}, fmt.Errorf("%w: reserved command field", ErrProtocol)
		}
		commandObject[key] = value
	}
	data, err := json.Marshal(commandObject)
	if err != nil {
		return wireResponse{}, fmt.Errorf("pirpc: encode %s command: %w", command, err)
	}
	if len(data)+1 > t.opts.MaxFrameBytes {
		return wireResponse{}, ErrFrameTooLarge
	}
	data = append(data, '\n')

	pending := pendingRequest{command: command, result: make(chan requestResult, 1)}
	t.mu.Lock()
	if t.isDoneLocked() {
		t.mu.Unlock()
		return wireResponse{}, t.terminalError()
	}
	if len(t.pending) >= t.opts.MaxPending {
		t.mu.Unlock()
		return wireResponse{}, ErrTooManyRequests
	}
	t.pending[id] = pending
	t.mu.Unlock()

	frame := outboundFrame{data: data, ack: make(chan error, 1)}
	select {
	case t.outbound <- frame:
	case <-ctx.Done():
		t.removePending(id)
		return wireResponse{}, ctx.Err()
	case <-t.done:
		t.removePending(id)
		return wireResponse{}, t.terminalError()
	}

	select {
	case err := <-frame.ack:
		if err != nil {
			t.removePending(id)
			return wireResponse{}, err
		}
	case <-ctx.Done():
		// The request may already be on the wire. Keep its bounded pending slot
		// until a response or shutdown arrives so a late response is not treated
		// as a forged/unknown id.
		return wireResponse{}, ctx.Err()
	case <-t.done:
		return wireResponse{}, t.terminalError()
	}

	select {
	case result := <-pending.result:
		return result.response, result.err
	case <-ctx.Done():
		return wireResponse{}, ctx.Err()
	case <-t.done:
		return wireResponse{}, t.terminalError()
	}
}

func (t *Transport) sendOneWay(ctx context.Context, object any) error {
	data, err := json.Marshal(object)
	if err != nil {
		return fmt.Errorf("pirpc: encode one-way command: %w", err)
	}
	if len(data)+1 > t.opts.MaxFrameBytes {
		return ErrFrameTooLarge
	}
	frame := outboundFrame{data: append(data, '\n'), ack: make(chan error, 1)}
	select {
	case t.outbound <- frame:
	case <-ctx.Done():
		return ctx.Err()
	case <-t.done:
		return t.terminalError()
	}
	select {
	case err := <-frame.ack:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-t.done:
		return t.terminalError()
	}
}

func (t *Transport) writeLoop() {
	for {
		select {
		case frame := <-t.outbound:
			err := writeAll(t.writer, frame.data)
			frame.ack <- err
			if err != nil {
				t.stop(fmt.Errorf("pirpc: write failed: %w", ErrClosed))
				return
			}
		case <-t.done:
			return
		}
	}
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		data = data[n:]
	}
	return nil
}

func (t *Transport) readLoop() {
	reader := bufio.NewReaderSize(t.reader, min(t.opts.MaxFrameBytes+1, 64<<10))
	for {
		frame, err := readLFFrame(reader, t.opts.MaxFrameBytes)
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				t.stop(io.EOF)
			case errors.Is(err, ErrFrameTooLarge):
				t.stop(ErrFrameTooLarge)
			default:
				t.stop(fmt.Errorf("%w: invalid JSONL framing", ErrProtocol))
			}
			return
		}
		if err := t.dispatch(frame); err != nil {
			t.stop(err)
			return
		}
	}
}

func readLFFrame(reader *bufio.Reader, maxBytes int) ([]byte, error) {
	var frame bytes.Buffer
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > 0 {
			if frame.Len()+len(fragment) > maxBytes {
				return nil, ErrFrameTooLarge
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
				return nil, fmt.Errorf("%w: empty frame", ErrProtocol)
			}
			return append([]byte(nil), data...), nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			if errors.Is(err, io.EOF) && frame.Len() == 0 {
				return nil, io.EOF
			}
			return nil, io.ErrUnexpectedEOF
		}
	}
}

type envelope struct {
	Type string `json:"type"`
}

type wireResponse struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Command string          `json:"command"`
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   string          `json:"error"`
}

func (t *Transport) dispatch(frame []byte) error {
	var header envelope
	if err := json.Unmarshal(frame, &header); err != nil || header.Type == "" {
		return fmt.Errorf("%w: malformed event envelope", ErrProtocol)
	}
	if header.Type == "response" {
		return t.dispatchResponse(frame)
	}
	event, uiDialog, err := normalizeEvent(frame, header.Type, t.opts.MaxTextBytes)
	if err != nil {
		return err
	}
	if uiDialog != nil && uiDialog.requiresResponse() {
		t.mu.Lock()
		if len(t.uiPending) >= t.opts.MaxUIRequests {
			t.mu.Unlock()
			return fmt.Errorf("%w: too many extension UI requests", ErrProtocol)
		}
		if _, exists := t.uiPending[uiDialog.ID]; exists {
			t.mu.Unlock()
			return fmt.Errorf("%w: duplicate extension UI id", ErrProtocol)
		}
		t.uiPending[uiDialog.ID] = uiDialog.Method
		t.mu.Unlock()
	}
	t.publish(event)
	return nil
}

func (t *Transport) dispatchResponse(frame []byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(frame, &object); err != nil || allowFields(object, "id", "type", "command", "success", "data", "error") != nil {
		return fmt.Errorf("%w: malformed response", ErrProtocol)
	}
	var response wireResponse
	if err := json.Unmarshal(frame, &response); err != nil || response.ID == "" || response.Command == "" {
		return fmt.Errorf("%w: malformed response", ErrProtocol)
	}
	if response.Type != "response" {
		return fmt.Errorf("%w: malformed response", ErrProtocol)
	}
	if _, ok := object["success"]; !ok {
		return fmt.Errorf("%w: malformed response", ErrProtocol)
	}
	t.mu.Lock()
	pending, ok := t.pending[response.ID]
	if ok {
		delete(t.pending, response.ID)
	}
	t.mu.Unlock()
	if !ok || pending.command != response.Command {
		return fmt.Errorf("%w: uncorrelated response", ErrProtocol)
	}
	if !response.Success {
		pending.result <- requestResult{err: &CommandError{Command: response.Command}}
		return nil
	}
	pending.result <- requestResult{response: response}
	return nil
}

// CommandError deliberately excludes Pi's raw error string because provider
// errors may contain prompt or credential-adjacent material.
type CommandError struct{ Command string }

func (e *CommandError) Error() string { return "pirpc: " + e.Command + " command rejected" }

func (t *Transport) publish(event Event) {
	t.mu.Lock()
	for id, sub := range t.subs {
		select {
		case sub.events <- event:
		default:
			delete(t.subs, id)
			sub.done <- ErrSubscriberSlow
			close(sub.done)
			close(sub.events)
		}
	}
	t.mu.Unlock()
}

func (t *Transport) removeSubscriber(id uint64, reason error) {
	t.mu.Lock()
	if sub, ok := t.subs[id]; ok {
		delete(t.subs, id)
		sub.done <- reason
		close(sub.done)
		close(sub.events)
	}
	t.mu.Unlock()
}

func (t *Transport) removePending(id string) {
	t.mu.Lock()
	delete(t.pending, id)
	t.mu.Unlock()
}

func (t *Transport) stop(err error) {
	t.stopOnce.Do(func() {
		if err == nil {
			err = ErrClosed
		}
		t.errMu.Lock()
		t.err = err
		t.errMu.Unlock()
		close(t.done)
		_ = t.close()

		t.mu.Lock()
		for id, pending := range t.pending {
			delete(t.pending, id)
			pending.result <- requestResult{err: err}
		}
		for id, sub := range t.subs {
			delete(t.subs, id)
			sub.done <- err
			close(sub.done)
			close(sub.events)
		}
		clear(t.uiPending)
		t.mu.Unlock()
	})
}

func (t *Transport) terminalError() error {
	err := t.Err()
	if err == nil {
		return ErrClosed
	}
	return err
}

func (t *Transport) isDoneLocked() bool {
	select {
	case <-t.done:
		return true
	default:
		return false
	}
}
