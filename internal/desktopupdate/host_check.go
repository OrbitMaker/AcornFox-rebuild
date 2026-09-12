package desktopupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const defaultCheckTimeout = 30 * time.Second

// fetchIndex retrieves the raw signed index envelope from the policy IndexURL
// with strict HTTPS, allowed-host redirect validation, bounded timeout,
// no inherited cookies or auth, and a strict MaxIndexEnvelopeBytes limit.
// All network and protocol errors are returned redacted (no URLs or secrets).
func (c *HostController) fetchIndex(ctx context.Context) ([]byte, error) {
	if c.options.Policy == nil {
		return nil, ErrHostNotConfigured
	}
	p := c.options.Policy
	if err := validateArtifactURL(p.IndexURL, p.AllowedHosts); err != nil {
		return nil, ErrURLNotAllowed
	}

	timeout := c.options.DownloadTimeout
	if timeout <= 0 {
		timeout = defaultCheckTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var transport http.RoundTripper
	if c.options.HTTPClient != nil && c.options.HTTPClient.Transport != nil {
		transport = c.options.HTTPClient.Transport
	} else {
		transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			DisableCompression:    true,
		}
	}

	client := http.Client{
		Transport: transport,
		Jar:       nil,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= MaxRedirects {
				return fmt.Errorf("%w: too many redirects", ErrURLNotAllowed)
			}
			if err := validateRedirectURL(req.URL, p.AllowedHosts); err != nil {
				return err
			}
			req.Header.Del("Cookie")
			req.Header.Del("Authorization")
			return nil
		},
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, p.IndexURL, nil)
	if err != nil {
		return nil, ErrDownloadFailed
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Del("Cookie")
	req.Header.Del("Authorization")

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(reqCtx.Err(), context.Canceled) {
			return nil, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		if errors.Is(err, ErrURLNotAllowed) {
			return nil, ErrURLNotAllowed
		}
		return nil, ErrDownloadFailed
	}

	var closed bool
	defer func() {
		if !closed {
			_ = resp.Body.Close()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		closed = true
		_ = resp.Body.Close()
		return nil, ErrDownloadFailed
	}

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(MaxIndexEnvelopeBytes)+1))
	closed = true
	closeErr := resp.Body.Close()

	if readErr != nil {
		if errors.Is(readErr, context.Canceled) || errors.Is(reqCtx.Err(), context.Canceled) {
			return nil, context.Canceled
		}
		if errors.Is(readErr, context.DeadlineExceeded) || errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, ErrDownloadFailed
	}
	if closeErr != nil {
		if errors.Is(closeErr, context.Canceled) || errors.Is(reqCtx.Err(), context.Canceled) {
			return nil, context.Canceled
		}
		if errors.Is(closeErr, context.DeadlineExceeded) || errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
	}
	// Check internal request context error (catches both internal deadline expiration
	// and parent cancellation before the envelope is accepted).
	if err := reqCtx.Err(); err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > MaxIndexEnvelopeBytes {
		return nil, ErrInvalidEnvelope
	}
	return raw, nil
}

// CheckAndSelect executes a trusted update check against the frozen policy IndexURL
// and durably binds exactly one selected pending offer, without downloading artifacts,
// preparing slots, mutating the guest backend, or starting a VM/GUI.
//
// If no policy is configured, it returns not-configured without network access.
// Missing or corrupt state fails closed without creating or repairing state.
// If a pending offer or cleanup work is present, it returns ErrHostPending without
// executing cleanup, backend hooks, or runtime probes.
func (c *HostController) CheckAndSelect(ctx context.Context) (HostUpdateStatus, error) {
	if c.options.Policy == nil {
		return HostUpdateStatus{State: "not-configured"}, nil
	}
	if ctx == nil {
		return HostUpdateStatus{}, ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return HostUpdateStatus{}, err
	}

	s, state, err := c.openExistingDriver(ctx)
	if err != nil {
		return HostUpdateStatus{}, err
	}
	defer s.close()

	if state.Pending != nil || len(state.Cleanup) > 0 || state.CollectSlots {
		return hostStatus(state), ErrHostPending
	}

	envelope, err := c.fetchIndex(ctx)
	if err != nil {
		return hostStatus(state), err
	}

	// Ensure cancellation right before the durable state mutation boundary
	// rejects the offer without modifying catalog floor or pending state.
	if err := ctx.Err(); err != nil {
		return hostStatus(state), err
	}

	return c.selectOffer(s, &state, envelope, false)
}
