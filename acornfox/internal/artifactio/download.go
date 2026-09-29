package artifactio

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultDownloadTimeout = 10 * time.Minute
	DefaultMaxRedirects    = 10
)

var (
	ErrDownloadFailed = errors.New("artifactio: download failed")
	ErrDigestMismatch = errors.New("artifactio: artifact sha256 mismatch")
	ErrSizeMismatch   = errors.New("artifactio: artifact size mismatch")
	ErrURLNotAllowed  = errors.New("artifactio: url not allowed")
)

type DownloadOptions struct {
	URL            string
	AllowedHosts   []string
	Out            io.Writer
	ExpectedSize   int64
	ExpectedSHA256 string
	Timeout        time.Duration
	Transport      http.RoundTripper
	MaxRedirects   int
}

func ValidateRedirectURL(u *url.URL, allowedHosts []string) error {
	if u.Scheme != "https" {
		return fmt.Errorf("%w: redirect scheme must be https", ErrURLNotAllowed)
	}
	if u.User != nil {
		return fmt.Errorf("%w: redirect userinfo not permitted", ErrURLNotAllowed)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%w: redirect fragment not permitted", ErrURLNotAllowed)
	}
	port := u.Port()
	if port != "" && port != "443" {
		return fmt.Errorf("%w: redirect non-standard port %q", ErrURLNotAllowed, port)
	}
	hostname := strings.ToLower(u.Hostname())
	matched := false
	for _, host := range allowedHosts {
		if hostname == strings.ToLower(host) {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("%w: redirect host not in allowed hosts", ErrURLNotAllowed)
	}
	return nil
}

func DownloadArtifactStream(ctx context.Context, opts DownloadOptions) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrDownloadFailed)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.Out == nil {
		return fmt.Errorf("%w: nil output writer", ErrDownloadFailed)
	}
	if opts.ExpectedSize <= 0 {
		return fmt.Errorf("%w: invalid expected size %d", ErrSizeMismatch, opts.ExpectedSize)
	}
	if len(opts.ExpectedSHA256) != 64 {
		return fmt.Errorf("%w: invalid expected sha256 %q", ErrDigestMismatch, opts.ExpectedSHA256)
	}

	initialParsed, err := url.Parse(opts.URL)
	if err != nil {
		return fmt.Errorf("%w: parse url failed", ErrURLNotAllowed)
	}
	if err := ValidateRedirectURL(initialParsed, opts.AllowedHosts); err != nil {
		return err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultDownloadTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	transport := opts.Transport
	if transport == nil {
		transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			DisableCompression:    true,
		}
	}

	maxRedirects := opts.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = DefaultMaxRedirects
	}

	client := http.Client{
		Transport: transport,
		Jar:       nil,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("%w: too many redirects", ErrURLNotAllowed)
			}
			if err := ValidateRedirectURL(req.URL, opts.AllowedHosts); err != nil {
				return err
			}
			req.Header.Del("Cookie")
			req.Header.Del("Authorization")
			return nil
		},
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, opts.URL, nil)
	if err != nil {
		return fmt.Errorf("%w: failed to create request", ErrDownloadFailed)
	}

	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Del("Cookie")
	req.Header.Del("Authorization")

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(reqCtx.Err(), context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		if errors.Is(err, ErrURLNotAllowed) {
			return ErrURLNotAllowed
		}
		return fmt.Errorf("%w: request failed", ErrDownloadFailed)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: unexpected HTTP status %d", ErrDownloadFailed, resp.StatusCode)
	}

	hasher := sha256.New()
	multi := io.MultiWriter(opts.Out, hasher)

	limitReader := io.LimitReader(resp.Body, opts.ExpectedSize+1)
	n, err := io.Copy(multi, limitReader)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(reqCtx.Err(), context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return fmt.Errorf("%w: stream read error", ErrDownloadFailed)
	}

	if n > opts.ExpectedSize {
		return fmt.Errorf("%w: downloaded bytes exceeded expected size %d", ErrSizeMismatch, opts.ExpectedSize)
	}
	if n < opts.ExpectedSize {
		return fmt.Errorf("%w: downloaded bytes %d less than expected size %d", ErrSizeMismatch, n, opts.ExpectedSize)
	}

	actualSHA256 := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(actualSHA256, opts.ExpectedSHA256) {
		return fmt.Errorf("%w: got %s, want %s", ErrDigestMismatch, actualSHA256, opts.ExpectedSHA256)
	}

	return nil
}
