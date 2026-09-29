package registryhttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/acornfox/acornfox/internal/contracts"
)

const (
	dockerAuthRealm   = "https://auth.docker.io/token"
	dockerAuthService = "registry.docker.io"
	ghcrAuthRealm     = "https://ghcr.io/token"
	ghcrAuthService   = "ghcr.io"
	maxTokenResponse  = 64 << 10
)

type bearerChallenge struct {
	Realm   string
	Service string
	Scope   string
}

func parseBearerChallenge(header string) (*bearerChallenge, error) {
	trimmed := strings.TrimSpace(header)
	if !strings.HasPrefix(strings.ToLower(trimmed), "bearer ") {
		return nil, errors.New("not a bearer challenge")
	}
	paramStr := strings.TrimSpace(trimmed[len("bearer "):])
	challenge := &bearerChallenge{}

	// Parse comma-separated key="value" or key=value pairs
	for len(paramStr) > 0 {
		idx := strings.IndexByte(paramStr, '=')
		if idx == -1 {
			break
		}
		key := strings.TrimSpace(paramStr[:idx])
		paramStr = strings.TrimSpace(paramStr[idx+1:])

		var val string
		if strings.HasPrefix(paramStr, `"`) {
			paramStr = paramStr[1:]
			endQuote := strings.IndexByte(paramStr, '"')
			if endQuote == -1 {
				return nil, errors.New("unclosed quote in challenge")
			}
			val = paramStr[:endQuote]
			paramStr = strings.TrimSpace(paramStr[endQuote+1:])
			if strings.HasPrefix(paramStr, ",") {
				paramStr = strings.TrimSpace(paramStr[1:])
			}
		} else {
			endComma := strings.IndexByte(paramStr, ',')
			if endComma == -1 {
				val = strings.TrimSpace(paramStr)
				paramStr = ""
			} else {
				val = strings.TrimSpace(paramStr[:endComma])
				paramStr = strings.TrimSpace(paramStr[endComma+1:])
			}
		}

		switch strings.ToLower(key) {
		case "realm":
			challenge.Realm = val
		case "service":
			challenge.Service = val
		case "scope":
			challenge.Scope = val
		}
	}

	if challenge.Realm == "" {
		return nil, errors.New("challenge missing realm")
	}
	return challenge, nil
}

func (p *Provider) handleAnonymousChallenge(ctx context.Context, session *httpSession, repository string, resp *http.Response) error {
	// Never forward Basic secrets to an anonymous realm challenge
	if session.authHeader != "" {
		return p.failure(session.operation, contracts.ErrUnauthorized, "anonymous_auth", "basic auth credentials denied", nil)
	}

	challengeHeader := resp.Header.Get("Www-Authenticate")
	if challengeHeader == "" {
		return p.failure(session.operation, contracts.ErrUnauthorized, "anonymous_auth", "missing www-authenticate header", nil)
	}

	challenge, err := parseBearerChallenge(challengeHeader)
	if err != nil {
		return p.failure(session.operation, contracts.ErrUnauthorized, "anonymous_auth", "invalid bearer challenge", err)
	}

	host := registryHost(repository)

	parsedRealm, err := url.Parse(challenge.Realm)
	if err != nil || parsedRealm.User != nil || parsedRealm.RawQuery != "" || parsedRealm.Fragment != "" {
		return p.failure(session.operation, contracts.ErrForbidden, "anonymous_auth", "invalid realm URL or opaque credentials/query rejected", nil)
	}

	// Validate production realms and services
	switch host {
	case "registry-1.docker.io", "docker.io":
		if challenge.Realm != dockerAuthRealm || challenge.Service != dockerAuthService {
			return p.failure(session.operation, contracts.ErrForbidden, "anonymous_auth", "invalid challenge realm or service for Docker Hub", nil)
		}
	case "ghcr.io":
		if challenge.Realm != ghcrAuthRealm || challenge.Service != ghcrAuthService {
			return p.failure(session.operation, contracts.ErrForbidden, "anonymous_auth", "invalid challenge realm or service for GHCR", nil)
		}
	default:
		// Loopback test fixtures: realm must match baseURL origin exactly, scheme must be http, User/Query/Fragment must be empty
		if session.baseURL != nil && session.baseURL.Scheme == "http" && isLoopbackHost(session.baseURL.Hostname()) {
			if parsedRealm.Scheme != "http" || parsedRealm.Host != session.baseURL.Host || parsedRealm.Path == "" {
				return p.failure(session.operation, contracts.ErrForbidden, "anonymous_auth", "loopback challenge realm must match test registry origin", nil)
			}
		} else {
			return p.failure(session.operation, contracts.ErrForbidden, "anonymous_auth", "unsupported registry host for anonymous challenge", nil)
		}
	}

	// Validate scope: pull-only on exact requested repository. Challenge scope must be empty or equal to expectedScope.
	repoPath := stripRegistryHost(repository)
	expectedScope := "repository:" + repoPath + ":pull"
	if challenge.Scope != "" && challenge.Scope != expectedScope {
		return p.failure(session.operation, contracts.ErrForbidden, "anonymous_auth", "challenge scope does not match expected repository pull scope", nil)
	}

	// Construct token URL starting with clean query
	tokenURL := *parsedRealm
	q := url.Values{}
	if challenge.Service != "" {
		q.Set("service", challenge.Service)
	}
	q.Set("scope", expectedScope)
	tokenURL.RawQuery = q.Encode()

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL.String(), nil)
	if err != nil {
		return p.failure(session.operation, contracts.ErrUnavailable, "anonymous_auth", "construct token request failed", err)
	}

	// Token client: strictly no redirects
	var transport http.RoundTripper
	if session.client != nil {
		transport = session.client.Transport
	}
	tokenClient := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("redirects are forbidden for token challenge")
		},
	}

	tokenResp, err := tokenClient.Do(tokenReq)
	if err != nil {
		return p.failure(session.operation, contracts.ErrUnavailable, "anonymous_auth", "token request failed", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode < 200 || tokenResp.StatusCode >= 300 {
		return p.failure(session.operation, contracts.ErrUnauthorized, "anonymous_auth", "token request returned unsuccessful status", nil)
	}

	body, err := io.ReadAll(io.LimitReader(tokenResp.Body, maxTokenResponse+1))
	if err != nil || len(body) > maxTokenResponse {
		return p.failure(session.operation, contracts.ErrValidation, "anonymous_auth", "token response too large", nil)
	}

	var parsedResp struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &parsedResp); err != nil {
		return p.failure(session.operation, contracts.ErrValidation, "anonymous_auth", "token response invalid json", nil)
	}

	// P2 Fix: Reject ambiguous token response if both are present and disagree
	if parsedResp.Token != "" && parsedResp.AccessToken != "" && parsedResp.Token != parsedResp.AccessToken {
		return p.failure(session.operation, contracts.ErrValidation, "anonymous_auth", "ambiguous token response rejected", nil)
	}

	tok := parsedResp.Token
	if tok == "" {
		tok = parsedResp.AccessToken
	}
	if tok == "" || strings.ContainsAny(tok, "\r\n") {
		return p.failure(session.operation, contracts.ErrUnauthorized, "anonymous_auth", "token response missing valid token", nil)
	}

	// Keep token in memory and track for cleanup
	session.authBytes = []byte(tok)
	session.authHeader = "Bearer " + tok
	session.tokenRetried = true

	return nil
}
