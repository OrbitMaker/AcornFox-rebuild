package main

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/open-card/open-card/internal/compatibility"
)

const (
	apiVersionHeader    = "Open-Card-API-Version"
	apiMinVersionHeader = "Open-Card-API-Min-Version"
	apiMaxVersionHeader = "Open-Card-API-Max-Version"
	apiCurrentVersion   = "1.1"
	apiPreviousVersion  = "1.0"
)

type apiVersionContextKey struct{}

var apiCapabilities = map[compatibility.Version][]string{
	{Major: 1, Minor: 0}: {"rest", "sse"},
	{Major: 1, Minor: 1}: {"rest", "sse", "persistent_sse_schema"},
}

func negotiateAPIRequest(request *http.Request) (string, []string, error) {
	minimum := strings.TrimSpace(request.Header.Get(apiMinVersionHeader))
	maximum := strings.TrimSpace(request.Header.Get(apiMaxVersionHeader))
	if exact := strings.TrimSpace(request.Header.Get(apiVersionHeader)); exact != "" {
		if minimum != "" || maximum != "" {
			return "", nil, errors.New("exact and range API version headers are mutually exclusive")
		}
		minimum, maximum = exact, exact
	}
	if minimum == "" && maximum == "" {
		minimum, maximum = apiPreviousVersion, apiPreviousVersion
	}
	minVersion, err := compatibility.Parse(minimum)
	if err != nil {
		return "", nil, err
	}
	maxVersion, err := compatibility.Parse(maximum)
	if err != nil {
		return "", nil, err
	}
	negotiated, err := compatibility.Negotiate(minVersion, maxVersion, []compatibility.Version{{Major: 1, Minor: 1}, {Major: 1, Minor: 0}}, apiCapabilities)
	if err != nil {
		return "", nil, err
	}
	return negotiated.Version.String(), negotiated.DisabledCapabilities, nil
}

func withAPIVersion(request *http.Request, version string) *http.Request {
	return request.WithContext(context.WithValue(request.Context(), apiVersionContextKey{}, version))
}

func apiVersionFromContext(ctx context.Context) string {
	if version, ok := ctx.Value(apiVersionContextKey{}).(string); ok && version != "" {
		return version
	}
	return apiPreviousVersion
}
