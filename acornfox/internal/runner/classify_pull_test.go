package runner

import (
	"context"
	"errors"
	"testing"
)

func TestClassifyPull(t *testing.T) {
	cases := []struct {
		name, msg, code string
	}{
		{"mirror 403", `unknown: failed to resolve reference "docker.io/x/y:0": unexpected status from HEAD request to https://docker.m.daocloud.io/v2/x/y/manifests/0?ns=docker.io: 403 Forbidden`, "image_not_found"},
		{"manifest unknown", "manifest unknown: manifest unknown", "image_not_found"},
		{"pull access denied", "pull access denied for x, repository does not exist or may require 'docker login'", "image_not_found"},
		{"dial timeout", "Get https://registry-1.docker.io/v2/: dial tcp 1.2.3.4:443: i/o timeout", "pull_timeout"},
		{"tls timeout", "net/http: TLS handshake timeout", "pull_timeout"},
		{"other", "invalid reference format", "pull_failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := classifyPull(context.Background(), errors.New(c.msg))
			if f == nil || f.Code != c.code || f.Stage != "image" {
				t.Fatalf("got %+v, want image/%s", f, c.code)
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	<-ctx.Done()
	if f := classifyPull(ctx, errors.New("whatever")); f.Code != "pull_timeout" {
		t.Fatalf("deadline: got %s", f.Code)
	}
}
