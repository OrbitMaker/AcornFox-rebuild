package runner

import (
	"errors"
	"strings"
	"testing"
)

func TestClassifyBuildRegistryTimeout(t *testing.T) {
	cases := []struct {
		name, log, want string
	}{
		{"npm", "npm error code ETIMEDOUT\nnpm error network request to https://registry.npmjs.org/express failed, reason:", "registry_timeout"},
		{"pip", "WARNING: Retrying (Retry(total=4, connect=None)) after connection broken by 'ConnectTimeoutError(...)': /simple/flask/", "registry_timeout"},
		{"go", "go: github.com/x/y@v1.0.0: Get \"https://proxy.golang.org/github.com/x/y/@v/v1.0.0.mod\": dial tcp 142.250.1.1:443: i/o timeout", "registry_timeout"},
		{"apk", "WARNING: fetching https://dl-cdn.alpinelinux.org/alpine/v3.20/main: temporary error (try again later)", "registry_timeout"},
		{"base image", "Get \"https://registry-1.docker.io/v2/\": dial tcp: lookup registry-1.docker.io: i/o timeout", "base_image_not_found"},
		{"missing module", "Error: Cannot find module 'express'", "dependency_missing"},
		{"other", "Step 5/8 : RUN make\nmake: *** No rule to make target 'all'.", "build_failed"},
	}
	for _, c := range cases {
		f := classifyBuild(errors.New("The command returned a non-zero code: 1"), strings.Split(c.log, "\n"))
		if f.Code != c.want {
			t.Errorf("%s: code = %q, want %q", c.name, f.Code, c.want)
		}
		if c.want == "registry_timeout" && !strings.Contains(f.Hint, "registry.npmmirror.com") {
			t.Errorf("%s: hint does not mention domestic mirrors: %q", c.name, f.Hint)
		}
	}
}
