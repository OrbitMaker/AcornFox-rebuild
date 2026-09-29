package reconcile

import (
	"context"
	"errors"
	"testing"
)

func TestClassifyGitCloneAuthRequired(t *testing.T) {
	out := "Cloning into '/x'...\nfatal: could not read Username for 'https://gitee.com': terminal prompts disabled\n"
	d := classifyGitClone(context.Background(), errors.New("exit status 128"), out)
	if d.Stage != "source" || d.Code != "auth_required" {
		t.Fatalf("got %s/%s", d.Stage, d.Code)
	}
}
