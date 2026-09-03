package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/open-card/open-card/internal/install"
)

func TestAcornFoxContractCheckRejectsBeforeUpgradeDependencies(t *testing.T) {
	oldIdentity, oldVersion, oldCommit, oldLayout := processIdentity, buildVersion, buildSourceCommit, buildLayoutSchema
	t.Cleanup(func() {
		processIdentity, buildVersion, buildSourceCommit, buildLayoutSchema = oldIdentity, oldVersion, oldCommit, oldLayout
	})
	processIdentity, buildVersion, buildSourceCommit, buildLayoutSchema = "acornfox", "1.2.3-test.1", "0123456789abcdef0123456789abcdef01234567", "1"
	deps := upgradeDependencies{euid: func() int { t.Fatal("legacy dependency called"); return 0 }}
	for _, args := range [][]string{
		{"contract-check", "--product", "acornfox", "--layout-schema", "1"},
		{"contract-check"},
		{"contract-check", "--product", "acornfox", "--layout-schema", "1", "extra"},
	} {
		var stdout, stderr bytes.Buffer
		_ = runWithDependencies(context.Background(), args, &stdout, &stderr, deps)
		result, err := install.ParseAcornFoxHelperContractResultV1(bytes.TrimSpace(stdout.Bytes()))
		if err != nil || len(stderr.Bytes()) != 0 {
			t.Fatalf("args=%q result=%q stderr=%q err=%v", args, stdout.String(), stderr.String(), err)
		}
		if len(args) == 5 && result.Code != install.AcornFoxHelperCodeReceiptUnavailable {
			t.Fatalf("valid args result=%#v", result)
		}
		if len(args) != 5 && result.Code != install.AcornFoxHelperCodeInvalidArguments {
			t.Fatalf("invalid args result=%#v", result)
		}
	}
}
