//go:build linux

package desktopupdateguest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/install"
)

func installTestHelper(t *testing.T, root, script string) {
	t.Helper()
	helperPath := filepath.Join(root, install.AcornFoxUpgradeHelperPath)
	if e := os.MkdirAll(filepath.Dir(helperPath), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(helperPath, []byte(script), 0755); e != nil {
		t.Fatal(e)
	}
}

func TestProductionBackendRecoverRolledBack(t *testing.T) {
	f := newFixture(t)
	upgradePrepared, err := json.Marshal(install.AcornFoxUpgradeReceiptV1{
		SchemaVersion:         1,
		State:                 "RECOVERY_PREPARED",
		BindingSHA256:         strings.Repeat("1", 64),
		PreviousBindingSHA256: strings.Repeat("1", 64),
		ReleaseID:             "release-0.1.0-beta.14",
		SourceCommit:          strings.Repeat("a", 40),
		LayoutSHA256:          strings.Repeat("2", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	upgradeRolledBack, err := json.Marshal(install.AcornFoxUpgradeReceiptV1{
		SchemaVersion:         1,
		State:                 "ROLLED_BACK",
		BindingSHA256:         strings.Repeat("1", 64),
		PreviousBindingSHA256: strings.Repeat("1", 64),
		ReleaseID:             "release-0.1.0-beta.14",
		SourceCommit:          strings.Repeat("a", 40),
		LayoutSHA256:          strings.Repeat("2", 64),
	})
	if err != nil {
		t.Fatal(err)
	}

	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = "recover-prepare" ]; then
  cat <<'EOF'
{"ok":true,"command":"recover-prepare","receipt":%s}
EOF
elif [ "$1" = "recover-finalize" ]; then
  cat <<'EOF'
{"ok":true,"command":"recover-finalize","receipt":%s}
EOF
else
  exit 1
fi
`, string(upgradePrepared), string(upgradeRolledBack))

	installTestHelper(t, f.x.paths.anchor, script)
	backend := productionBackend{x: f.x}

	err = backend.Recover(context.Background())
	if !errors.Is(err, install.ErrAcornFoxUpgradeRolledBack) {
		t.Fatalf("expected ErrAcornFoxUpgradeRolledBack, got: %v", err)
	}
}

func TestProductionBackendRecoverBootstrapNoOp(t *testing.T) {
	f := newFixture(t)
	bootstrapRec, err := install.MarshalAcornFoxHostBootstrapReceiptV1(install.AcornFoxHostBootstrapReceiptV1{
		SchemaVersion:          1,
		State:                  "REPO_PREPARED",
		BindingSHA256:          strings.Repeat("1", 64),
		ReleaseID:              "release-0.1.0-beta.13",
		SourceCommit:           strings.Repeat("a", 40),
		LayoutSHA256:           strings.Repeat("2", 64),
		SubstrateReceiptSHA256: strings.Repeat("3", 64),
		FinalEvidenceSHA256:    strings.Repeat("4", 64),
	})
	if err != nil {
		t.Fatal(err)
	}

	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = "recover-prepare" ]; then
  cat <<'EOF'
{"ok":true,"command":"recover-prepare","receipt":%s}
EOF
elif [ "$1" = "recover-finalize" ]; then
  cat <<'EOF'
{"ok":true,"command":"recover-finalize","receipt":%s}
EOF
else
  exit 1
fi
`, string(bootstrapRec), string(bootstrapRec))

	installTestHelper(t, f.x.paths.anchor, script)
	backend := productionBackend{x: f.x}

	err = backend.Recover(context.Background())
	if err != nil {
		t.Fatalf("expected nil for bootstrap no-op recovery, got: %v", err)
	}
}

func TestProductionBackendRecoverSecondVerbFailureNotHidden(t *testing.T) {
	f := newFixture(t)
	upgradeRolledBack, _ := json.Marshal(install.AcornFoxUpgradeReceiptV1{
		SchemaVersion:         1,
		State:                 "ROLLED_BACK",
		BindingSHA256:         strings.Repeat("1", 64),
		PreviousBindingSHA256: strings.Repeat("1", 64),
		ReleaseID:             "release-0.1.0-beta.14",
		SourceCommit:          strings.Repeat("a", 40),
		LayoutSHA256:          strings.Repeat("2", 64),
	})

	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = "recover-prepare" ]; then
  cat <<'EOF'
{"ok":true,"command":"recover-prepare","receipt":%s}
EOF
elif [ "$1" = "recover-finalize" ]; then
  echo "fatal backend failure" >&2
  exit 1
else
  exit 1
fi
`, string(upgradeRolledBack))

	installTestHelper(t, f.x.paths.anchor, script)
	backend := productionBackend{x: f.x}

	err := backend.Recover(context.Background())
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("expected ErrBusy when recover-finalize fails, got: %v", err)
	}
}

func TestProductionBackendRecoverMalformedReceiptFails(t *testing.T) {
	f := newFixture(t)

	script := `#!/bin/sh
if [ "$1" = "recover-prepare" ]; then
  cat <<'EOF'
{"ok":true,"command":"recover-prepare","receipt":{"malformed":true}}
EOF
else
  exit 1
fi
`

	installTestHelper(t, f.x.paths.anchor, script)
	backend := productionBackend{x: f.x}

	err := backend.Recover(context.Background())
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("expected ErrBusy on malformed receipt, got: %v", err)
	}
}
