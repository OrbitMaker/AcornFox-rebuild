package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/persistence/sqlite"
	"github.com/open-card/open-card/internal/unifiedinstall"
)

func TestNativeSQLiteUnknownOutcomeIsVisibleWithoutPrivateCause(t *testing.T) {
	privateCause := errors.New("private database path and cause")
	message := nativeSQLiteFailureMessage(errors.Join(sqlite.ErrNativeBackupOutcomeUnknown, privateCause))
	if !strings.Contains(message, "outcome unknown") || strings.Contains(message, privateCause.Error()) {
		t.Fatal("published backup uncertainty was hidden or private cause exposed")
	}
	if strings.Contains(nativeSQLiteFailureMessage(errors.New("pre-effect refusal")), "outcome unknown") {
		t.Fatal("ordinary refusal was mislabeled committed")
	}
}

func TestNativeSQLiteRestoreUnknownDoesNotExposePrivateCause(t *testing.T) {
	privateCause := errors.New("private restore path and cause")
	message := nativeSQLiteRestoreFailureMessage(errors.Join(unifiedinstall.ErrNativeRestoreUnknown, privateCause))
	if !strings.Contains(message, "outcome unknown") || strings.Contains(message, privateCause.Error()) {
		t.Fatal("restore uncertainty or private cause was mishandled")
	}
	if strings.Contains(nativeSQLiteRestoreFailureMessage(errors.New("preflight refused")), "outcome unknown") {
		t.Fatal("pre-effect refusal mislabeled")
	}
}
