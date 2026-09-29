package migrationpreview

import (
	"errors"
	"testing"
)

type failedPreviewFKRows struct{}

func (failedPreviewFKRows) Next() bool   { return false }
func (failedPreviewFKRows) Err() error   { return errors.New("fixture iterator failed") }
func (failedPreviewFKRows) Close() error { return nil }
func TestPreviewFKIterationErrorFailsClosed(t *testing.T) {
	if violation, err := previewForeignKeyResult(failedPreviewFKRows{}); violation || err == nil {
		t.Fatal("FK iterator error reported successful projection")
	}
}
