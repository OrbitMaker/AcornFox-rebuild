package compose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

func TestM2ComposeFixturesMatchFailClosedImportBoundary(t *testing.T) {
	root := filepath.Join("..", "..", "..", "tests", "fixtures", "compose")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		entry := entry
		t.Run(entry.Name(), func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join(root, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			result, importErr := ImportJSON(payload, Options{ApplicationID: domain.ID("app_m2_fixtures"), Name: "fixture", Now: time.Unix(100, 0)})
			negative := strings.HasPrefix(entry.Name(), "negative-")
			if negative {
				if importErr == nil || result.Report.Accepted || len(result.Report.RejectedFields) == 0 {
					t.Fatalf("negative fixture did not fail closed: report=%#v err=%v", result.Report, importErr)
				}
				return
			}
			if importErr != nil || !result.Report.Accepted || len(result.ServiceGroup.Services) < 2 {
				t.Fatalf("positive fixture was rejected: report=%#v err=%v", result.Report, importErr)
			}
		})
	}
}
