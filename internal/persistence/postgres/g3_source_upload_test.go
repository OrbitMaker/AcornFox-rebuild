package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestG3SourceUploadMigrationStoresMetadataWithoutPayloadOrHostPaths(t *testing.T) {
	payload, err := os.ReadFile("../../../migrations/control-plane/0023_source_uploads.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(payload))
	for _, fragment := range []string{"create table if not exists source_uploads", "create table if not exists source_upload_files", "status in ('ready','claimed','expired','failed')", "storage_ref = 'upload://' || id", "claimed_application_id"} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("migration is missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"file_content", "client_path", "absolute_path", "secretkey", "secretid"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("migration must not persist %q", forbidden)
		}
	}
}
