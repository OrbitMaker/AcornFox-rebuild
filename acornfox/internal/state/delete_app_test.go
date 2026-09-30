package state

import (
	"context"
	"errors"
	"strconv"
	"testing"
)

func TestDeleteAppRemovesRelatedSQLRecords(t *testing.T) {
	for _, keepVolumes := range []bool{false, true} {
		t.Run(strconv.FormatBool(keepVolumes), func(t *testing.T) {
			ctx := context.Background()
			s := openAddonStore(t)
			for _, name := range []string{"shop", "other"} {
				if _, _, err := s.EnsureApp(ctx, name); err != nil {
					t.Fatal(err)
				}
				if err := s.SetEnv(ctx, EnvVar{App: name, Key: "SECRET", Value: "test-value", Secret: true}); err != nil {
					t.Fatal(err)
				}
				if _, _, err := s.AddVolume(ctx, name, "/data", false); err != nil {
					t.Fatal(err)
				}
				dep, _, err := s.CreateDeployment(ctx, NewDeployment{App: name, SourceKind: SourceImage, SourceRef: "test:image", SourceDigest: "digest-" + name})
				if err != nil {
					t.Fatal(err)
				}
				if err := s.AddEvent(ctx, Event{App: name, DeploymentID: dep.ID, Stage: "test", Message: "test event"}); err != nil {
					t.Fatal(err)
				}
				if _, _, err := s.AddDomain(ctx, name, name+".example.com"); err != nil {
					t.Fatal(err)
				}
				if _, err := s.AddAddon(ctx, testAddon(t, name, AddonPostgres)); err != nil {
					t.Fatal(err)
				}
				if _, err := s.AddAddon(ctx, testAddon(t, name, AddonRedis)); err != nil {
					t.Fatal(err)
				}
				if err := s.RemoveAddon(ctx, name, AddonPostgres, false); err != nil {
					t.Fatal(err)
				}
			}

			if err := s.DeleteApp(ctx, "shop", keepVolumes); err != nil {
				t.Fatalf("delete real SQLite app: %v", err)
			}
			if _, err := s.GetApp(ctx, "shop"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("deleted app still present: %v", err)
			}
			for _, table := range []string{"app_env", "app_volumes", "deployments", "app_domains", "events", "addons"} {
				var deletedCount, otherCount int
				if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE app=?", "shop").Scan(&deletedCount); err != nil {
					t.Fatal(err)
				}
				if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE app=?", "other").Scan(&otherCount); err != nil {
					t.Fatal(err)
				}
				if deletedCount != 0 || otherCount == 0 {
					t.Fatalf("table %s: deleted app rows=%d, other app rows=%d", table, deletedCount, otherCount)
				}
			}
			if err := s.DeleteApp(ctx, "shop", keepVolumes); !errors.Is(err, ErrNotFound) {
				t.Fatalf("delete missing app: %v", err)
			}
		})
	}
}
