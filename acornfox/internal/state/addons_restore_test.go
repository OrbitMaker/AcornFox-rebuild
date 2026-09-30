package state

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestAddonSoftDeleteRestoresStoredCredentials(t *testing.T) {
	for _, kind := range []string{AddonPostgres, AddonMySQL, AddonRedis} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			s := openAddonStore(t)
			if _, _, err := s.EnsureApp(ctx, "shop"); err != nil {
				t.Fatal(err)
			}
			original := testAddon(t, "shop", kind)
			if reused, err := s.AddAddon(ctx, original); err != nil || reused {
				t.Fatalf("initial add: reused=%v err=%v", reused, err)
			}
			before, err := s.ListAddons(ctx, "shop")
			if err != nil || len(before) != 1 {
				t.Fatalf("before remove: count=%d err=%v", len(before), err)
			}
			if err := s.RemoveAddon(ctx, "shop", kind, false); err != nil {
				t.Fatal(err)
			}
			active, err := s.ListAddons(ctx, "shop")
			if err != nil || len(active) != 0 {
				t.Fatalf("removed add-on must not be active: count=%d err=%v", len(active), err)
			}
			removed, err := s.ListRemovedAddons(ctx, "shop")
			if err != nil || len(removed) != 1 || !bytes.Equal(removed[0].Credentials, original.Credentials) {
				t.Fatalf("soft deletion lost the credentials: count=%d err=%v", len(removed), err)
			}

			// The new request contains different credentials and a different spec.
			// Restoration must keep the spec tied to the retained database volume.
			replacement := testAddon(t, "shop", kind)
			replacement.Image = kind + ":another-version"
			replacement.VolumeName += "-another"
			replacement.EnvVar = "OTHER_URL"
			if reused, err := s.AddAddon(ctx, replacement); err != nil || !reused {
				t.Fatalf("restore: reused=%v err=%v", reused, err)
			}
			after, err := s.ListAddons(ctx, "shop")
			if err != nil || len(after) != 1 {
				t.Fatalf("after restore: count=%d err=%v", len(after), err)
			}
			got, want := after[0], before[0]
			if !bytes.Equal(got.Credentials, want.Credentials) || got.Image != want.Image ||
				got.VolumeName != want.VolumeName || got.EnvVar != want.EnvVar || !got.CreatedAt.Equal(want.CreatedAt) {
				t.Fatal("restoration changed stored credentials, spec or creation time")
			}
			removed, err = s.ListRemovedAddons(ctx, "shop")
			if err != nil || len(removed) != 0 {
				t.Fatalf("restored add-on must not remain removed: count=%d err=%v", len(removed), err)
			}
		})
	}
}

func TestAddonRestoreChecksStoredEnvironmentConflict(t *testing.T) {
	ctx := context.Background()
	s := openAddonStore(t)
	if _, _, err := s.EnsureApp(ctx, "shop"); err != nil {
		t.Fatal(err)
	}
	postgres := testAddon(t, "shop", AddonPostgres)
	if _, err := s.AddAddon(ctx, postgres); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveAddon(ctx, "shop", AddonPostgres, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAddon(ctx, testAddon(t, "shop", AddonMySQL)); err != nil {
		t.Fatal(err)
	}
	// Changing the requested env key must not bypass the stored DATABASE_URL conflict.
	request := testAddon(t, "shop", AddonPostgres)
	request.EnvVar = "OTHER_URL"
	if reused, err := s.AddAddon(ctx, request); reused || !errors.Is(err, ErrConflict) {
		t.Fatalf("restore conflict: reused=%v err=%v", reused, err)
	}
	active, err := s.ListAddons(ctx, "shop")
	if err != nil || len(active) != 1 || active[0].Kind != AddonMySQL {
		t.Fatalf("restore conflict changed active add-ons: count=%d err=%v", len(active), err)
	}
	removed, err := s.ListRemovedAddons(ctx, "shop")
	if err != nil || len(removed) != 1 || !bytes.Equal(removed[0].Credentials, postgres.Credentials) {
		t.Fatal("restore conflict changed removed credentials")
	}
	if err := s.RemoveAddon(ctx, "shop", AddonMySQL, false); err != nil {
		t.Fatal(err)
	}
	if reused, err := s.AddAddon(ctx, request); !reused || err != nil {
		t.Fatalf("restore after conflict removed: reused=%v err=%v", reused, err)
	}
}

func TestAddonHardDeleteAllowsNewCredentials(t *testing.T) {
	for _, removed := range []bool{false, true} {
		t.Run(strconv.FormatBool(removed), func(t *testing.T) {
			ctx := context.Background()
			s := openAddonStore(t)
			if _, _, err := s.EnsureApp(ctx, "shop"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.AddAddon(ctx, testAddon(t, "shop", AddonMySQL)); err != nil {
				t.Fatal(err)
			}
			if removed {
				if err := s.RemoveAddon(ctx, "shop", AddonMySQL, false); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.RemoveAddon(ctx, "shop", AddonMySQL, true); err != nil {
				t.Fatal(err)
			}
			if err := s.RemoveAddon(ctx, "shop", AddonMySQL, true); !errors.Is(err, ErrNotFound) {
				t.Fatalf("hard delete twice: %v", err)
			}
			replacement := testAddon(t, "shop", AddonMySQL)
			if reused, err := s.AddAddon(ctx, replacement); reused || err != nil {
				t.Fatalf("new add after hard delete: reused=%v err=%v", reused, err)
			}
			list, err := s.ListAddons(ctx, "shop")
			if err != nil || len(list) != 1 || !bytes.Equal(list[0].Credentials, replacement.Credentials) {
				t.Fatal("hard delete did not allow fresh credentials")
			}
		})
	}
}

func TestAddonSoftDeletePersistsAcrossStoreReopen(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Path: filepath.Join(t.TempDir(), "af.db")}
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, _, err := s.EnsureApp(ctx, "shop"); err != nil {
		t.Fatal(err)
	}
	original := testAddon(t, "shop", AddonPostgres)
	if _, err := s.AddAddon(ctx, original); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveAddon(ctx, "shop", AddonPostgres, false); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if reused, err := s.AddAddon(ctx, testAddon(t, "shop", AddonPostgres)); err != nil || !reused {
		t.Fatalf("restore after reopen: reused=%v err=%v", reused, err)
	}
	list, err := s.ListAddons(ctx, "shop")
	if err != nil || len(list) != 1 || !bytes.Equal(list[0].Credentials, original.Credentials) {
		t.Fatal("reopen lost retained credentials")
	}
}

func TestAddonSoftDeleteMigrationFrom0004(t *testing.T) {
	ctx := context.Background()
	original := testAddon(t, "shop", AddonPostgres)
	path := filepath.Join(t.TempDir(), "af.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, schemaMigrationsDDL); err != nil {
		t.Fatal(err)
	}
	for _, m := range migrationList()[:4] {
		if _, err := db.ExecContext(ctx, m.body); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO _schema_migrations(version,checksum,applied_at) VALUES(?,?,?)`, m.version, checksum(m.body), formatTime(time.Now())); err != nil {
			t.Fatal(err)
		}
	}
	now := formatTime(time.Now())
	if _, err := db.ExecContext(ctx, `INSERT INTO apps(name,desired,health_path,public_port,memory_mb,cpu_milli,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
		"shop", DesiredRunning, "/", 18810, DefaultMemoryMB, DefaultCPUMilli, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO addons(app,kind,image,volume_name,credentials,env_var,created_at) VALUES(?,?,?,?,?,?,?)`,
		original.App, original.Kind, original.Image, original.VolumeName, string(original.Credentials), original.EnvVar, now); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(Config{Path: path})
	if err != nil {
		t.Fatalf("upgrade from 0004: %v", err)
	}
	defer s.Close()
	list, err := s.ListAddons(ctx, "shop")
	if err != nil || len(list) != 1 || !bytes.Equal(list[0].Credentials, original.Credentials) {
		t.Fatal("migration did not preserve existing add-on credentials")
	}
	if err := s.RemoveAddon(ctx, "shop", AddonPostgres, false); err != nil {
		t.Fatal(err)
	}
	if reused, err := s.AddAddon(ctx, testAddon(t, "shop", AddonPostgres)); !reused || err != nil {
		t.Fatalf("restore on upgraded schema: reused=%v err=%v", reused, err)
	}
}
