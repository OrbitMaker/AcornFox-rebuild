package state

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func openAddonStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(Config{Path: filepath.Join(t.TempDir(), "af.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testAddon(t *testing.T, app, kind string) Addon {
	t.Helper()
	c, err := NewAddonCredentials(app, kind, "af-"+app+"-addon-"+kind, 5432)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return Addon{App: app, Kind: kind, Image: kind + ":pinned", VolumeName: "af-" + app + "-addon-" + kind + "-data",
		Credentials: raw, EnvVar: AddonEnvVar(kind)}
}

func TestAddonStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	s := openAddonStore(t)
	if _, _, err := s.EnsureApp(ctx, "shop"); err != nil {
		t.Fatal(err)
	}

	pg := testAddon(t, "shop", AddonPostgres)
	if _, err := s.AddAddon(ctx, pg); err != nil {
		t.Fatalf("add postgres: %v", err)
	}
	if _, err := s.AddAddon(ctx, testAddon(t, "shop", AddonRedis)); err != nil {
		t.Fatalf("add redis: %v", err)
	}

	// Same kind twice, and a second DATABASE_URL provider, both conflict.
	if _, err := s.AddAddon(ctx, testAddon(t, "shop", AddonPostgres)); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate kind: want ErrConflict, got %v", err)
	}
	if _, err := s.AddAddon(ctx, testAddon(t, "shop", AddonMySQL)); !errors.Is(err, ErrConflict) {
		t.Fatalf("second DATABASE_URL: want ErrConflict, got %v", err)
	}

	list, err := s.ListAddons(ctx, "shop")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Kind != AddonPostgres || list[1].Kind != AddonRedis {
		t.Fatalf("list = %+v", list)
	}
	got, err := list[0].DecodeCredentials()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := pg.DecodeCredentials()
	if got != want {
		t.Fatalf("credentials did not round-trip: %+v vs %+v", got, want)
	}

	if err := s.RemoveAddon(ctx, "shop", AddonPostgres, false); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := s.RemoveAddon(ctx, "shop", AddonPostgres, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove twice: want ErrNotFound, got %v", err)
	}
	// With postgres gone, mysql may now provide DATABASE_URL.
	if _, err := s.AddAddon(ctx, testAddon(t, "shop", AddonMySQL)); err != nil {
		t.Fatalf("add mysql after removing postgres: %v", err)
	}
}

func TestAddAddonValidation(t *testing.T) {
	ctx := context.Background()
	s := openAddonStore(t)
	if _, err := s.AddAddon(ctx, testAddon(t, "ghost", AddonRedis)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing app: want ErrNotFound, got %v", err)
	}
	if _, _, err := s.EnsureApp(ctx, "shop"); err != nil {
		t.Fatal(err)
	}
	bad := testAddon(t, "shop", AddonRedis)
	bad.Kind = "mongo"
	if _, err := s.AddAddon(ctx, bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad kind: want ErrInvalid, got %v", err)
	}
	bad = testAddon(t, "shop", AddonRedis)
	bad.Credentials = []byte("{not json")
	if _, err := s.AddAddon(ctx, bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad credentials: want ErrInvalid, got %v", err)
	}
}

func TestNewAddonCredentialsURLs(t *testing.T) {
	hex32 := `[0-9a-f]{32}`
	cases := []struct {
		kind, host string
		port       int
		url        *regexp.Regexp
	}{
		{AddonPostgres, "af-shop-addon-postgres", 5432, regexp.MustCompile(`^postgresql://acornfox_shop:` + hex32 + `@af-shop-addon-postgres:5432/acornfox_shop$`)},
		{AddonMySQL, "af-shop-addon-mysql", 3306, regexp.MustCompile(`^mysql://acornfox_shop:` + hex32 + `@af-shop-addon-mysql:3306/acornfox_shop$`)},
		{AddonRedis, "af-shop-addon-redis", 6379, regexp.MustCompile(`^redis://:` + hex32 + `@af-shop-addon-redis:6379/0$`)},
	}
	for _, c := range cases {
		cr, err := NewAddonCredentials("shop", c.kind, c.host, c.port)
		if err != nil {
			t.Fatalf("%s: %v", c.kind, err)
		}
		if !c.url.MatchString(cr.URL) {
			t.Fatalf("%s url = %q", c.kind, cr.URL)
		}
		again, _ := NewAddonCredentials("shop", c.kind, c.host, c.port)
		if again.Password == cr.Password {
			t.Fatalf("%s: passwords are not random", c.kind)
		}
	}
	my, _ := NewAddonCredentials("shop", AddonMySQL, "h", 3306)
	if my.RootPassword == "" || my.RootPassword == my.Password {
		t.Fatalf("mysql root password must be separate: %+v", my)
	}
	if _, err := NewAddonCredentials("shop", "mongo", "h", 1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad kind: %v", err)
	}
}

func TestAddonDBName(t *testing.T) {
	if got := addonDBName("my-shop"); got != "acornfox_my_shop" {
		t.Fatalf("hyphen mapping: %q", got)
	}
	long := "a" + strings.Repeat("b", 38) + "c" // 40 chars, the longest valid app name
	n := addonDBName(long)
	if len(n) != mysqlMaxUser || !strings.HasPrefix(n, "acornfox_") {
		t.Fatalf("long name: %q (%d)", n, len(n))
	}
	if addonDBName(long) != n || addonDBName(long[:39]+"d") == n {
		t.Fatalf("long names must be deterministic and distinct")
	}
}
