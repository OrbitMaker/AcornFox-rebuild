package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/acornfoxsetup"
)

var runtimeTestResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

const runtimeTestOrigin = "https://console.example.com"

func runtimeConfigFixture(t *testing.T) (*acornFoxRuntimeConfig, acornFoxProductionPreparedFixture, AcornFoxBuildIdentityV1) {
	t.Helper()
	cp, p := newAcornFoxControlPlanePrepared(t, &acornFoxControlPlaneLedgerFake{}, &acornFoxControlPlaneProvisionerFake{})
	if _, err := cp.migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	a, _ := AcornFoxRepoActivationID(p.binding)
	info, err := os.Lstat(filepath.Join(p.host, "opt/acornfox/activations", a, "database.env"))
	if err != nil {
		t.Fatal(err)
	}
	p.owners.set(info, acornFoxInstallPrincipal{})
	s := newAcornFoxRuntimeConfig(p.layout)
	s.ownership = p.owners.edge()
	s.self = acornFoxSelfVerifier{path: filepath.Join(p.host, AcornFoxUpgradeHelperPath), uid: os.Getuid(), gid: os.Getgid()}
	s.now = func() time.Time { return time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC) }
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		// Portable tests cover the state machine only. The Linux-only test below
		// exercises the real syscall and a competing target without this seam.
		s.rename = func(parent *os.File, old, next string) error {
			target := filepath.Join(parent.Name(), next)
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				return os.ErrExist
			}
			return os.Rename(filepath.Join(parent.Name(), old), target)
		}
	}
	return s, p, cp.expectedIdentity
}
func runtimeRun(s *acornFoxRuntimeConfig, id AcornFoxBuildIdentityV1) (AcornFoxRuntimeConfigReceiptV1, error) {
	return s.run(context.Background(), id, runtimeTestOrigin, runtimeTestResolvers, false)
}
func runtimeIntentForTest(t *testing.T, p acornFoxProductionPreparedFixture) (acornFoxRuntimeIntent, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(p.state, acornFoxRuntimeIntentName))
	if err != nil {
		t.Fatal(err)
	}
	i, err := parseAcornFoxRuntimeIntent(raw)
	if err != nil {
		t.Fatal(err)
	}
	return i, raw
}
func runtimeScopeForTest(t *testing.T, p acornFoxProductionPreparedFixture) ([]SubstrateEntry, error) {
	t.Helper()
	lock, err := p.store.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	a, _, err := acornFoxRuntimeAuthority(context.Background(), p.store, p.store.hostRoot)
	if err != nil {
		return nil, err
	}
	return acornFoxRuntimeConfigScope(p.store.hostRoot, p.store, a)
}
func TestAcornFoxRuntimeConfigReplayCrashPrefixes(t *testing.T) {
	for _, point := range []string{"intent", "file-prefix", "file", "directory-ready", "published", "complete"} {
		t.Run(point, func(t *testing.T) {
			s, p, id := runtimeConfigFixture(t)
			stopped := false
			if point != "complete" {
				s.step = func(got string) error {
					if got == point && !stopped {
						stopped = true
						return errors.New("injected crash")
					}
					return nil
				}
			}
			first, err := runtimeRun(s, id)
			if point != "complete" && err == nil {
				t.Fatal("crash not observed")
			}
			if point == "complete" && (err != nil || first.Validate() != nil) {
				t.Fatalf("complete: %v", err)
			}
			intent, raw := runtimeIntentForTest(t, p)
			if got, err := runtimeScopeForTest(t, p); err != nil {
				t.Fatalf("prefix scope: %v", err)
			} else if point == "intent" && len(got) != 0 {
				t.Fatal("intent-only has host entries")
			}
			// Entropy must never be consumed while resuming a persisted intent.
			s.random = bytes.NewReader(nil)
			s.now = func() time.Time { panic("regenerated timestamp") }
			s.step = func(string) error { return nil }
			second, err := s.run(context.Background(), id, "", nil, true)
			if err != nil || second != intent.receipt(raw) {
				t.Fatalf("recovery failed: %v", err)
			}
			after, err := os.ReadFile(filepath.Join(p.state, acornFoxRuntimeIntentName))
			if err != nil || !bytes.Equal(after, raw) {
				t.Fatal("intent changed")
			}
			for _, f := range intent.Files {
				path := filepath.Join(p.host, strings.TrimPrefix(f.Path, "/"))
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, f.Data) {
					t.Fatal("published bytes differ")
				}
				info, err := os.Lstat(path)
				if err != nil || uint32(info.Mode().Perm()) != f.Mode {
					t.Fatal("published mode differs")
				}
			}
			entries, err := runtimeScopeForTest(t, p)
			if err != nil || len(entries) != 8 {
				t.Fatalf("final scope: %v count=%d", err, len(entries))
			}
			if _, err := os.Lstat(filepath.Join(p.host, acornFoxRuntimeTemporary(raw))); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("temporary survived publish")
			}
			third, err := runtimeRun(s, id)
			if err != nil || third != second {
				t.Fatalf("idempotent configure: %v", err)
			}
			if _, err := s.run(context.Background(), id, "https://different.example.com", runtimeTestResolvers, false); err == nil {
				t.Fatal("origin silently rebound")
			}
		})
	}
}
func TestAcornFoxRuntimeConfigNoIntentRecoverIsReadOnly(t *testing.T) {
	s, p, id := runtimeConfigFixture(t)
	s.random = bytes.NewReader(nil)
	if _, err := s.run(context.Background(), id, "", nil, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(p.state, acornFoxRuntimeIntentName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovery created intent")
	}
	entries, err := runtimeScopeForTest(t, p)
	if err != nil || len(entries) != 0 {
		t.Fatal("no-intent scope")
	}
}
func TestAcornFoxRuntimeConfigForeignTargetNeverOverwritten(t *testing.T) {
	for _, beforeIntent := range []bool{true, false} {
		t.Run(fmt.Sprint(beforeIntent), func(t *testing.T) {
			s, p, id := runtimeConfigFixture(t)
			if !beforeIntent {
				s.step = func(point string) error {
					if point == "intent" {
						return errors.New("crash")
					}
					return nil
				}
				if _, err := runtimeRun(s, id); err == nil {
					t.Fatal("fault")
				}
				s.step = func(string) error { return nil }
			}
			target := filepath.Join(p.host, acornFoxRuntimeTarget)
			if err := os.Mkdir(target, 0755); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(target, "foreign")
			if err := os.WriteFile(sentinel, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := runtimeRun(s, id); err == nil {
				t.Fatal("foreign target accepted")
			}
			got, err := os.ReadFile(sentinel)
			if err != nil || string(got) != "untouched" {
				t.Fatal("foreign target overwritten")
			}
		})
	}
}
func TestAcornFoxRuntimeConfigRejectsCorruptStateAndFiles(t *testing.T) {
	cases := map[string]func(*testing.T, acornFoxProductionPreparedFixture, acornFoxRuntimeIntent, []byte){
		"intent-empty": func(t *testing.T, p acornFoxProductionPreparedFixture, _ acornFoxRuntimeIntent, _ []byte) {
			runtimeOverwrite(t, filepath.Join(p.state, acornFoxRuntimeIntentName), nil, 0600)
		},
		"intent-json": func(t *testing.T, p acornFoxProductionPreparedFixture, _ acornFoxRuntimeIntent, _ []byte) {
			runtimeOverwrite(t, filepath.Join(p.state, acornFoxRuntimeIntentName), []byte(`{"unknown":true}`), 0600)
		},
		"intent-key": func(t *testing.T, p acornFoxProductionPreparedFixture, i acornFoxRuntimeIntent, _ []byte) {
			i.Files[4].Data = []byte("wrong key")
			raw, _ := json.Marshal(i)
			runtimeOverwrite(t, filepath.Join(p.state, acornFoxRuntimeIntentName), raw, 0600)
		},
		"intent-mode": func(t *testing.T, p acornFoxProductionPreparedFixture, _ acornFoxRuntimeIntent, _ []byte) {
			if err := os.Chmod(filepath.Join(p.state, acornFoxRuntimeIntentName), 0644); err != nil {
				t.Fatal(err)
			}
		},
		"intent-extra": func(t *testing.T, p acornFoxProductionPreparedFixture, i acornFoxRuntimeIntent, _ []byte) {
			i.Files = append(i.Files, i.Files[0])
			raw, _ := json.Marshal(i)
			runtimeOverwrite(t, filepath.Join(p.state, acornFoxRuntimeIntentName), raw, 0600)
		},
		"temporary-foreign": func(t *testing.T, p acornFoxProductionPreparedFixture, _ acornFoxRuntimeIntent, raw []byte) {
			runtimeOverwrite(t, filepath.Join(p.host, acornFoxRuntimeTemporary(raw), "unknown"), []byte("foreign"), 0600)
		},
		"temporary-prefix": func(t *testing.T, p acornFoxProductionPreparedFixture, _ acornFoxRuntimeIntent, raw []byte) {
			runtimeOverwrite(t, filepath.Join(p.host, acornFoxRuntimeTemporary(raw), "server.env"), []byte("bad"), 0600)
		},
		"temporary-mode": func(t *testing.T, p acornFoxProductionPreparedFixture, _ acornFoxRuntimeIntent, raw []byte) {
			if err := os.Chmod(filepath.Join(p.host, acornFoxRuntimeTemporary(raw), "server.env"), 0666); err != nil {
				t.Fatal(err)
			}
		},
		"temporary-owner": func(t *testing.T, p acornFoxProductionPreparedFixture, _ acornFoxRuntimeIntent, raw []byte) {
			info, err := os.Lstat(filepath.Join(p.host, acornFoxRuntimeTemporary(raw), "server.env"))
			if err != nil {
				t.Fatal(err)
			}
			p.owners.set(info, acornFoxInstallPrincipal{uid: 1002, gid: 1002})
		},
		"temporary-symlink": func(t *testing.T, p acornFoxProductionPreparedFixture, _ acornFoxRuntimeIntent, raw []byte) {
			path := filepath.Join(p.host, acornFoxRuntimeTemporary(raw), "server.env")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/tmp/foreign", path); err != nil {
				t.Fatal(err)
			}
		},
		"other-temporary": func(t *testing.T, p acornFoxProductionPreparedFixture, _ acornFoxRuntimeIntent, _ []byte) {
			if err := os.Mkdir(filepath.Join(p.host, acornFoxRuntimeParent, ".runtime-other"), 0700); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			s, p, id := runtimeConfigFixture(t)
			s.step = func(point string) error {
				if point == "file-prefix" {
					return errors.New("crash")
				}
				return nil
			}
			if _, err := runtimeRun(s, id); err == nil {
				t.Fatal("fault")
			}
			i, raw := runtimeIntentForTest(t, p)
			corrupt(t, p, i, raw)
			s.step = func(string) error { return nil }
			if _, err := s.run(context.Background(), id, "", nil, true); err == nil {
				t.Fatal("corruption accepted")
			}
			if _, err := runtimeScopeForTest(t, p); err == nil {
				t.Fatal("corrupt scope accepted")
			}
		})
	}
}
func runtimeOverwrite(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
}
func TestAcornFoxRuntimeConfigCompleteIsFailClosed(t *testing.T) {
	for _, kind := range []string{"missing-file", "temporary", "wrong-receipt", "missing-intent"} {
		t.Run(kind, func(t *testing.T) {
			s, p, id := runtimeConfigFixture(t)
			if _, err := runtimeRun(s, id); err != nil {
				t.Fatal(err)
			}
			_, raw := runtimeIntentForTest(t, p)
			switch kind {
			case "missing-file":
				if err := os.Remove(filepath.Join(p.host, acornFoxRuntimeTarget, "agent.key")); err != nil {
					t.Fatal(err)
				}
			case "temporary":
				if err := os.Mkdir(filepath.Join(p.host, acornFoxRuntimeTemporary(raw)), 0700); err != nil {
					t.Fatal(err)
				}
			case "wrong-receipt":
				runtimeOverwrite(t, filepath.Join(p.state, acornFoxRuntimeReceiptName), []byte(`{}`), 0600)
			case "missing-intent":
				if err := os.Remove(filepath.Join(p.state, acornFoxRuntimeIntentName)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.run(context.Background(), id, "", nil, true); err == nil {
				t.Fatal("completed evidence damage accepted")
			}
			if _, err := runtimeScopeForTest(t, p); err == nil {
				t.Fatal("damaged final scope accepted")
			}
		})
	}
}
func TestAcornFoxRuntimeConfigAuthorityAndLock(t *testing.T) {
	for _, kind := range []string{"wrong-source", "wrong-self", "wrong-current", "wrong-c1-env", "locked"} {
		t.Run(kind, func(t *testing.T) {
			s, p, id := runtimeConfigFixture(t)
			switch kind {
			case "wrong-source":
				id.SourceCommit = strings.Repeat("b", 40)
			case "wrong-self":
				s.self.path = p.sentinel
			case "wrong-current":
				path := filepath.Join(p.host, "opt/acornfox/current")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("releases/foreign", path); err != nil {
					t.Fatal(err)
				}
			case "wrong-c1-env":
				runtimeOverwrite(t, filepath.Join(p.state, acornFoxControlPlaneStateEnv), []byte("changed"), 0600)
			case "locked":
				lock, err := p.store.Acquire(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Release()
			}
			if _, err := runtimeRun(s, id); err == nil {
				t.Fatal("invalid authority accepted")
			}
			if _, err := os.Lstat(filepath.Join(p.state, acornFoxRuntimeIntentName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid authority created intent")
			}
		})
	}
}
func TestAcornFoxRuntimeIntentWireValidationAndRedaction(t *testing.T) {
	inputs := acornfoxsetup.Inputs{Origin: runtimeTestOrigin, Version: "1.2.3", ResolverEndpoints: runtimeTestResolvers, Now: time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)}
	b, err := acornfoxsetup.Generate(inputs, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	i := acornFoxRuntimeIntent{SchemaVersion: 1, BindingSHA256: strings.Repeat("a", 64), ReleaseID: "release-1.2.3", SourceCommit: strings.Repeat("b", 40), Inputs: inputs}
	for _, f := range b.Files {
		i.Files = append(i.Files, acornFoxRuntimeFileWire{f.Path, f.Mode, f.Owner, f.Group, f.Data})
	}
	raw, err := json.Marshal(i)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseAcornFoxRuntimeIntent(raw)
	if err != nil || !bytes.Equal(parsed.Files[4].Data, i.Files[4].Data) {
		t.Fatal("private intent lost key bytes")
	}
	r := i.receipt(raw)
	public, err := MarshalAcornFoxRuntimeConfigReceiptV1(r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(public, i.Files[4].Data) || bytes.Contains(public, []byte("data")) || bytes.Contains(public, []byte("inputs")) {
		t.Fatal("public receipt includes private payload")
	}
	for _, v := range []any{i, i.Files, i.Files[4]} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if strings.Contains(fmt.Sprintf(verb, v), "PRIVATE KEY") {
				t.Fatal("fmt leaked private key")
			}
		}
	}
	for _, bad := range [][]byte{append(raw, '\n'), append([]byte(`{"extra":true,`), raw[1:]...), bytes.Repeat([]byte("x"), acornFoxRuntimeMaxIntent+1)} {
		if _, err := parseAcornFoxRuntimeIntent(bad); err == nil {
			t.Fatal("noncanonical intent accepted")
		}
	}
}

func TestAcornFoxRuntimeConfigMetadataCrashPrefixes(t *testing.T) {
	for _, name := range []string{acornFoxRuntimeIntentName, acornFoxRuntimeReceiptName} {
		for _, phase := range []string{"metadata-temp:", "metadata-linked:"} {
			t.Run(phase+name, func(t *testing.T) {
				s, p, id := runtimeConfigFixture(t)
				point := phase + name
				s.step = func(got string) error {
					if got == point {
						return errors.New("crash before metadata cleanup")
					}
					return nil
				}
				if _, err := runtimeRun(s, id); err == nil {
					t.Fatal("crash not observed")
				}
				raw, err := acornFoxRuntimeReadState(p.store, acornFoxRuntimeIntentName)
				if err != nil {
					t.Fatal(err)
				}
				intent, err := parseAcornFoxRuntimeIntent(raw)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := runtimeScopeForTest(t, p); err != nil {
					t.Fatalf("metadata prefix scope: %v", err)
				}
				s.step = func(string) error { return nil }
				s.random = bytes.NewReader(nil)
				s.now = func() time.Time { panic("metadata recovery regenerated keys") }
				got, err := s.run(context.Background(), id, "", nil, true)
				if err != nil || got != intent.receipt(raw) {
					t.Fatalf("metadata prefix recovery: %v", err)
				}
				for _, n := range []string{acornFoxRuntimeIntentName, acornFoxRuntimeReceiptName} {
					info, err := os.Lstat(filepath.Join(p.state, n))
					if err != nil || acornFoxRepoNlink(info) != 1 {
						t.Fatal("final metadata is not single-link")
					}
					if _, err := os.Lstat(filepath.Join(p.state, acornFoxRuntimeMetadataTemporary(n))); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("known metadata temporary survived")
					}
				}
			})
		}
	}
}
func TestAcornFoxRuntimeConfigMetadataForeignPrefixPreserved(t *testing.T) {
	for _, kind := range []string{"partial-temporary", "different-inode-pair"} {
		t.Run(kind, func(t *testing.T) {
			s, p, id := runtimeConfigFixture(t)
			temp := filepath.Join(p.state, acornFoxRuntimeMetadataTemporary(acornFoxRuntimeIntentName))
			foreign := []byte("partial private intent")
			if kind == "different-inode-pair" {
				s.step = func(point string) error {
					if point == "intent" {
						return errors.New("crash")
					}
					return nil
				}
				if _, err := runtimeRun(s, id); err == nil {
					t.Fatal("fault")
				}
				var err error
				foreign, err = os.ReadFile(filepath.Join(p.state, acornFoxRuntimeIntentName))
				if err != nil {
					t.Fatal(err)
				}
			}
			runtimeOverwrite(t, temp, foreign, 0600)
			s.step = func(string) error { return nil }
			s.random = bytes.NewReader(nil)
			s.now = func() time.Time { panic("foreign intent regenerated") }
			if _, err := runtimeRun(s, id); err == nil {
				t.Fatal("unknown metadata accepted")
			}
			if _, err := s.run(context.Background(), id, "", nil, true); err == nil {
				t.Fatal("unknown metadata recovered")
			}
			after, err := os.ReadFile(temp)
			if err != nil || !bytes.Equal(after, foreign) {
				t.Fatal("unknown metadata removed or changed")
			}
		})
	}
}

func TestAcornFoxRuntimeConfigMetadataWriteBeforeSync(t *testing.T) {
	for _, name := range []string{acornFoxRuntimeIntentName, acornFoxRuntimeReceiptName} {
		t.Run(name, func(t *testing.T) {
			s, p, id := runtimeConfigFixture(t)
			s.step = func(point string) error {
				if point == "metadata-written:"+name {
					return errors.New("crash after write before sync")
				}
				return nil
			}
			if _, err := runtimeRun(s, id); err == nil {
				t.Fatal("write-before-sync fault not observed")
			}
			if _, err := os.Lstat(filepath.Join(p.state, name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("metadata linked before data sync")
			}
			s.step = func(string) error { return nil }
			s.random = bytes.NewReader(nil)
			s.now = func() time.Time { panic("regenerated intent") }
			syncAttempted := false
			s.syncMetadata = func(f *os.File) error {
				if filepath.Base(f.Name()) == acornFoxRuntimeMetadataTemporary(name) {
					syncAttempted = true
					return errors.New("injected recovery file sync failure")
				}
				return f.Sync()
			}
			if _, err := s.run(context.Background(), id, "", nil, true); err == nil || !syncAttempted {
				t.Fatal("recovery did not require data sync")
			}
			if _, err := os.Lstat(filepath.Join(p.state, name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed data sync still published metadata")
			}
			if _, err := os.Lstat(filepath.Join(p.state, acornFoxRuntimeMetadataTemporary(name))); err != nil {
				t.Fatal("failed data sync removed evidence")
			}
			s.syncMetadata = func(f *os.File) error { return f.Sync() }
			if _, err := s.run(context.Background(), id, "", nil, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}
