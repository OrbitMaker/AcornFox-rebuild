package healthcheck

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
	webhookprovider "github.com/open-card/open-card/internal/providers/notification/webhook"
)

const webhookProviderTestMountID = "mount_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type webhookProviderSecretResolverFake struct {
	material    contracts.BuildSecretMaterial
	resolveErr  error
	revokeErr   error
	blockRevoke bool
	trace       *[]string
	reference   domain.SecretReference
	operation   contracts.OperationContext
	revoked     contracts.OperationContext
}

func (f *webhookProviderSecretResolverFake) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{Name: "webhook-provider-test-secret", Version: "test", ContractVersion: contracts.ContractAPIVersion, Capabilities: contracts.NewCapabilitySet(contracts.CapabilitySecretResolve)}
}
func (f *webhookProviderSecretResolverFake) ResolveBuildSecret(_ context.Context, reference domain.SecretReference, operation contracts.OperationContext) (contracts.BuildSecretMaterial, error) {
	if f.trace != nil {
		*f.trace = append(*f.trace, "resolve")
	}
	f.reference, f.operation = reference, operation
	if f.resolveErr != nil {
		return contracts.BuildSecretMaterial{}, f.resolveErr
	}
	return f.material, nil
}
func (f *webhookProviderSecretResolverFake) RevokeBuildSecret(ctx context.Context, _ contracts.BuildSecretMaterial, operation contracts.OperationContext) error {
	if f.trace != nil {
		*f.trace = append(*f.trace, "revoke")
	}
	f.revoked = operation
	if f.blockRevoke {
		<-ctx.Done()
		return ctx.Err()
	}
	return f.revokeErr
}

type webhookProviderFake struct{}

func (webhookProviderFake) Metadata(context.Context) contracts.ProviderMetadata {
	return contracts.ProviderMetadata{}
}
func (webhookProviderFake) Send(context.Context, contracts.Notification, contracts.OperationContext) error {
	return nil
}
func (webhookProviderFake) Test(context.Context, contracts.OperationContext) error { return nil }

func webhookProviderConfig() WebhookConfigV1 {
	return WebhookConfigV1{Schema: webhookConfigSchema, EndpointID: "system_host_alert", URL: "https://hooks.example.test/events", SecretReference: domain.SecretReference{ID: "secret_system_webhook", Name: "webhook", Provider: "filesystem-secret", Version: "v1"}, Enabled: true, ConfiguredAt: time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)}
}

func webhookProviderFixture(t *testing.T, contents []byte, mode os.FileMode) (string, int, int, contracts.BuildSecretMaterial, func() time.Time) {
	t.Helper()
	root := t.TempDir()
	uid, gid := os.Getuid(), os.Getgid()
	now := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	path := filepath.Join(root, webhookProviderTestMountID+".secret")
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	return root, uid, gid, contracts.BuildSecretMaterial{MountID: webhookProviderTestMountID, Reference: webhookProviderConfig().SecretReference, Path: path, ExpiresAt: now.Add(time.Minute)}, func() time.Time { return now }
}

func TestWebhookProviderResolverBindsRootMaterialAndRevokesInOrder(t *testing.T) {
	config := webhookProviderConfig()
	root, uid, gid, material, clock := webhookProviderFixture(t, []byte("ignored"), 0o400)
	contents := []byte("  signing-secret\n")
	operation := contracts.OperationContext{IdempotencyKey: "host-alert-attempt", Actor: "healthcheck"}
	trace := []string{}
	secrets := &webhookProviderSecretResolverFake{material: material, trace: &trace}
	var got webhookprovider.Config
	resolver, err := NewTaskWebhookProviderResolver(secrets, root, uid, gid, func(value webhookprovider.Config) (contracts.NotificationProvider, error) {
		trace = append(trace, "factory")
		got = value
		return webhookProviderFake{}, nil
	}, func(path string) ([]byte, error) {
		trace = append(trace, "read")
		if path != material.Path {
			t.Fatalf("path=%q", path)
		}
		return contents, nil
	}, clock, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := resolver.ResolveWebhookNotificationProvider(context.Background(), config, operation)
	if err != nil || provider == nil {
		t.Fatalf("provider=%v err=%v", provider, err)
	}
	if want := []string{"resolve", "read", "factory", "revoke"}; !reflect.DeepEqual(trace, want) {
		t.Fatalf("trace=%v want=%v", trace, want)
	}
	if secrets.reference != config.SecretReference || secrets.operation != operation {
		t.Fatalf("resolve reference=%+v operation=%+v", secrets.reference, secrets.operation)
	}
	if got.Endpoint != config.URL || got.Secret != "signing-secret" || got.RetryDelays == nil || len(got.RetryDelays) != 0 || got.AllowLoopbackFixture || got.LookupIP != nil {
		t.Fatalf("provider config=%+v", got)
	}
	if secrets.revoked.IdempotencyKey != operation.IdempotencyKey+":revoke" || secrets.revoked.Actor != operation.Actor || secrets.revoked.Deadline.IsZero() {
		t.Fatalf("revoke=%+v", secrets.revoked)
	}
	for _, value := range contents {
		if value != 0 {
			t.Fatalf("source secret bytes were not wiped: %q", contents)
		}
	}
}

func TestWebhookProviderResolverRejectsRootsAndMaterials(t *testing.T) {
	config := webhookProviderConfig()
	root, uid, gid, material, clock := webhookProviderFixture(t, []byte("secret"), 0o400)
	for _, tc := range []struct {
		name   string
		mutate func(*contracts.BuildSecretMaterial)
	}{
		{name: "bad mount", mutate: func(m *contracts.BuildSecretMaterial) { m.MountID = "mount_bad" }},
		{name: "wrong path", mutate: func(m *contracts.BuildSecretMaterial) { m.Path = filepath.Join(root, "other.secret") }},
		{name: "zero expiry", mutate: func(m *contracts.BuildSecretMaterial) { m.ExpiresAt = time.Time{} }},
		{name: "non UTC expiry", mutate: func(m *contracts.BuildSecretMaterial) { m.ExpiresAt = time.Now() }},
		{name: "expired", mutate: func(m *contracts.BuildSecretMaterial) { m.ExpiresAt = clock().Add(-time.Second) }},
		{name: "mismatched reference", mutate: func(m *contracts.BuildSecretMaterial) { m.Reference.Name = "different" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := material
			tc.mutate(&bad)
			secrets := &webhookProviderSecretResolverFake{material: bad}
			resolver, err := NewTaskWebhookProviderResolver(secrets, root, uid, gid, nil, nil, clock, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			if provider, err := resolver.ResolveWebhookNotificationProvider(context.Background(), config, contracts.OperationContext{IdempotencyKey: "resolve"}); !errors.Is(err, ErrWebhookProviderResolution) || provider != nil {
				t.Fatalf("provider=%v err=%v", provider, err)
			}
			if secrets.revoked.Deadline.IsZero() {
				t.Fatal("resolved material was not revoked")
			}
		})
	}
	if _, err := NewTaskWebhookProviderResolver(&webhookProviderSecretResolverFake{}, root, uid+1, gid, nil, nil, clock, false, nil); !errors.Is(err, ErrWebhookProviderResolution) {
		t.Fatalf("wrong root owner err=%v", err)
	}
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTaskWebhookProviderResolver(&webhookProviderSecretResolverFake{}, root, uid, gid, nil, nil, clock, false, nil); !errors.Is(err, ErrWebhookProviderResolution) {
		t.Fatalf("writable root err=%v", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	link := root + "-link"
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTaskWebhookProviderResolver(&webhookProviderSecretResolverFake{}, link, uid, gid, nil, nil, clock, false, nil); !errors.Is(err, ErrWebhookProviderResolution) {
		t.Fatalf("symlink root err=%v", err)
	}
	if _, err := NewProductionWebhookProviderResolver(nil, root); !errors.Is(err, ErrWebhookProviderResolution) {
		t.Fatalf("nil production deps err=%v", err)
	}
}

func TestWebhookProviderSecretReaderRejectsUnsafeFiles(t *testing.T) {
	root, uid, gid, material, _ := webhookProviderFixture(t, []byte("secret"), 0o400)
	handle, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	if _, err := readWebhookProviderSecretFromRoot(handle, filepath.Base(material.Path), uid, gid); err != nil {
		t.Fatalf("valid secret: %v", err)
	}
	for _, tc := range []struct {
		name    string
		prepare func(string)
	}{
		{name: "symlink", prepare: func(path string) { _ = os.Remove(path); _ = os.Symlink("/dev/null", path) }},
		{name: "wrong mode", prepare: func(path string) { _ = os.Chmod(path, 0o640) }},
		{name: "hardlink", prepare: func(path string) { _ = os.Link(path, path+".other") }},
		{name: "oversize", prepare: func(path string) {
			_ = os.Chmod(path, 0o600)
			_ = os.WriteFile(path, make([]byte, maxWebhookProviderSecretBytes+1), 0o400)
			_ = os.Chmod(path, 0o400)
		}},
		{name: "empty", prepare: func(path string) {
			_ = os.Chmod(path, 0o600)
			_ = os.WriteFile(path, nil, 0o400)
			_ = os.Chmod(path, 0o400)
		}},
		{name: "fifo", prepare: func(path string) { _ = os.Remove(path); _ = syscall.Mkfifo(path, 0o400) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subroot, subUID, subGID, subMaterial, _ := webhookProviderFixture(t, []byte("secret"), 0o400)
			subHandle, err := os.OpenRoot(subroot)
			if err != nil {
				t.Fatal(err)
			}
			defer subHandle.Close()
			path := subMaterial.Path
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("secret"), 0o400); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o400); err != nil {
				t.Fatal(err)
			}
			tc.prepare(path)
			if _, err := readWebhookProviderSecretFromRoot(subHandle, filepath.Base(path), subUID, subGID); !errors.Is(err, ErrWebhookProviderResolution) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	wrongOwner := syntheticWebhookFileInfo{mode: 0o400, size: 6, stat: syscall.Stat_t{Uid: uint32(uid + 1), Gid: uint32(gid), Nlink: 1}}
	if validWebhookProviderSecretInfo(wrongOwner, uid, gid) {
		t.Fatal("synthetic wrong owner accepted")
	}
	special := syntheticWebhookFileInfo{mode: os.ModeNamedPipe | 0o400, size: 6, stat: syscall.Stat_t{Uid: uint32(uid), Gid: uint32(gid), Nlink: 1}}
	if validWebhookProviderSecretInfo(special, uid, gid) {
		t.Fatal("synthetic special file accepted")
	}
	multipleLinks := syntheticWebhookFileInfo{mode: 0o400, size: 6, stat: syscall.Stat_t{Uid: uint32(uid), Gid: uint32(gid), Nlink: 2}}
	if validWebhookProviderSecretInfo(multipleLinks, uid, gid) {
		t.Fatal("synthetic multiple links accepted")
	}
}

func TestWebhookProviderResolverRejectsMaterialRootReplacementAfterRead(t *testing.T) {
	config := webhookProviderConfig()
	root, uid, gid, material, clock := webhookProviderFixture(t, []byte("secret"), 0o400)
	replaced := root + "-replaced"
	t.Cleanup(func() { _ = os.RemoveAll(replaced) })
	secrets := &webhookProviderSecretResolverFake{material: material}
	resolver, err := NewTaskWebhookProviderResolver(secrets, root, uid, gid, func(webhookprovider.Config) (contracts.NotificationProvider, error) {
		return webhookProviderFake{}, nil
	}, func(string) ([]byte, error) {
		if err := os.Rename(root, replaced); err != nil {
			return nil, err
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			return nil, err
		}
		return []byte("secret"), nil
	}, clock, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if provider, err := resolver.ResolveWebhookNotificationProvider(context.Background(), config, contracts.OperationContext{IdempotencyKey: "root-replacement"}); provider != nil || !errors.Is(err, ErrWebhookProviderResolution) {
		t.Fatalf("provider=%v err=%v", provider, err)
	}
	if secrets.revoked.Deadline.IsZero() {
		t.Fatal("replaced-root material was not revoked")
	}
}

func TestWebhookProviderResolverPinnedRootRejectsSymlinkSwapAndClose(t *testing.T) {
	config := webhookProviderConfig()
	root, uid, gid, material, clock := webhookProviderFixture(t, []byte("secret"), 0o400)
	secrets := &webhookProviderSecretResolverFake{material: material}
	resolver, err := NewTaskWebhookProviderResolver(secrets, root, uid, gid, func(webhookprovider.Config) (contracts.NotificationProvider, error) {
		return webhookProviderFake{}, nil
	}, nil, clock, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	replaced := root + "-pinned"
	t.Cleanup(func() { _ = os.RemoveAll(replaced) })
	if err := os.Rename(root, replaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replaced, root); err != nil {
		t.Fatal(err)
	}
	if provider, err := resolver.ResolveWebhookNotificationProvider(context.Background(), config, contracts.OperationContext{IdempotencyKey: "symlink-swap"}); provider != nil || !errors.Is(err, ErrWebhookProviderResolution) {
		t.Fatalf("provider=%v err=%v", provider, err)
	}
	if err := resolver.Close(); err != nil {
		t.Fatal(err)
	}
	if err := resolver.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveWebhookNotificationProvider(context.Background(), config, contracts.OperationContext{IdempotencyKey: "after-close"}); !errors.Is(err, ErrWebhookProviderResolution) {
		t.Fatalf("after close err=%v", err)
	}
}

func TestWebhookProviderMaterialClockMustBeUTC(t *testing.T) {
	root, _, _, material, _ := webhookProviderFixture(t, []byte("secret"), 0o400)
	if validWebhookProviderMaterial(material, root, func() time.Time { return time.Date(2026, 8, 31, 16, 0, 0, 0, time.FixedZone("local", 8*60*60)) }) {
		t.Fatal("local timezone clock was accepted")
	}
}

func TestWebhookProviderResolverRedactsAndBoundsCleanup(t *testing.T) {
	config := webhookProviderConfig()
	root, uid, gid, material, clock := webhookProviderFixture(t, []byte("secret"), 0o400)
	secretPath, secretValue := material.Path, "outbound-signing-secret"
	for _, tc := range []struct {
		name                   string
		resolve, read, factory error
	}{
		{name: "resolver", resolve: fmt.Errorf("url=%s secret=%s path=%s", config.URL, secretValue, secretPath)},
		{name: "reader", read: fmt.Errorf("url=%s secret=%s path=%s", config.URL, secretValue, secretPath)},
		{name: "factory", factory: fmt.Errorf("url=%s secret=%s path=%s", config.URL, secretValue, secretPath)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secrets := &webhookProviderSecretResolverFake{material: material, resolveErr: tc.resolve}
			resolver, err := NewTaskWebhookProviderResolver(secrets, root, uid, gid, func(webhookprovider.Config) (contracts.NotificationProvider, error) { return nil, tc.factory }, func(string) ([]byte, error) { return []byte(secretValue), tc.read }, clock, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = resolver.ResolveWebhookNotificationProvider(context.Background(), config, contracts.OperationContext{IdempotencyKey: "resolve"})
			if !errors.Is(err, ErrWebhookProviderResolution) {
				t.Fatalf("err=%v", err)
			}
			for _, leak := range []string{config.URL, secretValue, secretPath, "url="} {
				if strings.Contains(err.Error(), leak) || strings.Contains(fmt.Sprint(err), leak) || strings.Contains(fmt.Sprintf("%#v", err), leak) {
					t.Fatalf("error leaked %q: %v", leak, err)
				}
			}
		})
	}
	secrets := &webhookProviderSecretResolverFake{material: material, revokeErr: errors.New("secret=" + secretValue)}
	resolver, err := NewTaskWebhookProviderResolver(secrets, root, uid, gid, func(webhookprovider.Config) (contracts.NotificationProvider, error) {
		return webhookProviderFake{}, nil
	}, nil, clock, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if provider, err := resolver.ResolveWebhookNotificationProvider(context.Background(), config, contracts.OperationContext{IdempotencyKey: "revoke-error"}); provider != nil || !errors.Is(err, ErrWebhookProviderResolution) {
		t.Fatalf("provider=%v err=%v", provider, err)
	}
	secrets = &webhookProviderSecretResolverFake{material: material, blockRevoke: true}
	resolver, err = NewTaskWebhookProviderResolver(secrets, root, uid, gid, func(webhookprovider.Config) (contracts.NotificationProvider, error) {
		return webhookProviderFake{}, nil
	}, nil, clock, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := resolver.ResolveWebhookNotificationProvider(context.Background(), config, contracts.OperationContext{IdempotencyKey: "revoke-timeout"}); !errors.Is(err, ErrWebhookProviderResolution) {
		t.Fatalf("timeout err=%v", err)
	}
	if elapsed := time.Since(started); elapsed < webhookProviderRevokeTimeout || elapsed > webhookProviderRevokeTimeout+time.Second || secrets.revoked.Deadline.IsZero() {
		t.Fatalf("cleanup elapsed=%v revoke=%+v", elapsed, secrets.revoked)
	}
	cancelCtx, cancel := context.WithCancel(context.Background())
	resolver, err = NewTaskWebhookProviderResolver(&webhookProviderSecretResolverFake{material: material, revokeErr: errors.New("cleanup")}, root, uid, gid, func(webhookprovider.Config) (contracts.NotificationProvider, error) {
		cancel()
		return webhookProviderFake{}, nil
	}, nil, clock, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveWebhookNotificationProvider(cancelCtx, config, contracts.OperationContext{IdempotencyKey: "cancel"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation precedence err=%v", err)
	}
}

func TestTaskWebhookProviderResolverSignsLoopbackAndRejectsPrivateAnswer(t *testing.T) {
	const secret = "task-loopback-signing-secret"
	root, uid, gid, material, clock := webhookProviderFixture(t, []byte(secret), 0o400)
	var body []byte
	var header http.Header
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ = io.ReadAll(request.Body)
		header = request.Header.Clone()
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	config := webhookProviderConfig()
	config.URL = "https://opencard-webhook-fixture.test/events"
	secrets := &webhookProviderSecretResolverFake{material: material}
	resolver, err := NewTaskWebhookProviderResolver(secrets, root, uid, gid, func(value webhookprovider.Config) (contracts.NotificationProvider, error) {
		if value.Endpoint != config.URL || !value.AllowLoopbackFixture || value.Secret != secret || value.RetryDelays == nil || len(value.RetryDelays) != 0 {
			t.Fatalf("config=%+v", value)
		}
		return webhookprovider.New(webhookprovider.Config{Endpoint: server.URL, Secret: value.Secret, RetryDelays: make([]time.Duration, 0), AllowLoopbackFixture: true})
	}, nil, clock, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := resolver.ResolveWebhookNotificationProvider(context.Background(), config, contracts.OperationContext{IdempotencyKey: "resolve"})
	if err != nil {
		t.Fatal(err)
	}
	notification := contracts.Notification{EventID: "event_loopback", EventType: "system.host_health.occurrence", Payload: map[string]any{"state": "degraded"}, OccurredAt: time.Unix(1_700_000_000, 0).UTC()}
	if err := provider.Send(context.Background(), notification, contracts.OperationContext{IdempotencyKey: "send"}); err != nil {
		t.Fatal(err)
	}
	if err := foundation.VerifyWebhookSignature(secret, notification.OccurredAt.Unix(), notification.EventID.String(), body, header.Get("X-Open-Card-Signature"), notification.OccurredAt); err != nil {
		t.Fatalf("signature: %v", err)
	}
	config.URL = "https://public.example.test/events"
	secrets = &webhookProviderSecretResolverFake{material: material}
	resolver, err = NewTaskWebhookProviderResolver(secrets, root, uid, gid, nil, nil, clock, false, func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err = resolver.ResolveWebhookNotificationProvider(context.Background(), config, contracts.OperationContext{IdempotencyKey: "resolve-private"})
	if err != nil {
		t.Fatal(err)
	}
	err = provider.Send(context.Background(), notification, contracts.OperationContext{IdempotencyKey: "send-private"})
	var providerErr *contracts.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != contracts.ErrForbidden {
		t.Fatalf("private answer accepted: %v", err)
	}
}

type syntheticWebhookFileInfo struct {
	mode os.FileMode
	size int64
	stat syscall.Stat_t
}

func (i syntheticWebhookFileInfo) Name() string       { return "secret" }
func (i syntheticWebhookFileInfo) Size() int64        { return i.size }
func (i syntheticWebhookFileInfo) Mode() os.FileMode  { return i.mode }
func (i syntheticWebhookFileInfo) ModTime() time.Time { return time.Time{} }
func (i syntheticWebhookFileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i syntheticWebhookFileInfo) Sys() any           { return &i.stat }
