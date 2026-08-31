package healthcheck

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	webhookprovider "github.com/open-card/open-card/internal/providers/notification/webhook"
	secretprovider "github.com/open-card/open-card/internal/providers/secret"
)

const (
	maxWebhookProviderSecretBytes = 64 << 10
	webhookProviderRevokeTimeout  = 3 * time.Second
)

var webhookProviderMountID = regexp.MustCompile(`^mount_[0-9a-f]{48}$`)

// ErrWebhookProviderResolution is the sole non-context error returned by the
// system webhook resolver. Resolver, filesystem, and provider details can
// contain endpoint or secret-material information and must not cross this
// boundary.
var ErrWebhookProviderResolution = errors.New("webhook provider resolution failed")

// WebhookNotificationProviderFactory is a task-only construction seam. It
// receives a copied signing secret in the provider configuration; callers must
// not retain or log it.
type WebhookNotificationProviderFactory func(webhookprovider.Config) (contracts.NotificationProvider, error)

// WebhookSecretReader is a task-only read seam. Production always uses the
// no-follow bounded reader below.
type WebhookSecretReader func(string) ([]byte, error)

// NewProductionWebhookProviderResolver binds the system resolver to the
// supplied root-owned material directory. Production has no loopback exception,
// custom DNS resolver, provider factory, or read seam.
func NewProductionWebhookProviderResolver(secrets *secretprovider.Provider, materialRoot string) (*SystemWebhookProviderResolver, error) {
	return newWebhookProviderResolver(secrets, materialRoot, 0, 0, nil, nil, func() time.Time { return time.Now().UTC() }, false, nil)
}

// NewTaskWebhookProviderResolver creates the same resolver with task-only
// seams. The root's expected owner is explicit; nil factory and reader select
// production implementations. Loopback and DNS injection are never available
// from the production constructor.
func NewTaskWebhookProviderResolver(secrets contracts.BuildSecretResolver, materialRoot string, uid, gid int, factory WebhookNotificationProviderFactory, readSecret WebhookSecretReader, clock func() time.Time, allowLoopbackFixture bool, lookupIP func(context.Context, string) ([]net.IPAddr, error)) (*SystemWebhookProviderResolver, error) {
	return newWebhookProviderResolver(secrets, materialRoot, uid, gid, factory, readSecret, clock, allowLoopbackFixture, lookupIP)
}

type webhookMaterialRoot struct {
	path   string
	info   os.FileInfo
	handle *os.Root
	uid    int
	gid    int
}

// SystemWebhookProviderResolver owns a pinned material-root descriptor. Call
// Close when the composition root stops; it is idempotent and makes future
// resolution fail closed.
type SystemWebhookProviderResolver struct {
	mu         sync.Mutex
	secrets    contracts.BuildSecretResolver
	root       webhookMaterialRoot
	factory    WebhookNotificationProviderFactory
	read       WebhookSecretReader
	clock      func() time.Time
	loopback   bool
	lookupIP   func(context.Context, string) ([]net.IPAddr, error)
	customRead bool
}

var _ WebhookProviderResolver = (*SystemWebhookProviderResolver)(nil)

func newWebhookProviderResolver(secrets contracts.BuildSecretResolver, materialRoot string, uid, gid int, factory WebhookNotificationProviderFactory, readSecret WebhookSecretReader, clock func() time.Time, allowLoopbackFixture bool, lookupIP func(context.Context, string) ([]net.IPAddr, error)) (*SystemWebhookProviderResolver, error) {
	if secrets == nil || clock == nil {
		return nil, ErrWebhookProviderResolution
	}
	root, err := newWebhookMaterialRoot(materialRoot, uid, gid)
	if err != nil {
		return nil, ErrWebhookProviderResolution
	}
	if factory == nil {
		factory = func(config webhookprovider.Config) (contracts.NotificationProvider, error) {
			return webhookprovider.New(config)
		}
	}
	return &SystemWebhookProviderResolver{secrets: secrets, root: root, factory: factory, read: readSecret, clock: clock, loopback: allowLoopbackFixture, lookupIP: lookupIP, customRead: readSecret != nil}, nil
}

func (r *SystemWebhookProviderResolver) ResolveWebhookNotificationProvider(ctx context.Context, config WebhookConfigV1, operation contracts.OperationContext) (provider contracts.NotificationProvider, err error) {
	if r == nil {
		return nil, ErrWebhookProviderResolution
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.secrets == nil || r.factory == nil || (r.customRead && r.read == nil) || r.clock == nil || ctx == nil || config.Validate() != nil || !config.Enabled || operation.Validate() != nil || !r.root.valid() {
		return nil, ErrWebhookProviderResolution
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	reference := config.SecretReference
	material, resolveErr := r.secrets.ResolveBuildSecret(ctx, reference, operation)
	if resolveErr != nil {
		return nil, ErrWebhookProviderResolution
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), webhookProviderRevokeTimeout)
		defer cancel()
		revokeErr := r.secrets.RevokeBuildSecret(cleanupCtx, material, webhookProviderRevokeOperation(operation, cleanupCtx))
		// Caller cancellation always wins, including cancellation that happens
		// during bounded cleanup. Cleanup can otherwise only invalidate an
		// otherwise successful provider construction.
		if callerErr := ctx.Err(); callerErr != nil {
			provider = nil
			err = callerErr
			return
		}
		if revokeErr != nil && err == nil {
			provider = nil
			err = ErrWebhookProviderResolution
		}
	}()

	if material.Reference != reference || !validWebhookProviderMaterial(material, r.root.path, r.clock) || !r.root.valid() {
		return nil, ErrWebhookProviderResolution
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var contents []byte
	var readErr error
	if r.customRead {
		contents, readErr = r.read(material.Path)
	} else {
		contents, readErr = readWebhookProviderSecretFromRoot(r.root.handle, material.MountID+".secret", r.root.uid, r.root.gid)
	}
	if readErr != nil || !r.root.valid() {
		zeroWebhookProviderBytes(contents)
		return nil, ErrWebhookProviderResolution
	}
	defer zeroWebhookProviderBytes(contents)
	if len(contents) == 0 || len(contents) > maxWebhookProviderSecretBytes {
		return nil, ErrWebhookProviderResolution
	}
	secret := string(bytes.TrimSpace(contents))
	if secret == "" {
		return nil, ErrWebhookProviderResolution
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The transient source bytes above are wiped on every path. The concrete
	// provider retains this GC-managed immutable string for as long as its caller
	// retains the provider; the dispatcher scopes use to one send, but this
	// resolver cannot enforce or zero provider-held strings.
	provider, factoryErr := r.factory(webhookprovider.Config{
		Endpoint:             config.URL,
		Secret:               secret,
		RetryDelays:          make([]time.Duration, 0),
		AllowLoopbackFixture: r.loopback,
		LookupIP:             r.lookupIP,
	})
	if factoryErr != nil || provider == nil {
		return nil, ErrWebhookProviderResolution
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return provider, nil
}

func (r *SystemWebhookProviderResolver) String() string { return "system-webhook-provider-resolver" }
func (r *SystemWebhookProviderResolver) GoString() string {
	return "healthcheck.SystemWebhookProviderResolver{}"
}

// Close releases the pinned material-root descriptor. A closed resolver cannot
// read replacement paths or resolve another provider.
func (r *SystemWebhookProviderResolver) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.root.handle == nil {
		return nil
	}
	err := r.root.handle.Close()
	r.root.handle = nil
	if err != nil {
		return ErrWebhookProviderResolution
	}
	return nil
}

func newWebhookMaterialRoot(path string, uid, gid int) (webhookMaterialRoot, error) {
	if !cleanAbsoluteWebhookSecretPath(path) {
		return webhookMaterialRoot{}, ErrWebhookProviderResolution
	}
	info, err := os.Lstat(path)
	if err != nil || !validWebhookMaterialRootInfo(info, uid, gid) {
		return webhookMaterialRoot{}, ErrWebhookProviderResolution
	}
	handle, err := os.OpenRoot(path)
	if err != nil {
		return webhookMaterialRoot{}, ErrWebhookProviderResolution
	}
	return webhookMaterialRoot{path: path, info: info, handle: handle, uid: uid, gid: gid}, nil
}

func (r webhookMaterialRoot) valid() bool {
	info, err := os.Lstat(r.path)
	return r.handle != nil && err == nil && validWebhookMaterialRootInfo(info, r.uid, r.gid) && os.SameFile(r.info, info)
}

func validWebhookProviderMaterial(material contracts.BuildSecretMaterial, root string, clock func() time.Time) bool {
	if clock == nil || !webhookProviderMountID.MatchString(material.MountID) || material.Path != filepath.Join(root, material.MountID+".secret") || !utc(material.ExpiresAt) {
		return false
	}
	now := clock()
	return utc(now) && material.ExpiresAt.After(now)
}

func webhookProviderRevokeOperation(operation contracts.OperationContext, ctx context.Context) contracts.OperationContext {
	deadline, _ := ctx.Deadline()
	return contracts.OperationContext{IdempotencyKey: operation.IdempotencyKey + ":revoke", Actor: operation.Actor, Deadline: deadline.UTC()}
}

func cleanAbsoluteWebhookSecretPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && strings.TrimSpace(path) == path
}

// readWebhookProviderSecretFromRoot uses the held root descriptor plus
// pre/post Lstat and fstat identity checks. os.Root may follow leaf symlinks on
// some platforms, so the same-owner material-root writer remains a trusted
// boundary; these checks reject observed replacement/symlink swaps rather than
// claiming a kernel-openat guarantee unavailable through os.Root.
func readWebhookProviderSecretFromRoot(root *os.Root, name string, uid, gid int) ([]byte, error) {
	if root == nil || name != filepath.Base(name) || name != webhookProviderTestableSecretName(name) {
		return nil, ErrWebhookProviderResolution
	}
	before, err := root.Lstat(name)
	if err != nil || !validWebhookProviderSecretInfo(before, uid, gid) {
		return nil, ErrWebhookProviderResolution
	}
	file, err := root.OpenFile(name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrWebhookProviderResolution
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !validWebhookProviderSecretInfo(opened, uid, gid) || !os.SameFile(before, opened) {
		return nil, ErrWebhookProviderResolution
	}
	after, err := root.Lstat(name)
	if err != nil || !validWebhookProviderSecretInfo(after, uid, gid) || !os.SameFile(before, after) {
		return nil, ErrWebhookProviderResolution
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxWebhookProviderSecretBytes+1))
	if err != nil || len(contents) == 0 || len(contents) > maxWebhookProviderSecretBytes {
		zeroWebhookProviderBytes(contents)
		return nil, ErrWebhookProviderResolution
	}
	return contents, nil
}

func webhookProviderTestableSecretName(name string) string {
	if !strings.HasSuffix(name, ".secret") || !webhookProviderMountID.MatchString(strings.TrimSuffix(name, ".secret")) {
		return ""
	}
	return name
}

func validWebhookMaterialRootInfo(info os.FileInfo, uid, gid int) bool {
	identity, ok := webhookProviderFileIdentityFrom(info)
	return ok && info.Mode()&os.ModeSymlink == 0 && !identity.regular && identity.directory && identity.uid == uid && identity.gid == gid && identity.mode.Perm()&0o022 == 0
}

func validWebhookProviderSecretInfo(info os.FileInfo, uid, gid int) bool {
	identity, ok := webhookProviderFileIdentityFrom(info)
	return ok && identity.regular && identity.uid == uid && identity.gid == gid && identity.nlink == 1 && identity.size > 0 && identity.size <= maxWebhookProviderSecretBytes && (identity.mode.Perm() == 0o400 || identity.mode.Perm() == 0o600) && identity.mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

type webhookProviderFileIdentity struct {
	mode      os.FileMode
	size      int64
	uid, gid  int
	nlink     uint64
	regular   bool
	directory bool
}

func webhookProviderFileIdentityFrom(info os.FileInfo) (webhookProviderFileIdentity, bool) {
	if info == nil {
		return webhookProviderFileIdentity{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return webhookProviderFileIdentity{}, false
	}
	return webhookProviderFileIdentity{mode: info.Mode(), size: info.Size(), uid: int(stat.Uid), gid: int(stat.Gid), nlink: uint64(stat.Nlink), regular: info.Mode().IsRegular(), directory: info.IsDir()}, true
}

func zeroWebhookProviderBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
