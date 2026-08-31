// Package tencentcos provides the version-aware backup-store adapter boundary.
// It deliberately has no COS SDK dependency: production credential acquisition
// and SDK wiring need their own separately reviewed constructor.
package tencentcos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/open-card/open-card/internal/install"
)

const (
	maxObjectKeyLength = 1024
	maxVersionIDLength = 256
	maxObjectSize      = int64(1 << 50)
	maxListPageSize    = 1000
)

var (
	// ErrContract is returned for unsafe caller or provider values.
	ErrContract = errors.New("tencent cos backup contract validation failed")
	// ErrTransport deliberately hides provider errors, endpoints, and credentials.
	ErrTransport = errors.New("tencent cos backup operation could not be verified")
	// ErrNotFound is the only typed absence result used for an exact version.
	ErrNotFound = errors.New("tencent cos object version not found")

	// Long names make the boundary explicit for callers that avoid generic names.
	ErrTencentCOSContract  = ErrContract
	ErrTencentCOSTransport = ErrTransport
	ErrTencentCOSNotFound  = ErrNotFound

	sha256Text = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// VersioningStatus is the only bucket-wide state this adapter accepts.
type VersioningStatus string

const VersioningEnabled VersioningStatus = "Enabled"

// ObjectVersion contains only immutable object evidence. Delete markers have
// no usable body metadata and are never accepted as managed backups.
type ObjectVersion struct {
	Key            string
	VersionID      string
	SHA256         string
	Size           int64
	IsDeleteMarker bool
}

func (v ObjectVersion) Validate() error {
	if !validObjectKey(v.Key) || !validVersionID(v.VersionID) {
		return ErrContract
	}
	if v.IsDeleteMarker {
		return nil
	}
	if !sha256Text.MatchString(v.SHA256) || v.Size <= 0 || v.Size > maxObjectSize {
		return ErrContract
	}
	return nil
}

// VersionPage is one exact COS ListObjectVersions page. A truncated page must
// provide a key marker; COS permits an empty version-id marker and it must be
// replayed exactly rather than normalized away.
type VersionPage struct {
	Versions            []ObjectVersion
	IsTruncated         bool
	NextKeyMarker       string
	NextVersionIDMarker string
}

func (p VersionPage) Validate() error {
	if len(p.Versions) > maxListPageSize {
		return ErrContract
	}
	for _, version := range p.Versions {
		if version.Validate() != nil {
			return ErrContract
		}
	}
	if p.IsTruncated {
		if !validMarker(p.NextKeyMarker) || p.NextVersionIDMarker != "" && !validVersionID(p.NextVersionIDMarker) {
			return ErrContract
		}
		return nil
	}
	if p.NextKeyMarker != "" || p.NextVersionIDMarker != "" {
		return ErrContract
	}
	return nil
}

// COSAPI is the dependency-injected, SDK-free COS port. Implementations must
// use ErrNotFound for an exact Head absence; backend error strings are not part
// of this contract.
type COSAPI interface {
	VersioningStatus(context.Context) (VersioningStatus, error)
	Put(context.Context, string, io.Reader, int64, string) (ObjectVersion, error)
	Head(context.Context, string, string) (ObjectVersion, error)
	Get(context.Context, string, string) (io.ReadCloser, ObjectVersion, error)
	ListVersions(context.Context, string, string, string, int) (VersionPage, error)
	DeleteVersion(context.Context, string, string) error
}

// Adapter satisfies install.BackupObjectStore using only the config-bound
// installation namespace. It must be created by NewTaskBackupObjectStore.
type Adapter struct {
	config          install.BackupConfigV1
	api             COSAPI
	namespacePrefix string
}

var _ install.BackupObjectStore = (*Adapter)(nil)

// PlatformAdapter is the V3 companion-receipt adapter. It intentionally has a
// different Get signature from Adapter, so V1 wire compatibility remains
// compile-time separated.
type PlatformAdapter struct{ base *Adapter }

var _ install.PlatformBackupVersionedStore = (*PlatformAdapter)(nil)

// NewTaskBackupObjectStore creates the test/task-only adapter. There is
// intentionally no production constructor until a reviewed official SDK port
// and credential acquisition path are approved.
func NewTaskBackupObjectStore(_ context.Context, config install.BackupConfigV1, expectedInstallationSHA256 string, api COSAPI) (*Adapter, error) {
	if api == nil || config.BindInstallation(expectedInstallationSHA256) != nil {
		return nil, ErrContract
	}
	return &Adapter{config: config, api: api, namespacePrefix: config.Prefix + "/" + config.InstallationIDSHA256 + "/"}, nil
}

// NewTaskPlatformBackupVersionedStore creates the task/test-only V3 adapter.
// It does not acquire credentials, sign requests, or create production SDK
// clients; COSAPI remains the sole injected boundary.
func NewTaskPlatformBackupVersionedStore(ctx context.Context, config install.BackupConfigV1, expectedInstallationSHA256 string, api COSAPI) (*PlatformAdapter, error) {
	base, err := NewTaskBackupObjectStore(ctx, config, expectedInstallationSHA256, api)
	if err != nil {
		return nil, ErrContract
	}
	return &PlatformAdapter{base: base}, nil
}

func (a *Adapter) PutIfAbsent(ctx context.Context, expected install.RemoteBackupExpectedObject, body io.Reader) (install.RemoteBackupObject, error) {
	if a == nil || a.api == nil || body == nil || expected.Validate() != nil || !a.validObjectKey(expected.ObjectKey) {
		return install.RemoteBackupObject{}, ErrContract
	}
	if err := a.versioningEnabled(ctx); err != nil {
		return install.RemoteBackupObject{}, err
	}
	versions, err := a.listExact(ctx, expected.ObjectKey)
	if err != nil {
		return install.RemoteBackupObject{}, err
	}
	if len(versions) == 1 {
		if !matchesExpected(versions[0], expected) {
			return install.RemoteBackupObject{}, ErrTransport
		}
		return a.headExpected(ctx, expected.ObjectKey, versions[0].VersionID, expected)
	}
	if len(versions) != 0 {
		return install.RemoteBackupObject{}, ErrTransport
	}

	put, putErr := a.api.Put(ctx, expected.ObjectKey, body, expected.Size, expected.SHA256)
	if putErr != nil {
		return a.reconcilePut(ctx, expected)
	}
	if !matchesExpected(put, expected) {
		return install.RemoteBackupObject{}, ErrTransport
	}
	if _, err := a.headExpected(ctx, expected.ObjectKey, put.VersionID, expected); err != nil {
		return install.RemoteBackupObject{}, err
	}
	versions, err = a.listExact(ctx, expected.ObjectKey)
	if err != nil || len(versions) != 1 || versions[0].VersionID != put.VersionID || !matchesExpected(versions[0], expected) {
		return install.RemoteBackupObject{}, ErrTransport
	}
	return remoteObject(put)
}

func (a *Adapter) Head(ctx context.Context, key string) (install.RemoteBackupObject, error) {
	if a == nil || a.api == nil || !a.validObjectKey(key) {
		return install.RemoteBackupObject{}, ErrContract
	}
	if err := a.versioningEnabled(ctx); err != nil {
		return install.RemoteBackupObject{}, err
	}
	version, err := a.api.Head(ctx, key, "")
	if err != nil {
		return install.RemoteBackupObject{}, mapAPIError(err)
	}
	if version.Validate() != nil || version.IsDeleteMarker || version.Key != key {
		return install.RemoteBackupObject{}, ErrTransport
	}
	return remoteObject(version)
}

func (a *Adapter) Get(ctx context.Context, key, versionID string) (io.ReadCloser, install.RemoteBackupObject, error) {
	ref := install.RemoteBackupVersionRef{ObjectKey: key, VersionID: versionID}
	if a == nil || a.api == nil || !a.validObjectKey(key) || ref.Validate() != nil {
		return nil, install.RemoteBackupObject{}, ErrContract
	}
	if err := a.versioningEnabled(ctx); err != nil {
		return nil, install.RemoteBackupObject{}, err
	}
	stream, version, err := a.api.Get(ctx, key, versionID)
	if err != nil {
		closeQuietly(stream)
		return nil, install.RemoteBackupObject{}, mapAPIError(err)
	}
	if stream == nil || version.Validate() != nil || version.IsDeleteMarker || version.Key != key || version.VersionID != versionID {
		closeQuietly(stream)
		return nil, install.RemoteBackupObject{}, ErrTransport
	}
	object, err := remoteObject(version)
	if err != nil {
		closeQuietly(stream)
		return nil, install.RemoteBackupObject{}, ErrTransport
	}
	return stream, object, nil
}

func (a *Adapter) List(ctx context.Context, prefix string) ([]install.RemoteBackupObject, error) {
	if a == nil || a.api == nil || prefix != a.namespacePrefix {
		return nil, ErrContract
	}
	if err := a.versioningEnabled(ctx); err != nil {
		return nil, err
	}
	versions, err := a.listVersions(ctx, prefix, false)
	if err != nil {
		return nil, err
	}
	objects := make([]install.RemoteBackupObject, 0, len(versions))
	for _, version := range versions {
		object, err := remoteObject(version)
		if err != nil {
			return nil, ErrTransport
		}
		objects = append(objects, object)
	}
	sort.Slice(objects, func(i, j int) bool {
		if objects[i].ObjectKey == objects[j].ObjectKey {
			return objects[i].VersionID < objects[j].VersionID
		}
		return objects[i].ObjectKey < objects[j].ObjectKey
	})
	return objects, nil
}

func (a *Adapter) DeleteVersion(ctx context.Context, key, versionID string) error {
	ref := install.RemoteBackupVersionRef{ObjectKey: key, VersionID: versionID}
	if a == nil || a.api == nil || !a.validObjectKey(key) || ref.Validate() != nil {
		return ErrContract
	}
	if err := a.versioningEnabled(ctx); err != nil {
		return err
	}
	if err := a.api.DeleteVersion(ctx, key, versionID); err != nil && !errors.Is(err, ErrNotFound) {
		return mapAPIError(err)
	}
	_, err := a.api.Head(ctx, key, versionID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return ErrTransport
}

func (a *Adapter) reconcilePut(ctx context.Context, expected install.RemoteBackupExpectedObject) (install.RemoteBackupObject, error) {
	versions, err := a.listExact(ctx, expected.ObjectKey)
	if err != nil || len(versions) != 1 || !matchesExpected(versions[0], expected) {
		return install.RemoteBackupObject{}, ErrTransport
	}
	return a.headExpected(ctx, expected.ObjectKey, versions[0].VersionID, expected)
}

func (a *Adapter) headExpected(ctx context.Context, key, versionID string, expected install.RemoteBackupExpectedObject) (install.RemoteBackupObject, error) {
	version, err := a.api.Head(ctx, key, versionID)
	if err != nil {
		return install.RemoteBackupObject{}, mapAPIError(err)
	}
	if !matchesExpected(version, expected) || version.VersionID != versionID {
		return install.RemoteBackupObject{}, ErrTransport
	}
	return remoteObject(version)
}

func (a *Adapter) listExact(ctx context.Context, key string) ([]ObjectVersion, error) {
	return a.listVersions(ctx, key, true)
}

func (a *Adapter) listVersions(ctx context.Context, prefix string, exact bool) ([]ObjectVersion, error) {
	var versions []ObjectVersion
	seenVersions := make(map[string]struct{})
	seenMarkers := make(map[string]struct{})
	keyMarker, versionMarker := "", ""
	for {
		if ctx == nil || ctx.Err() != nil {
			return nil, ErrTransport
		}
		page, err := a.api.ListVersions(ctx, prefix, keyMarker, versionMarker, maxListPageSize)
		if err != nil || page.Validate() != nil {
			return nil, ErrTransport
		}
		for _, version := range page.Versions {
			if version.IsDeleteMarker || !a.validObjectKey(version.Key) || (exact && version.Key != prefix) || (!exact && !strings.HasPrefix(version.Key, prefix)) {
				return nil, ErrTransport
			}
			identity := version.Key + "\x00" + version.VersionID
			if _, exists := seenVersions[identity]; exists {
				return nil, ErrTransport
			}
			seenVersions[identity] = struct{}{}
			versions = append(versions, version)
		}
		if !page.IsTruncated {
			return versions, nil
		}
		next := page.NextKeyMarker + "\x00" + page.NextVersionIDMarker
		current := keyMarker + "\x00" + versionMarker
		if next == current {
			return nil, ErrTransport
		}
		if _, exists := seenMarkers[next]; exists {
			return nil, ErrTransport
		}
		seenMarkers[next] = struct{}{}
		keyMarker, versionMarker = page.NextKeyMarker, page.NextVersionIDMarker
	}
}

func (a *Adapter) versioningEnabled(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || a == nil || a.api == nil {
		return ErrTransport
	}
	status, err := a.api.VersioningStatus(ctx)
	if err != nil || status != VersioningEnabled {
		return ErrTransport
	}
	return nil
}

func (a *Adapter) validObjectKey(key string) bool {
	if !strings.HasPrefix(key, a.namespacePrefix) || len(strings.TrimPrefix(key, a.namespacePrefix)) == 0 {
		return false
	}
	backupID := strings.TrimSuffix(strings.TrimPrefix(key, a.namespacePrefix), ".ocbkp")
	canonical, err := a.config.ObjectKey(backupID)
	return err == nil && canonical == key
}

func remoteObject(version ObjectVersion) (install.RemoteBackupObject, error) {
	if version.Validate() != nil || version.IsDeleteMarker {
		return install.RemoteBackupObject{}, ErrTransport
	}
	object := install.RemoteBackupObject{ObjectKey: version.Key, VersionID: version.VersionID, SHA256: version.SHA256, Size: version.Size}
	if object.Validate() != nil {
		return install.RemoteBackupObject{}, ErrTransport
	}
	return object, nil
}

func matchesExpected(version ObjectVersion, expected install.RemoteBackupExpectedObject) bool {
	return version.Validate() == nil && !version.IsDeleteMarker && version.Key == expected.ObjectKey && version.SHA256 == expected.SHA256 && version.Size == expected.Size
}

func mapAPIError(err error) error {
	if errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	return ErrTransport
}

func closeQuietly(stream io.ReadCloser) {
	if stream != nil {
		_ = stream.Close()
	}
}

func validObjectKey(key string) bool {
	return len(key) > 0 && len(key) <= maxObjectKeyLength && !strings.ContainsAny(key, "\\\x00\r\n")
}

func validVersionID(versionID string) bool {
	if len(versionID) == 0 || len(versionID) > maxVersionIDLength || versionID == "null" {
		return false
	}
	for _, r := range versionID {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._~=-", r) {
			continue
		}
		return false
	}
	return true
}

func validMarker(marker string) bool {
	return len(marker) > 0 && len(marker) <= maxObjectKeyLength && !strings.ContainsAny(marker, "\\\x00\r\n")
}

func (a *PlatformAdapter) PutReconciled(ctx context.Context, expected install.PlatformBackupExpectedObject, body io.Reader) (install.PlatformBackupStoreObject, error) {
	if a == nil || a.base == nil || body == nil || !a.validExpected(expected) {
		return install.PlatformBackupStoreObject{}, ErrContract
	}
	if err := a.base.versioningEnabled(ctx); err != nil {
		return install.PlatformBackupStoreObject{}, err
	}
	versions, err := a.listExact(ctx, expected.ObjectKey)
	if err != nil {
		return install.PlatformBackupStoreObject{}, err
	}
	if len(versions) == 1 {
		if !platformMatchesExpected(versions[0], expected) {
			return install.PlatformBackupStoreObject{}, ErrTransport
		}
		return a.headAndListExpected(ctx, expected, versions[0].VersionID)
	}
	if len(versions) != 0 {
		return install.PlatformBackupStoreObject{}, ErrTransport
	}
	evidence := &platformPutEvidenceReader{source: body, hash: sha256.New()}
	put, putErr := a.base.api.Put(ctx, expected.ObjectKey, evidence, expected.Size, expected.SHA256)
	if putErr != nil {
		versions, err = a.listExact(ctx, expected.ObjectKey)
		if err != nil || len(versions) != 1 || !platformMatchesExpected(versions[0], expected) {
			return install.PlatformBackupStoreObject{}, ErrTransport
		}
		return a.headAndListExpected(ctx, expected, versions[0].VersionID)
	}
	if !evidence.matches(expected) {
		return install.PlatformBackupStoreObject{}, ErrTransport
	}
	if !platformMatchesExpected(put, expected) {
		return install.PlatformBackupStoreObject{}, ErrTransport
	}
	return a.headAndListExpected(ctx, expected, put.VersionID)
}

func (a *PlatformAdapter) HeadCurrentVersion(ctx context.Context, key string) (install.PlatformBackupStoreObject, error) {
	if a == nil || a.base == nil || !a.validManagedKey(key) {
		return install.PlatformBackupStoreObject{}, ErrContract
	}
	if err := a.base.versioningEnabled(ctx); err != nil {
		return install.PlatformBackupStoreObject{}, err
	}
	version, err := a.base.api.Head(ctx, key, "")
	if err != nil {
		return install.PlatformBackupStoreObject{}, mapAPIError(err)
	}
	if version.Validate() != nil || version.IsDeleteMarker || version.Key != key {
		return install.PlatformBackupStoreObject{}, ErrTransport
	}
	return platformObject(version)
}

func (a *PlatformAdapter) Get(ctx context.Context, key, versionID string) (io.ReadCloser, install.PlatformBackupStoreObject, error) {
	if a == nil || a.base == nil || !a.validManagedKey(key) || !validVersionID(versionID) {
		return nil, install.PlatformBackupStoreObject{}, ErrContract
	}
	if err := a.base.versioningEnabled(ctx); err != nil {
		return nil, install.PlatformBackupStoreObject{}, err
	}
	stream, version, err := a.base.api.Get(ctx, key, versionID)
	if err != nil {
		closeQuietly(stream)
		return nil, install.PlatformBackupStoreObject{}, mapAPIError(err)
	}
	if stream == nil || version.Validate() != nil || version.IsDeleteMarker || version.Key != key || version.VersionID != versionID {
		closeQuietly(stream)
		return nil, install.PlatformBackupStoreObject{}, ErrTransport
	}
	object, err := platformObject(version)
	if err != nil {
		closeQuietly(stream)
		return nil, install.PlatformBackupStoreObject{}, ErrTransport
	}
	return stream, object, nil
}

func (a *PlatformAdapter) ListVersions(ctx context.Context, prefix string) ([]install.PlatformBackupStoreObject, error) {
	if a == nil || a.base == nil || prefix != strings.TrimSuffix(a.base.namespacePrefix, "/") {
		return nil, ErrContract
	}
	if err := a.base.versioningEnabled(ctx); err != nil {
		return nil, err
	}
	versions, err := a.listVersions(ctx, a.base.namespacePrefix, false)
	if err != nil {
		return nil, err
	}
	objects := make([]install.PlatformBackupStoreObject, 0, len(versions))
	for _, version := range versions {
		object, err := platformObject(version)
		if err != nil {
			return nil, ErrTransport
		}
		objects = append(objects, object)
	}
	sort.Slice(objects, func(i, j int) bool {
		if objects[i].ObjectKey == objects[j].ObjectKey {
			return objects[i].VersionID < objects[j].VersionID
		}
		return objects[i].ObjectKey < objects[j].ObjectKey
	})
	return objects, nil
}

func (a *PlatformAdapter) DeleteVersion(ctx context.Context, key, versionID string) error {
	if a == nil || a.base == nil || !a.validManagedKey(key) || !validVersionID(versionID) {
		return ErrContract
	}
	if err := a.base.versioningEnabled(ctx); err != nil {
		return err
	}
	if err := a.base.api.DeleteVersion(ctx, key, versionID); err != nil && !errors.Is(err, ErrNotFound) {
		return mapAPIError(err)
	}
	_, err := a.base.api.Head(ctx, key, versionID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return ErrTransport
}

func (a *PlatformAdapter) headAndListExpected(ctx context.Context, expected install.PlatformBackupExpectedObject, versionID string) (install.PlatformBackupStoreObject, error) {
	version, err := a.base.api.Head(ctx, expected.ObjectKey, versionID)
	if err != nil || !platformMatchesExpected(version, expected) || version.VersionID != versionID {
		return install.PlatformBackupStoreObject{}, mapPlatformHeadError(err)
	}
	object, err := platformObject(version)
	if err != nil {
		return install.PlatformBackupStoreObject{}, ErrTransport
	}
	versions, err := a.listExact(ctx, expected.ObjectKey)
	if err != nil || len(versions) != 1 || versions[0] != version || !platformMatchesExpected(versions[0], expected) {
		return install.PlatformBackupStoreObject{}, ErrTransport
	}
	return object, nil
}

func (a *PlatformAdapter) listExact(ctx context.Context, key string) ([]ObjectVersion, error) {
	return a.listVersions(ctx, key, true)
}

func (a *PlatformAdapter) listVersions(ctx context.Context, prefix string, exact bool) ([]ObjectVersion, error) {
	var versions []ObjectVersion
	seenVersions, seenMarkers := map[string]struct{}{}, map[string]struct{}{}
	keyMarker, versionMarker := "", ""
	for {
		if ctx == nil || ctx.Err() != nil {
			return nil, ErrTransport
		}
		page, err := a.base.api.ListVersions(ctx, prefix, keyMarker, versionMarker, maxListPageSize)
		if err != nil || page.Validate() != nil {
			return nil, ErrTransport
		}
		for _, version := range page.Versions {
			if version.IsDeleteMarker || !a.validManagedKey(version.Key) || (exact && version.Key != prefix) || (!exact && !strings.HasPrefix(version.Key, prefix)) {
				return nil, ErrTransport
			}
			identity := version.Key + "\x00" + version.VersionID
			if _, exists := seenVersions[identity]; exists {
				return nil, ErrTransport
			}
			seenVersions[identity] = struct{}{}
			versions = append(versions, version)
		}
		if !page.IsTruncated {
			return versions, nil
		}
		next, current := page.NextKeyMarker+"\x00"+page.NextVersionIDMarker, keyMarker+"\x00"+versionMarker
		if next == current {
			return nil, ErrTransport
		}
		if _, exists := seenMarkers[next]; exists {
			return nil, ErrTransport
		}
		seenMarkers[next] = struct{}{}
		keyMarker, versionMarker = page.NextKeyMarker, page.NextVersionIDMarker
	}
}

func (a *PlatformAdapter) validExpected(expected install.PlatformBackupExpectedObject) bool {
	return a.validManagedKey(expected.ObjectKey) && sha256Text.MatchString(expected.SHA256) && expected.Size > 0 && expected.Size <= maxObjectSize
}
func (a *PlatformAdapter) validManagedKey(key string) bool {
	if a == nil || a.base == nil || !strings.HasPrefix(key, a.base.namespacePrefix) {
		return false
	}
	relative := strings.TrimPrefix(key, a.base.namespacePrefix)
	var backupID string
	switch {
	case strings.HasSuffix(relative, ".ocbkp"):
		backupID = strings.TrimSuffix(relative, ".ocbkp")
		canonical, err := a.base.config.ObjectKey(backupID)
		return err == nil && key == canonical
	case strings.HasSuffix(relative, ".receipt.json"):
		backupID = strings.TrimSuffix(relative, ".receipt.json")
		dataKey, err := a.base.config.ObjectKey(backupID)
		return err == nil && key == strings.TrimSuffix(dataKey, ".ocbkp")+".receipt.json"
	default:
		return false
	}
}
func platformMatchesExpected(version ObjectVersion, expected install.PlatformBackupExpectedObject) bool {
	return version.Validate() == nil && !version.IsDeleteMarker && version.Key == expected.ObjectKey && version.SHA256 == expected.SHA256 && version.Size == expected.Size
}
func platformObject(version ObjectVersion) (install.PlatformBackupStoreObject, error) {
	if version.Validate() != nil || version.IsDeleteMarker {
		return install.PlatformBackupStoreObject{}, ErrTransport
	}
	return install.PlatformBackupStoreObject{ObjectKey: version.Key, VersionID: version.VersionID, SHA256: version.SHA256, Size: version.Size}, nil
}
func mapPlatformHeadError(err error) error {
	if err != nil {
		return mapAPIError(err)
	}
	return ErrTransport
}

// platformPutEvidenceReader records only bytes read by COSAPI.Put. A provider
// claiming success after a short or partially consumed stream is rejected
// before its metadata can make that content visible.
type platformPutEvidenceReader struct {
	source  io.Reader
	hash    hash.Hash
	size    int64
	readErr error
}

func (r *platformPutEvidenceReader) Read(value []byte) (int, error) {
	n, err := r.source.Read(value)
	if n > 0 {
		_, _ = r.hash.Write(value[:n])
		r.size += int64(n)
	}
	if err != nil && err != io.EOF {
		r.readErr = err
	}
	return n, err
}

func (r *platformPutEvidenceReader) matches(expected install.PlatformBackupExpectedObject) bool {
	return r.readErr == nil && r.size == expected.Size && hex.EncodeToString(r.hash.Sum(nil)) == expected.SHA256
}
