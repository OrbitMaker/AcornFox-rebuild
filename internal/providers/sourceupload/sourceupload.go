// Package sourceupload owns the private, bounded filesystem ingress for G3
// source uploads. It receives multipart streams but never stores caller paths
// in PostgreSQL or returns physical storage locations to HTTP callers.
package sourceupload

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

const (
	DefaultMaxTotalBytes = int64(100 << 20)
	DefaultMaxFileBytes  = int64(32 << 20)
	DefaultMaxFiles      = 10_000
	DefaultMaxPathBytes  = 512
	DefaultMaxManifest   = int64(2 << 20)
)

var (
	ErrLimitExceeded = errors.New("source upload limit exceeded")
	ErrInvalidUpload = errors.New("source upload is invalid")
	ErrStorage       = errors.New("source upload storage is unavailable")
)

type Limits struct {
	MaxTotalBytes int64
	MaxFileBytes  int64
	MaxFiles      int
	MaxPathBytes  int
	MaxManifest   int64
}

func DefaultLimits() Limits {
	return Limits{MaxTotalBytes: DefaultMaxTotalBytes, MaxFileBytes: DefaultMaxFileBytes, MaxFiles: DefaultMaxFiles, MaxPathBytes: DefaultMaxPathBytes, MaxManifest: DefaultMaxManifest}
}

func (l Limits) Validate() error {
	if l.MaxTotalBytes <= 0 || l.MaxFileBytes <= 0 || l.MaxFiles <= 0 || l.MaxPathBytes <= 0 || l.MaxManifest <= 0 || l.MaxFileBytes > l.MaxTotalBytes || l.MaxPathBytes > DefaultMaxPathBytes {
		return ErrInvalidUpload
	}
	return nil
}

type Config struct {
	Root   string
	Limits Limits
	TTL    time.Duration
	Clock  func() time.Time
}

type Manager struct {
	root   string
	limits Limits
	ttl    time.Duration
	clock  func() time.Time
}

type StoredUpload struct {
	Upload domain.SourceUploadRecord
	Path   string
}

type Session struct {
	manager     *Manager
	id          domain.ID
	stage       string
	files       map[string]domain.SourceUploadFile
	total       int64
	archive     bool
	archivePath string
	closed      bool
}

func New(config Config) (*Manager, error) {
	root, err := filepath.Abs(strings.TrimSpace(config.Root))
	if err != nil || root == "" {
		return nil, fmt.Errorf("source upload root is invalid")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("source upload root is unavailable")
	}
	limits := config.Limits
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	ttl := config.TTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	if ttl <= 0 {
		return nil, ErrInvalidUpload
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Manager{root: root, limits: limits, ttl: ttl, clock: clock}, nil
}

func (m *Manager) Limits() Limits { return m.limits }

func (m *Manager) Begin(id domain.ID) (*Session, error) {
	if m == nil || m.root == "" || domain.RequireID(id, "source upload id") != nil {
		return nil, ErrInvalidUpload
	}
	root, err := m.checkedRoot()
	if err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(root, ".source-upload-")
	if err != nil {
		return nil, ErrStorage
	}
	if err := os.Chmod(stage, 0o700); err != nil {
		_ = os.RemoveAll(stage)
		return nil, ErrStorage
	}
	return &Session{manager: m, id: id, stage: stage, files: map[string]domain.SourceUploadFile{}}, nil
}

func (s *Session) WriteArchive(filename string, content io.Reader) error {
	if err := s.open(); err != nil {
		return err
	}
	if s.archive || len(s.files) != 0 {
		return ErrInvalidUpload
	}
	ext, ok := archiveExtension(filename)
	if !ok {
		return ErrInvalidUpload
	}
	path := filepath.Join(s.stage, "archive"+ext)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrStorage
	}
	bytes, digest, writeErr := s.copyFile(file, content, s.manager.limits.MaxTotalBytes)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		if errors.Is(writeErr, ErrLimitExceeded) {
			return ErrLimitExceeded
		}
		return ErrStorage
	}
	s.archive, s.archivePath, s.total = true, path, bytes
	s.files["archive"+ext] = domain.SourceUploadFile{Path: "archive" + ext, Bytes: bytes, Digest: digest}
	return nil
}

func (s *Session) WriteDirectoryFile(rawPath string, content io.Reader) error {
	if err := s.open(); err != nil {
		return err
	}
	if s.archive {
		return ErrInvalidUpload
	}
	path, err := domain.NormalizeSourceUploadPath(rawPath)
	if err != nil || len(path) > s.manager.limits.MaxPathBytes || len(s.files) >= s.manager.limits.MaxFiles {
		return ErrInvalidUpload
	}
	if _, exists := s.files[path]; exists {
		return ErrInvalidUpload
	}
	root := filepath.Join(s.stage, "files")
	if err := safeMkdirAll(root, filepath.Dir(path)); err != nil {
		return ErrStorage
	}
	target := filepath.Join(root, filepath.FromSlash(path))
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrStorage
	}
	bytes, digest, writeErr := s.copyFile(file, content)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(target)
		if errors.Is(writeErr, ErrLimitExceeded) {
			return ErrLimitExceeded
		}
		return ErrStorage
	}
	info, err := os.Lstat(target)
	if !singleLinkedRegular(info, err) {
		_ = os.Remove(target)
		return ErrStorage
	}
	s.files[path] = domain.SourceUploadFile{Path: path, Bytes: bytes, Digest: digest}
	return nil
}

func (s *Session) Finalize(kind domain.SourceUploadKind, manifest []domain.SourceUploadFile, idempotencyKey string) (StoredUpload, error) {
	if err := s.open(); err != nil {
		return StoredUpload{}, err
	}
	defer func() {
		if !s.closed {
			s.Abort()
		}
	}()
	if kind != domain.SourceUploadArchive && kind != domain.SourceUploadDirectory {
		return StoredUpload{}, ErrInvalidUpload
	}
	var files []domain.SourceUploadFile
	var digest string
	if kind == domain.SourceUploadArchive {
		if !s.archive || len(s.files) != 1 || len(manifest) != 0 {
			return StoredUpload{}, ErrInvalidUpload
		}
		files = sortedFiles(s.files)
		digest = files[0].Digest
	} else {
		if s.archive || len(s.files) == 0 || len(s.files) > s.manager.limits.MaxFiles {
			return StoredUpload{}, ErrInvalidUpload
		}
		files = sortedFiles(s.files)
		if err := exactManifest(files, manifest); err != nil {
			return StoredUpload{}, err
		}
		digest = directoryDigest(files)
	}
	for _, file := range files {
		path := filepath.Join(s.stage, filepath.FromSlash(file.Path))
		if kind == domain.SourceUploadDirectory {
			path = filepath.Join(s.stage, "files", filepath.FromSlash(file.Path))
		}
		info, err := os.Lstat(path)
		if !singleLinkedRegular(info, err) {
			return StoredUpload{}, ErrInvalidUpload
		}
	}
	if err := domain.ValidateSourceUploadDigest(digest); err != nil || strings.TrimSpace(idempotencyKey) == "" {
		return StoredUpload{}, ErrInvalidUpload
	}
	now := s.manager.clock().UTC()
	upload := domain.SourceUploadRecord{ID: s.id, Kind: kind, Status: domain.SourceUploadReady, Digest: digest, Bytes: s.total, FileCount: len(files), StorageRef: "upload://" + s.id.String(), ExpiresAt: now.Add(s.manager.ttl), IdempotencyKey: strings.TrimSpace(idempotencyKey), RequestDigest: digest, CreatedAt: now, UpdatedAt: now, Files: files}
	if err := upload.Validate(); err != nil {
		return StoredUpload{}, ErrInvalidUpload
	}
	final := filepath.Join(s.manager.root, s.id.String())
	if _, err := os.Lstat(final); err == nil {
		return StoredUpload{}, ErrStorage
	} else if !errors.Is(err, fs.ErrNotExist) {
		return StoredUpload{}, ErrStorage
	}
	if err := os.Rename(s.stage, final); err != nil {
		return StoredUpload{}, ErrStorage
	}
	s.closed = true
	return StoredUpload{Upload: upload, Path: final}, nil
}

func (s *Session) Abort() {
	if s == nil || s.closed {
		return
	}
	s.closed = true
	_ = os.RemoveAll(s.stage)
}

func (m *Manager) Discard(id domain.ID) error {
	if m == nil || domain.RequireID(id, "source upload id") != nil {
		return ErrInvalidUpload
	}
	root, err := m.checkedRoot()
	if err != nil {
		return err
	}
	path := filepath.Join(root, id.String())
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return ErrStorage
	}
	if err := os.RemoveAll(path); err != nil {
		return ErrStorage
	}
	return nil
}

func (s *Session) copyFile(destination *os.File, source io.Reader, maximum ...int64) (int64, string, error) {
	if source == nil {
		return 0, "", ErrInvalidUpload
	}
	remaining := s.manager.limits.MaxTotalBytes - s.total
	if remaining < 0 {
		return 0, "", ErrLimitExceeded
	}
	limit := s.manager.limits.MaxFileBytes
	if len(maximum) == 1 {
		limit = maximum[0]
	}
	if remaining < limit {
		limit = remaining
	}
	hash := sha256.New()
	bytes, err := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(source, limit+1))
	if err != nil {
		return 0, "", err
	}
	if bytes > limit {
		return 0, "", ErrLimitExceeded
	}
	s.total += bytes
	return bytes, "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *Session) open() error {
	if s == nil || s.manager == nil || s.closed || s.stage == "" {
		return ErrInvalidUpload
	}
	info, err := os.Lstat(s.stage)
	if err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return ErrStorage
	}
	return nil
}

func (m *Manager) checkedRoot() (string, error) {
	info, err := os.Lstat(m.root)
	if err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return "", ErrStorage
	}
	return m.root, nil
}

func singleLinkedRegular(info fs.FileInfo, err error) bool {
	if err != nil || !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || stat.Nlink == 1
}

func archiveExtension(filename string) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(filename))
	switch {
	case strings.HasSuffix(name, ".tar.gz"):
		return ".tar.gz", true
	case strings.HasSuffix(name, ".tgz"):
		return ".tgz", true
	case strings.HasSuffix(name, ".zip"):
		return ".zip", true
	default:
		return "", false
	}
}

func safeMkdirAll(root, relative string) error {
	if err := os.Mkdir(root, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&fs.ModeSymlink != 0 {
		return ErrStorage
	}
	if relative == "." {
		return os.Chmod(root, 0o700)
	}
	current := root
	for _, part := range strings.Split(filepath.Clean(relative), string(filepath.Separator)) {
		if part == "." || part == "" || part == ".." {
			return ErrInvalidUpload
		}
		current = filepath.Join(current, part)
		if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
			return ErrStorage
		}
	}
	return nil
}

func sortedFiles(values map[string]domain.SourceUploadFile) []domain.SourceUploadFile {
	result := make([]domain.SourceUploadFile, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Path < result[right].Path })
	return result
}

func exactManifest(actual, manifest []domain.SourceUploadFile) error {
	if len(actual) != len(manifest) {
		return ErrInvalidUpload
	}
	copy := append([]domain.SourceUploadFile(nil), manifest...)
	sort.Slice(copy, func(left, right int) bool { return copy[left].Path < copy[right].Path })
	for index, item := range copy {
		if err := item.Validate(); err != nil || actual[index] != item {
			return ErrInvalidUpload
		}
	}
	return nil
}

func directoryDigest(files []domain.SourceUploadFile) string {
	hash := sha256.New()
	for _, file := range files {
		_, _ = io.WriteString(hash, file.Path)
		_, _ = io.WriteString(hash, "\x00")
		_, _ = io.WriteString(hash, strconv.FormatInt(file.Bytes, 10))
		_, _ = io.WriteString(hash, "\x00")
		_, _ = io.WriteString(hash, file.Digest)
		_, _ = io.WriteString(hash, "\n")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}
