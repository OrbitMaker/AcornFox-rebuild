package observability

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/acornfox/acornfox/internal/foundation"
)

const (
	LogCategoryBuild   LogCategory = "build"
	LogCategoryRuntime LogCategory = "runtime"
	LogCategoryAudit   LogCategory = "audit"

	// Category* spellings are kept short for call sites that already use a
	// generic category vocabulary.
	CategoryBuild   = LogCategoryBuild
	CategoryRuntime = LogCategoryRuntime
	CategoryAudit   = LogCategoryAudit

	defaultLogFileBytes     int64 = 10 * 1024 * 1024
	defaultLogTotalBytes    int64 = 5 * 1024 * 1024 * 1024
	defaultBuildFiles             = 20
	defaultRuntimeFiles           = 5
	defaultRuntimeRetention       = 7 * 24 * time.Hour
)

var (
	ErrInvalidLogCategory = errors.New("invalid log category")
	ErrInvalidLogStream   = errors.New("invalid log stream")
	ErrLogPathTraversal   = errors.New("log path traversal is not allowed")
	ErrLogFileTooLarge    = errors.New("log record exceeds configured file limit")
)

// LogCategory separates ordinary build/runtime logs from audit evidence.
// Audit files may be written through this store but are never considered by
// ordinary file-count or byte-budget garbage collection.
type LogCategory string

// LogStoreConfig defines bounded local persistence. RootDir is the canonical
// field; Dir and Path are accepted aliases so configuration can be adapted
// without a second wrapper type.
type LogStoreConfig struct {
	RootDir string
	Root    string
	Dir     string
	Path    string

	MaxFileBytes  int64
	MaxTotalBytes int64
	// MaxBytes and FileBytes/TotalBytes are compatibility aliases. Explicit
	// canonical fields take precedence when both are set.
	MaxBytes   int64
	FileBytes  int64
	TotalBytes int64

	// MaxBuildFiles is the number of build execution streams retained. All
	// segments of an expired build are removed together.
	MaxBuildFiles     int
	MaxRuntimeFiles   int
	MaxFilesPerStream int
	RuntimeRetention  time.Duration

	Secrets  []string
	Redactor foundation.Redactor
}

// LogStoreOptions is an alias for callers that prefer the options name.
type LogStoreOptions = LogStoreConfig

// LogConfig is a compact compatibility alias.
type LogConfig = LogStoreConfig

// LogStoreOption customizes a LogStoreConfig before opening it.
type LogStoreOption func(*LogStoreConfig)

func WithMaxFileBytes(value int64) LogStoreOption {
	return func(config *LogStoreConfig) { config.MaxFileBytes = value }
}

func WithMaxTotalBytes(value int64) LogStoreOption {
	return func(config *LogStoreConfig) { config.MaxTotalBytes = value }
}

func WithBuildRetention(files int) LogStoreOption {
	return func(config *LogStoreConfig) { config.MaxBuildFiles = files }
}

func WithRuntimeRetention(files int) LogStoreOption {
	return func(config *LogStoreConfig) { config.MaxRuntimeFiles = files }
}

func WithMaxFilesPerStream(files int) LogStoreOption {
	return func(config *LogStoreConfig) { config.MaxFilesPerStream = files }
}

func WithSecrets(secrets ...string) LogStoreOption {
	return func(config *LogStoreConfig) { config.Secrets = append([]string(nil), secrets...) }
}

func WithRedactor(redactor foundation.Redactor) LogStoreOption {
	return func(config *LogStoreConfig) { config.Redactor = redactor }
}

// LogFile describes one on-disk rotated segment.
type LogFile struct {
	Category LogCategory
	Stream   string
	Path     string
	Sequence int
	Bytes    int64
	ModTime  time.Time
}

// LogStore is safe for concurrent use by one process. It intentionally does
// not claim cross-process locking; the control-plane service owns one store
// instance and restart recovery scans the durable directory.
type LogStore struct {
	mu     sync.Mutex
	root   string
	config LogStoreConfig
	redact foundation.Redactor
}

// NewLogStore accepts either a root path, a LogStoreConfig, or a config plus
// LogStoreOption values. The flexible input keeps the small M0 API usable by
// both direct callers and config-driven binaries without adding dependencies.
func NewLogStore(rootOrConfig any, options ...any) (*LogStore, error) {
	config, err := logStoreConfig(rootOrConfig, options...)
	if err != nil {
		return nil, err
	}
	root := firstNonEmpty(config.RootDir, config.Root, config.Dir, config.Path)
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("log store root directory is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve log store root: %w", err)
	}
	if err := os.MkdirAll(absolute, 0o750); err != nil {
		return nil, fmt.Errorf("create log store root: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(absolute); resolveErr == nil {
		absolute = resolved
	}
	for _, category := range []LogCategory{LogCategoryBuild, LogCategoryRuntime, LogCategoryAudit} {
		categoryPath := filepath.Join(absolute, string(category))
		if err := os.MkdirAll(categoryPath, 0o750); err != nil {
			return nil, fmt.Errorf("create %s log directory: %w", category, err)
		}
		if err := ensureDirectoryNoSymlink(categoryPath); err != nil {
			return nil, fmt.Errorf("validate %s log directory: %w", category, err)
		}
	}
	redactor := config.Redactor
	if len(config.Secrets) > 0 {
		redactor = foundation.NewRedactor(config.Secrets...)
	}
	if redactor.Replacement == "" {
		redactor.Replacement = foundation.RedactedValue
	}
	store := &LogStore{root: absolute, config: config, redact: redactor}
	store.mu.Lock()
	defer store.mu.Unlock()
	// Opening a store is also restart recovery: scan durable segments and
	// enforce configured ordinary retention before the next append.
	if _, err := store.scanFilesLocked(false); err != nil {
		return nil, fmt.Errorf("recover log store: %w", err)
	}
	if err := store.gcLocked(); err != nil {
		return nil, fmt.Errorf("recover log store retention: %w", err)
	}
	return store, nil
}

// OpenLogStore and NewFileLogStore are constructor aliases.
func OpenLogStore(rootOrConfig any, options ...any) (*LogStore, error) {
	return NewLogStore(rootOrConfig, options...)
}

func NewFileLogStore(rootOrConfig any, options ...any) (*LogStore, error) {
	return NewLogStore(rootOrConfig, options...)
}

func logStoreConfig(rootOrConfig any, options ...any) (LogStoreConfig, error) {
	config := LogStoreConfig{
		MaxFileBytes:     defaultLogFileBytes,
		MaxTotalBytes:    defaultLogTotalBytes,
		MaxBuildFiles:    defaultBuildFiles,
		MaxRuntimeFiles:  defaultRuntimeFiles,
		RuntimeRetention: defaultRuntimeRetention,
	}
	switch value := rootOrConfig.(type) {
	case string:
		config.RootDir = value
	case LogStoreConfig:
		config = mergeLogStoreConfig(config, value)
	case *LogStoreConfig:
		if value == nil {
			return LogStoreConfig{}, errors.New("nil log store config")
		}
		config = mergeLogStoreConfig(config, *value)
	case nil:
		return LogStoreConfig{}, errors.New("log store root or config is required")
	default:
		return LogStoreConfig{}, fmt.Errorf("unsupported log store constructor value %T", rootOrConfig)
	}
	for _, option := range options {
		switch value := option.(type) {
		case LogStoreOption:
			if value != nil {
				value(&config)
			}
		case LogStoreConfig:
			config = mergeLogStoreConfig(config, value)
		case *LogStoreConfig:
			if value != nil {
				config = mergeLogStoreConfig(config, *value)
			}
		case foundation.Redactor:
			config.Redactor = value
		case []string:
			config.Secrets = append([]string(nil), value...)
		default:
			return LogStoreConfig{}, fmt.Errorf("unsupported log store option %T", option)
		}
	}
	if config.MaxFileBytes <= 0 {
		return LogStoreConfig{}, fmt.Errorf("max file bytes must be positive")
	}
	if config.MaxTotalBytes <= 0 {
		return LogStoreConfig{}, fmt.Errorf("max total bytes must be positive")
	}
	if config.MaxBuildFiles <= 0 {
		config.MaxBuildFiles = defaultBuildFiles
	}
	if config.MaxRuntimeFiles <= 0 {
		config.MaxRuntimeFiles = defaultRuntimeFiles
	}
	return config, nil
}

func mergeLogStoreConfig(base, override LogStoreConfig) LogStoreConfig {
	if override.RootDir != "" {
		base.RootDir = override.RootDir
	}
	if override.Root != "" {
		base.Root = override.Root
	}
	if override.Dir != "" {
		base.Dir = override.Dir
	}
	if override.Path != "" {
		base.Path = override.Path
	}
	if override.MaxFileBytes != 0 {
		base.MaxFileBytes = override.MaxFileBytes
	}
	if override.MaxTotalBytes != 0 {
		base.MaxTotalBytes = override.MaxTotalBytes
	}
	if override.MaxTotalBytes == 0 && override.MaxBytes != 0 {
		base.MaxTotalBytes = override.MaxBytes
	}
	if override.MaxFileBytes == 0 && override.FileBytes != 0 {
		base.MaxFileBytes = override.FileBytes
	}
	if override.MaxTotalBytes == 0 && override.TotalBytes != 0 {
		base.MaxTotalBytes = override.TotalBytes
	}
	if override.MaxBuildFiles != 0 {
		base.MaxBuildFiles = override.MaxBuildFiles
	}
	if override.MaxRuntimeFiles != 0 {
		base.MaxRuntimeFiles = override.MaxRuntimeFiles
	}
	if override.MaxFilesPerStream != 0 {
		base.MaxFilesPerStream = override.MaxFilesPerStream
	}
	if override.RuntimeRetention != 0 {
		base.RuntimeRetention = override.RuntimeRetention
	}
	if len(override.Secrets) > 0 {
		base.Secrets = append([]string(nil), override.Secrets...)
	}
	if override.Redactor.Secrets != nil || override.Redactor.Replacement != "" {
		base.Redactor = override.Redactor
	}
	return base
}

// RootDir returns the canonical absolute store root.
func (s *LogStore) RootDir() string {
	if s == nil {
		return ""
	}
	return s.root
}

// Append redacts data before any filesystem write, splits records at the file
// limit, and applies deterministic ordinary retention. Stream is a safe
// logical identifier (for example a build ID or service name), not a path.
func (s *LogStore) Append(category LogCategory, stream string, data []byte) error {
	if s == nil {
		return errors.New("log store is not initialized")
	}
	if err := validateCategory(category); err != nil {
		return err
	}
	if err := validateComponent(stream, ErrInvalidLogStream); err != nil {
		return err
	}
	redacted := s.redact.RedactBytes(data)
	if len(redacted) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	remaining := redacted
	segmentLimit := s.config.MaxFileBytes
	if category != LogCategoryAudit && s.config.MaxTotalBytes < segmentLimit {
		segmentLimit = s.config.MaxTotalBytes
	}
	for len(remaining) > 0 {
		if err := s.ensureStreamDirLocked(category, stream); err != nil {
			return err
		}
		files, err := s.filesForStreamLocked(category, stream)
		if err != nil {
			return err
		}
		var current LogFile
		if len(files) > 0 {
			current = files[len(files)-1]
		}
		if current.Path == "" || current.Bytes >= segmentLimit {
			current = LogFile{Category: category, Stream: stream, Sequence: nextSequence(files), Path: s.segmentPath(category, stream, nextSequence(files))}
			if err := os.MkdirAll(filepath.Dir(current.Path), 0o750); err != nil {
				return fmt.Errorf("create log stream directory: %w", err)
			}
		}
		available := segmentLimit - current.Bytes
		if available <= 0 {
			continue
		}
		chunkSize := int64(len(remaining))
		if chunkSize > available {
			chunkSize = available
		}
		file, err := os.OpenFile(current.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return fmt.Errorf("open log segment: %w", err)
		}
		written, writeErr := file.Write(remaining[:chunkSize])
		closeErr := file.Close()
		if writeErr != nil {
			return fmt.Errorf("write log segment: %w", writeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close log segment: %w", closeErr)
		}
		if written == 0 {
			return ioErrNoProgress
		}
		remaining = remaining[written:]
	}
	return s.gcLocked()
}

var ioErrNoProgress = errors.New("log write made no progress")

// AppendText is convenient for line-oriented callers.
func (s *LogStore) AppendText(category LogCategory, stream, text string) error {
	return s.Append(category, stream, []byte(text))
}

// Write is an append spelling retained for file-store callers.
func (s *LogStore) Write(category LogCategory, stream string, data []byte) error {
	return s.Append(category, stream, data)
}

// AppendRecord returns the last segment touched after appending data.
func (s *LogStore) AppendRecord(category LogCategory, stream string, data []byte) (LogFile, error) {
	if err := s.Append(category, stream, data); err != nil {
		return LogFile{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.filesForStreamLocked(category, stream)
	if err != nil || len(files) == 0 {
		return LogFile{}, err
	}
	return files[len(files)-1], nil
}

// Read concatenates all segments for one logical stream in sequence order.
func (s *LogStore) Read(category LogCategory, stream string) ([]byte, error) {
	if s == nil {
		return nil, errors.New("log store is not initialized")
	}
	if err := validateCategory(category); err != nil {
		return nil, err
	}
	if err := validateComponent(stream, ErrInvalidLogStream); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.filesForStreamLocked(category, stream)
	if err != nil {
		return nil, err
	}
	var output []byte
	for _, file := range files {
		data, err := os.ReadFile(file.Path)
		if err != nil {
			return nil, fmt.Errorf("read log segment %s: %w", file.Path, err)
		}
		output = append(output, data...)
	}
	return output, nil
}

// ReadAll is an alias for Read.
func (s *LogStore) ReadAll(category LogCategory, stream string) ([]byte, error) {
	return s.Read(category, stream)
}

// List returns stream segments in sequence order.
func (s *LogStore) List(category LogCategory, stream string) ([]LogFile, error) {
	if s == nil {
		return nil, errors.New("log store is not initialized")
	}
	if err := validateCategory(category); err != nil {
		return nil, err
	}
	if err := validateComponent(stream, ErrInvalidLogStream); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.filesForStreamLocked(category, stream)
}

// Files is an alias for List.
func (s *LogStore) Files(category LogCategory, stream string) ([]LogFile, error) {
	return s.List(category, stream)
}

// Path resolves a logical stream path only after validating both components.
func (s *LogStore) Path(category LogCategory, stream string) (string, error) {
	if s == nil {
		return "", errors.New("log store is not initialized")
	}
	if err := validateCategory(category); err != nil {
		return "", err
	}
	if err := validateComponent(stream, ErrInvalidLogStream); err != nil {
		return "", err
	}
	return filepath.Join(s.root, string(category), stream), nil
}

// GC applies per-stream retention and then the ordinary total-byte budget.
// Audit files are deliberately omitted from both passes.
func (s *LogStore) GC() error {
	if s == nil {
		return errors.New("log store is not initialized")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gcLocked()
}

// GarbageCollect is a compatibility alias for GC.
func (s *LogStore) GarbageCollect() error { return s.GC() }

// OrdinaryBytes reports build/runtime bytes only. Audit evidence never
// contributes to this quota.
func (s *LogStore) OrdinaryBytes() (int64, error) {
	if s == nil {
		return 0, errors.New("log store is not initialized")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.scanFilesLocked(true)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, file := range files {
		total += file.Bytes
	}
	return total, nil
}

// AuditBytes reports audit bytes separately and is never used by GC.
func (s *LogStore) AuditBytes() (int64, error) {
	if s == nil {
		return 0, errors.New("log store is not initialized")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.scanFilesLocked(false)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, file := range files {
		if file.Category == LogCategoryAudit {
			total += file.Bytes
		}
	}
	return total, nil
}

// Close is intentionally a no-op: each append owns and closes its descriptor.
func (s *LogStore) Close() error { return nil }

func (s *LogStore) gcLocked() error {
	files, err := s.scanFilesLocked(true)
	if err != nil {
		return err
	}
	// First enforce runtime per-stream retention. Build retention is applied
	// by build execution below so "latest 20 builds" is not misread as twenty
	// segments for every historical build.
	byStream := make(map[string][]LogFile)
	for _, file := range files {
		key := string(file.Category) + "\x00" + file.Stream
		byStream[key] = append(byStream[key], file)
	}
	for _, streamFiles := range byStream {
		if streamFiles[0].Category == LogCategoryBuild {
			continue
		}
		limit := s.retentionFor(streamFiles[0].Category)
		if limit <= 0 || len(streamFiles) <= limit {
			continue
		}
		sortLogFiles(streamFiles)
		for _, file := range streamFiles[:len(streamFiles)-limit] {
			if err := os.Remove(file.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove retained log segment %s: %w", file.Path, err)
			}
		}
	}
	if s.config.RuntimeRetention > 0 {
		cutoff := time.Now().Add(-s.config.RuntimeRetention)
		for _, file := range files {
			if file.Category == LogCategoryRuntime && file.ModTime.Before(cutoff) {
				if err := os.Remove(file.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
		}
	}
	if err := s.gcBuildStreamsLocked(); err != nil {
		return err
	}

	files, err = s.scanFilesLocked(true)
	if err != nil {
		return err
	}
	var total int64
	for _, file := range files {
		total += file.Bytes
	}
	if total <= s.config.MaxTotalBytes {
		return nil
	}
	sortLogFiles(files)
	newestPath := files[len(files)-1].Path
	for _, file := range files {
		if total <= s.config.MaxTotalBytes {
			break
		}
		// Keep the newest segment if it alone exceeds the quota. Deleting the
		// just-written tail would make a successful append disappear.
		if len(files) == 1 || file.Path == newestPath {
			break
		}
		if err := os.Remove(file.Path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("remove over-budget log segment %s: %w", file.Path, err)
		}
		total -= file.Bytes
	}
	return nil
}

func (s *LogStore) gcBuildStreamsLocked() error {
	if s.config.MaxBuildFiles <= 0 {
		return nil
	}
	files, err := s.scanFilesLocked(true)
	if err != nil {
		return err
	}
	byStream := make(map[string][]LogFile)
	for _, file := range files {
		if file.Category == LogCategoryBuild {
			byStream[file.Stream] = append(byStream[file.Stream], file)
		}
	}
	if len(byStream) <= s.config.MaxBuildFiles {
		return nil
	}
	type buildStream struct {
		name    string
		updated time.Time
	}
	streams := make([]buildStream, 0, len(byStream))
	for name, streamFiles := range byStream {
		updated := streamFiles[0].ModTime
		for _, file := range streamFiles[1:] {
			if file.ModTime.After(updated) {
				updated = file.ModTime
			}
		}
		streams = append(streams, buildStream{name: name, updated: updated})
	}
	sort.Slice(streams, func(i, j int) bool {
		if streams[i].updated.Equal(streams[j].updated) {
			return streams[i].name < streams[j].name
		}
		return streams[i].updated.Before(streams[j].updated)
	})
	for _, stream := range streams[:len(streams)-s.config.MaxBuildFiles] {
		for _, file := range byStream[stream.name] {
			if err := os.Remove(file.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove expired build log %s: %w", file.Path, err)
			}
		}
		_ = os.Remove(filepath.Join(s.root, string(LogCategoryBuild), stream.name))
	}
	return nil
}

func (s *LogStore) retentionFor(category LogCategory) int {
	if s.config.MaxFilesPerStream > 0 {
		return s.config.MaxFilesPerStream
	}
	if category == LogCategoryBuild {
		return s.config.MaxBuildFiles
	}
	return s.config.MaxRuntimeFiles
}

func (s *LogStore) filesForStreamLocked(category LogCategory, stream string) ([]LogFile, error) {
	if err := validateCategory(category); err != nil {
		return nil, err
	}
	if err := validateComponent(stream, ErrInvalidLogStream); err != nil {
		return nil, err
	}
	streamPath := filepath.Join(s.root, string(category), stream)
	if info, err := os.Lstat(streamPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: stream directory is a symlink", ErrLogPathTraversal)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%w: stream path is not a directory", ErrInvalidLogStream)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect log stream: %w", err)
	}
	entries, err := os.ReadDir(streamPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []LogFile{}, nil
		}
		return nil, fmt.Errorf("scan log stream: %w", err)
	}
	files := make([]LogFile, 0, len(entries))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: symlink log segment %s", ErrLogPathTraversal, entry.Name())
		}
		sequence, ok := parseSegmentName(entry.Name())
		if !ok || entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect log segment: %w", err)
		}
		files = append(files, LogFile{Category: category, Stream: stream, Path: filepath.Join(s.root, string(category), stream, entry.Name()), Sequence: sequence, Bytes: info.Size(), ModTime: info.ModTime()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Sequence < files[j].Sequence })
	return files, nil
}

func (s *LogStore) ensureStreamDirLocked(category LogCategory, stream string) error {
	categoryPath := filepath.Join(s.root, string(category))
	if err := ensureDirectoryNoSymlink(categoryPath); err != nil {
		return fmt.Errorf("validate category directory: %w", err)
	}
	streamPath := filepath.Join(categoryPath, stream)
	if err := os.MkdirAll(streamPath, 0o750); err != nil {
		return fmt.Errorf("create log stream directory: %w", err)
	}
	if err := ensureDirectoryNoSymlink(streamPath); err != nil {
		return fmt.Errorf("validate log stream directory: %w", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(s.root)
	if err != nil {
		return fmt.Errorf("resolve log store root: %w", err)
	}
	resolvedStream, err := filepath.EvalSymlinks(streamPath)
	if err != nil {
		return fmt.Errorf("resolve log stream: %w", err)
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedStream)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ErrLogPathTraversal
	}
	return nil
}

func ensureDirectoryNoSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrLogPathTraversal
	}
	if !info.IsDir() {
		return ErrInvalidLogStream
	}
	return nil
}

func (s *LogStore) scanFilesLocked(ordinaryOnly bool) ([]LogFile, error) {
	result := make([]LogFile, 0)
	categories := []LogCategory{LogCategoryBuild, LogCategoryRuntime}
	if !ordinaryOnly {
		categories = append(categories, LogCategoryAudit)
	}
	for _, category := range categories {
		categoryRoot := filepath.Join(s.root, string(category))
		entries, err := os.ReadDir(categoryRoot)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("scan %s logs: %w", category, err)
		}
		for _, streamEntry := range entries {
			if streamEntry.Type()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("%w: symlink stream %s", ErrLogPathTraversal, streamEntry.Name())
			}
			if !streamEntry.IsDir() || validateComponent(streamEntry.Name(), ErrInvalidLogStream) != nil {
				continue
			}
			files, err := s.filesForStreamLocked(category, streamEntry.Name())
			if err != nil {
				return nil, err
			}
			result = append(result, files...)
		}
	}
	return result, nil
}

func (s *LogStore) segmentPath(category LogCategory, stream string, sequence int) string {
	return filepath.Join(s.root, string(category), stream, fmt.Sprintf("segment-%06d.log", sequence))
}

func nextSequence(files []LogFile) int {
	if len(files) == 0 {
		return 0
	}
	return files[len(files)-1].Sequence + 1
}

func parseSegmentName(name string) (int, bool) {
	if !strings.HasPrefix(name, "segment-") || !strings.HasSuffix(name, ".log") {
		return 0, false
	}
	value := strings.TrimSuffix(strings.TrimPrefix(name, "segment-"), ".log")
	if value == "" {
		return 0, false
	}
	sequence, err := strconv.Atoi(value)
	return sequence, err == nil && sequence >= 0
}

func sortLogFiles(files []LogFile) {
	sort.Slice(files, func(i, j int) bool {
		if !files[i].ModTime.Equal(files[j].ModTime) {
			return files[i].ModTime.Before(files[j].ModTime)
		}
		if files[i].Path != files[j].Path {
			return files[i].Path < files[j].Path
		}
		return files[i].Sequence < files[j].Sequence
	})
}

func validateCategory(category LogCategory) error {
	switch category {
	case LogCategoryBuild, LogCategoryRuntime, LogCategoryAudit:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidLogCategory, category)
	}
}

func validateComponent(value string, kind error) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || trimmed == "." || trimmed == ".." {
		return fmt.Errorf("%w: %q", kind, value)
	}
	if filepath.IsAbs(trimmed) || strings.ContainsAny(trimmed, `/\\`) || strings.Contains(trimmed, "..") {
		return fmt.Errorf("%w: %q", ErrLogPathTraversal, value)
	}
	for _, runeValue := range trimmed {
		if unicode.IsControl(runeValue) {
			return fmt.Errorf("%w: control character", kind)
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
