// Package context builds the smallest authorized context package that can be
// handed to an AI provider. Source files and logs are data, never instructions;
// they are marked untrusted and redacted before size accounting or hashing.
package context

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

const (
	ScopeSourceFiles    = "source.files"
	ScopeBuildLogs      = "build.logs"
	ScopeObjectVersions = "objects.versions"
	ScopeSecretMetadata = "secrets.metadata"
	DefaultMaxBytes     = 64 * 1024
	DefaultMaxFileBytes = 16 * 1024
	DefaultMaxLogBytes  = 24 * 1024
	DefaultMaxLogLines  = 256
	DefaultTemplate     = "context-v1"
)

// Stable aliases make the API discoverable without creating alternate scope
// values in serialized packages.
const (
	ScopeFiles   = ScopeSourceFiles
	ScopeLogs    = ScopeBuildLogs
	ScopeObjects = ScopeObjectVersions
	ScopeSecrets = ScopeSecretMetadata
	ScopeSource  = ScopeSourceFiles
	ScopeBuild   = ScopeBuildLogs
)

var (
	ErrInvalidRequest    = errors.New("AI context request is invalid")
	ErrUnauthorizedScope = errors.New("AI context scope is not authorized")
	ErrCrossApplication  = errors.New("AI context contains a cross-application object")
	ErrOversized         = errors.New("AI context exceeds its size limit")
	ErrUnsafePath        = errors.New("AI context source path is unsafe")
	ErrInvalidLogWindow  = errors.New("AI context log window is invalid")
)

// SourceFile is an input fact and an output fact. Content is always redacted
// and marked untrusted in a built Package. Digest is optional input metadata;
// the builder computes a digest over the redacted content for evidence.
type SourceFile struct {
	ApplicationID domain.ID `json:"application_id,omitempty"`
	Scope         string    `json:"scope,omitempty"`
	Path          string    `json:"path"`
	Content       string    `json:"content,omitempty"`
	Digest        string    `json:"digest,omitempty"`
	Bytes         int       `json:"bytes,omitempty"`
	Truncated     bool      `json:"truncated,omitempty"`
	Untrusted     bool      `json:"untrusted"`
}

// LogWindow is both the input shape and the redacted output shape. Lines are
// retained only as a bounded convenience view; Content remains the canonical
// redacted payload.
type LogWindow struct {
	ApplicationID domain.ID `json:"application_id,omitempty"`
	Scope         string    `json:"scope,omitempty"`
	Source        string    `json:"source"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	WindowStart   time.Time `json:"-"`
	WindowEnd     time.Time `json:"-"`
	From          time.Time `json:"-"`
	To            time.Time `json:"-"`
	Content       string    `json:"content,omitempty"`
	Lines         []string  `json:"lines,omitempty"`
	Bytes         int       `json:"bytes,omitempty"`
	Truncated     bool      `json:"truncated,omitempty"`
	Untrusted     bool      `json:"untrusted"`
}

// ObjectVersion is intentionally metadata-only. It contains no object body,
// source text, environment value, or log line.
type ObjectVersion struct {
	ApplicationID domain.ID `json:"application_id,omitempty"`
	Kind          string    `json:"kind"`
	ID            string    `json:"id"`
	Version       string    `json:"version"`
	Scope         string    `json:"scope,omitempty"`
}

// SecretFact may carry Value only inside the builder call so known canaries
// can be removed from source/log content. Value has no JSON representation and
// is never copied into Package.Secrets.
type SecretFact struct {
	ApplicationID domain.ID `json:"application_id,omitempty"`
	Scope         string    `json:"scope,omitempty"`
	Name          string    `json:"name"`
	SecretName    string    `json:"-"`
	Exists        bool      `json:"exists"`
	Present       bool      `json:"-"`
	Verified      bool      `json:"verified"`
	Value         string    `json:"-"`
}

type SecretMetadata struct {
	ApplicationID domain.ID `json:"application_id,omitempty"`
	Scope         string    `json:"scope,omitempty"`
	Name          string    `json:"name"`
	Exists        bool      `json:"exists"`
	Verified      bool      `json:"verified"`
}

// Input is deliberately an in-memory fact shape. Callers must explicitly
// enumerate AuthorizedScopes; there is no implicit "all data" mode.
type Input struct {
	ApplicationID domain.ID
	TaskType      string
	Profile       string

	AuthorizedScopes []string
	// Scopes is a compatibility spelling for adapters that already use a
	// generic scope field. AuthorizedScopes remains the canonical field.
	Scopes []string

	SourceFiles []SourceFile
	Logs        []LogWindow
	Objects     []ObjectVersion
	Secrets     []SecretFact

	RelevantFiles      []string
	RelevantLogSources []string
	RelevantObjectIDs  []string
	KnownSecretValues  []string
	MaxBytes           int
	MaxFileBytes       int
	MaxLogBytes        int
	MaxLogLines        int
	TemplateVersion    string
}

type BuildRequest = Input
type Request = Input

// Config contains builder-wide finite limits and known secret values. It does
// not contain or persist any source/log data.
type Config struct {
	MaxBytes          int
	MaxFileBytes      int
	MaxLogBytes       int
	MaxLogLines       int
	TemplateVersion   string
	KnownSecretValues []string
}

// Package is the rich builder output. DomainContext converts it to the
// shared domain contract without exposing file/log content to callers that
// only need the provider-facing manifest.
type Package struct {
	ID               domain.ID            `json:"id"`
	ApplicationID    domain.ID            `json:"application_id"`
	TaskType         string               `json:"task_type"`
	Profile          string               `json:"profile"`
	Scope            []string             `json:"scope"`
	AuthorizedScopes []string             `json:"authorized_scopes"`
	ObjectVersions   map[string]string    `json:"object_versions"`
	Objects          []ObjectVersion      `json:"objects,omitempty"`
	Files            []SourceFile         `json:"files,omitempty"`
	Logs             []LogWindow          `json:"logs,omitempty"`
	Secrets          []SecretMetadata     `json:"secrets,omitempty"`
	SourceRefs       []domain.EvidenceRef `json:"source_refs"`
	ManifestDigest   string               `json:"manifest_digest"`
	Bytes            int64                `json:"bytes"`
	Authorized       bool                 `json:"authorized"`
	Redacted         bool                 `json:"redacted"`
	UntrustedData    bool                 `json:"untrusted_data"`
	Truncated        bool                 `json:"truncated"`
	TemplateVersion  string               `json:"template_version"`
}

// ContextPackage is the explicit product-facing spelling used by the M6
// architecture document. It aliases Package so no conversion or copy is
// needed at orchestration boundaries.
type ContextPackage = Package

// DomainContext is the only provider-facing representation. It contains
// references, versions, and flags, not raw source or log bodies.
func (p Package) DomainContext() domain.AIContextPackage {
	versions := make(map[string]string, len(p.ObjectVersions))
	for key, value := range p.ObjectVersions {
		versions[key] = value
	}
	return domain.AIContextPackage{
		ID: p.ID, ApplicationID: p.ApplicationID, TaskType: p.TaskType, Profile: p.Profile,
		Scope: append([]string(nil), p.Scope...), ObjectVersions: versions,
		SourceRefs: append([]domain.EvidenceRef(nil), p.SourceRefs...), ManifestDigest: p.ManifestDigest,
		Bytes: p.Bytes, Authorized: p.Authorized, Redacted: p.Redacted,
		UntrustedData: p.UntrustedData, TemplateVersion: p.TemplateVersion,
	}
}

func (p Package) AIContextPackage() domain.AIContextPackage { return p.DomainContext() }
func (p Package) AsDomain() domain.AIContextPackage         { return p.DomainContext() }

// Validate checks the safe manifest and the shared domain contract. It does
// not re-read or inspect an external workspace.
func (p Package) Validate() error {
	if err := p.DomainContext().Validate(); err != nil {
		return err
	}
	if !p.Authorized || !p.Redacted || !p.UntrustedData {
		return ErrInvalidRequest
	}
	for _, file := range p.Files {
		if file.ApplicationID != p.ApplicationID || file.Scope != ScopeSourceFiles || !file.Untrusted || strings.Contains(file.Content, "\x00") {
			return ErrInvalidRequest
		}
	}
	for _, log := range p.Logs {
		if log.ApplicationID != p.ApplicationID || log.Scope != ScopeBuildLogs || !log.Untrusted {
			return ErrInvalidRequest
		}
	}
	for _, object := range p.Objects {
		if object.ApplicationID != p.ApplicationID || object.Scope != ScopeObjectVersions {
			return ErrInvalidRequest
		}
	}
	for _, secret := range p.Secrets {
		if secret.ApplicationID != p.ApplicationID || secret.Scope != ScopeSecretMetadata {
			return ErrInvalidRequest
		}
	}
	return nil
}

// Builder enforces explicit scopes, one application boundary, and finite
// redaction/truncation before making a manifest visible.
type Builder struct {
	config Config
}

type ContextBuilder = Builder

func New(configs ...Config) *Builder {
	config := Config{}
	if len(configs) > 0 {
		config = configs[0]
	}
	if config.MaxBytes <= 0 {
		config.MaxBytes = DefaultMaxBytes
	}
	if config.MaxFileBytes <= 0 {
		config.MaxFileBytes = DefaultMaxFileBytes
	}
	if config.MaxLogBytes <= 0 {
		config.MaxLogBytes = DefaultMaxLogBytes
	}
	if config.MaxLogLines <= 0 {
		config.MaxLogLines = DefaultMaxLogLines
	}
	if strings.TrimSpace(config.TemplateVersion) == "" {
		config.TemplateVersion = DefaultTemplate
	}
	return &Builder{config: config}
}

func NewBuilder(configs ...Config) *Builder { return New(configs...) }

// BuildPackage is an intention-revealing alias for callers that want to make
// the richer file/log manifest explicit.
func (b *Builder) BuildPackage(input Input) (Package, error) { return b.Build(input) }

// BuildContext projects the redacted manifest into the shared domain object
// expected by contracts.AIProvider.
func (b *Builder) BuildContext(input Input) (domain.AIContextPackage, error) {
	pkg, err := b.Build(input)
	if err != nil {
		return domain.AIContextPackage{}, err
	}
	return pkg.DomainContext(), nil
}

func (b *Builder) BuildAIContext(input Input) (domain.AIContextPackage, error) {
	return b.BuildContext(input)
}

// Build constructs a deterministic package. Any cross-app or unauthorized
// fact aborts the entire build; no partial package is returned.
func (b *Builder) Build(input Input) (Package, error) {
	if b == nil {
		return Package{}, fmt.Errorf("%w: builder is nil", ErrInvalidRequest)
	}
	if input.ApplicationID.Empty() || strings.TrimSpace(input.TaskType) == "" {
		return Package{}, fmt.Errorf("%w: application and task type are required", ErrInvalidRequest)
	}
	profile := normalizeProfile(input.Profile)
	if profile == "" {
		profile = "local"
	}
	if !validProfile(profile) {
		return Package{}, fmt.Errorf("%w: unknown profile", ErrInvalidRequest)
	}
	templateVersion := strings.TrimSpace(input.TemplateVersion)
	if templateVersion == "" {
		templateVersion = b.config.TemplateVersion
	}
	authorized := input.AuthorizedScopes
	if len(authorized) == 0 {
		authorized = input.Scopes
	}
	authorizedSet, authorizedList := normalizeScopes(authorized)
	if len(authorizedSet) == 0 {
		return Package{}, fmt.Errorf("%w: at least one authorized scope is required", ErrUnauthorizedScope)
	}
	input.Logs = append([]LogWindow(nil), input.Logs...)
	for i := range input.Logs {
		normalizeLogWindow(&input.Logs[i])
	}
	input.Secrets = append([]SecretFact(nil), input.Secrets...)
	for i := range input.Secrets {
		if strings.TrimSpace(input.Secrets[i].Name) == "" {
			input.Secrets[i].Name = strings.TrimSpace(input.Secrets[i].SecretName)
		}
		if input.Secrets[i].Present {
			input.Secrets[i].Exists = true
		}
	}
	for _, file := range input.SourceFiles {
		if err := ensureApplication(input.ApplicationID, file.ApplicationID); err != nil {
			return Package{}, err
		}
		if err := ensureScope(authorizedSet, file.Scope, ScopeSourceFiles); err != nil {
			return Package{}, err
		}
		if err := safeSourcePath(file.Path); err != nil {
			return Package{}, err
		}
	}
	for _, log := range input.Logs {
		if err := ensureApplication(input.ApplicationID, log.ApplicationID); err != nil {
			return Package{}, err
		}
		if err := ensureScope(authorizedSet, log.Scope, ScopeBuildLogs); err != nil {
			return Package{}, err
		}
		if !log.Start.IsZero() && !log.End.IsZero() && log.End.Before(log.Start) {
			return Package{}, fmt.Errorf("%w: %s", ErrInvalidLogWindow, log.Source)
		}
	}
	for _, object := range input.Objects {
		if err := ensureApplication(input.ApplicationID, object.ApplicationID); err != nil {
			return Package{}, err
		}
		if err := ensureScope(authorizedSet, object.Scope, ScopeObjectVersions); err != nil {
			return Package{}, err
		}
		if strings.TrimSpace(object.Kind) == "" || strings.TrimSpace(object.ID) == "" || strings.TrimSpace(object.Version) == "" {
			return Package{}, fmt.Errorf("%w: object version is incomplete", ErrInvalidRequest)
		}
	}
	for _, secret := range input.Secrets {
		if err := ensureApplication(input.ApplicationID, secret.ApplicationID); err != nil {
			return Package{}, err
		}
		if err := ensureScope(authorizedSet, secret.Scope, ScopeSecretMetadata); err != nil {
			return Package{}, err
		}
		if strings.TrimSpace(secret.Name) == "" {
			return Package{}, fmt.Errorf("%w: secret name is required", ErrInvalidRequest)
		}
	}

	maxBytes, maxFileBytes, maxLogBytes, maxLogLines := effectiveLimits(b.config, input)
	knownSecrets := append([]string(nil), b.config.KnownSecretValues...)
	knownSecrets = append(knownSecrets, input.KnownSecretValues...)
	for _, secret := range input.Secrets {
		if secret.Value != "" {
			knownSecrets = append(knownSecrets, secret.Value)
		}
	}
	redactor := foundation.NewRedactor(knownSecrets...)
	result := Package{
		ApplicationID: input.ApplicationID, TaskType: strings.TrimSpace(input.TaskType), Profile: profile,
		AuthorizedScopes: authorizedList, Authorized: true, Redacted: true, UntrustedData: true,
		TemplateVersion: templateVersion, ObjectVersions: make(map[string]string),
	}
	remaining := maxBytes

	files := append([]SourceFile(nil), input.SourceFiles...)
	sort.SliceStable(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	for _, file := range files {
		if !relevantFile(file.Path, input.RelevantFiles) {
			continue
		}
		content := redactUntrusted(redactor.RedactString(file.Content))
		content, truncated := truncate(content, minPositive(maxFileBytes, remaining))
		if len(content) < len(redactor.RedactString(file.Content)) {
			truncated = true
		}
		file.ApplicationID = input.ApplicationID
		file.Scope = ScopeSourceFiles
		file.Path = redactUntrusted(file.Path)
		file.Content = content
		file.Digest = "sha256:" + hashText(ScopeSourceFiles, file.Path, content)
		file.Bytes = len(content)
		file.Truncated = truncated
		file.Untrusted = true
		result.Files = append(result.Files, file)
		remaining -= len(content)
		if remaining < 0 {
			remaining = 0
		}
		result.Truncated = result.Truncated || truncated
	}

	logs := append([]LogWindow(nil), input.Logs...)
	sort.SliceStable(logs, func(i, j int) bool {
		if logs[i].Start.Equal(logs[j].Start) {
			return logs[i].Source < logs[j].Source
		}
		return logs[i].Start.Before(logs[j].Start)
	})
	for _, log := range logs {
		if !relevantLog(log.Source, input.RelevantLogSources) {
			continue
		}
		content := log.Content
		if content == "" && len(log.Lines) > 0 {
			content = strings.Join(log.Lines, "\n")
		}
		content = redactUntrusted(redactor.RedactString(content))
		lines := strings.Split(content, "\n")
		truncated := false
		if len(lines) == 1 && lines[0] == "" {
			lines = nil
		}
		if maxLogLines > 0 && len(lines) > maxLogLines {
			lines = lines[:maxLogLines]
			content = strings.Join(lines, "\n")
			truncated = true
		}
		before := content
		content, byteTruncated := truncate(content, minPositive(maxLogBytes, remaining))
		truncated = truncated || byteTruncated || len(content) < len(before)
		log.ApplicationID = input.ApplicationID
		log.Scope = ScopeBuildLogs
		log.Source = redactUntrusted(log.Source)
		log.Start = log.Start.UTC()
		log.End = log.End.UTC()
		log.Content = content
		if content == "" {
			log.Lines = nil
		} else {
			log.Lines = strings.Split(content, "\n")
		}
		log.Bytes = len(content)
		log.Truncated = truncated
		log.Untrusted = true
		result.Logs = append(result.Logs, log)
		remaining -= len(content)
		if remaining < 0 {
			remaining = 0
		}
		result.Truncated = result.Truncated || truncated
	}

	objects := append([]ObjectVersion(nil), input.Objects...)
	sort.SliceStable(objects, func(i, j int) bool {
		left := objects[i].Kind + "\x00" + objects[i].ID
		right := objects[j].Kind + "\x00" + objects[j].ID
		return left < right
	})
	for _, object := range objects {
		if !relevantObject(object.ID, input.RelevantObjectIDs) {
			continue
		}
		object.ApplicationID = input.ApplicationID
		object.Scope = ScopeObjectVersions
		result.Objects = append(result.Objects, object)
		result.ObjectVersions[object.Kind+":"+object.ID] = object.Version
	}

	secrets := append([]SecretFact(nil), input.Secrets...)
	sort.SliceStable(secrets, func(i, j int) bool { return secrets[i].Name < secrets[j].Name })
	for _, secret := range secrets {
		result.Secrets = append(result.Secrets, SecretMetadata{ApplicationID: input.ApplicationID, Scope: ScopeSecretMetadata, Name: secret.Name, Exists: secret.Exists, Verified: secret.Verified})
	}
	if err := enforcePayloadLimit(&result, maxBytes); err != nil {
		return Package{}, err
	}

	result.Scope = scopesPresent(result)
	result.SourceRefs = buildRefs(result)
	result.Bytes = payloadBytes(result)
	if result.Bytes <= 0 {
		result.Bytes = 1
	}
	result.ManifestDigest = manifestDigest(result)
	result.ID = domain.ID("aictx_" + hashText(result.ApplicationID.String(), result.TaskType, result.Profile, result.TemplateVersion, result.ManifestDigest)[:32])
	if result.Bytes > int64(maxBytes) {
		return Package{}, fmt.Errorf("%w: manifest payload is larger than max bytes", ErrOversized)
	}
	if err := result.Validate(); err != nil {
		return Package{}, fmt.Errorf("%w: built context failed validation: %v", ErrInvalidRequest, err)
	}
	return result, nil
}

func effectiveLimits(config Config, input Input) (int, int, int, int) {
	maxBytes, maxFileBytes, maxLogBytes, maxLogLines := config.MaxBytes, config.MaxFileBytes, config.MaxLogBytes, config.MaxLogLines
	if input.MaxBytes > 0 {
		maxBytes = input.MaxBytes
	}
	if input.MaxFileBytes > 0 {
		maxFileBytes = input.MaxFileBytes
	}
	if input.MaxLogBytes > 0 {
		maxLogBytes = input.MaxLogBytes
	}
	if input.MaxLogLines > 0 {
		maxLogLines = input.MaxLogLines
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if maxFileBytes <= 0 {
		maxFileBytes = DefaultMaxFileBytes
	}
	if maxLogBytes <= 0 {
		maxLogBytes = DefaultMaxLogBytes
	}
	if maxLogLines <= 0 {
		maxLogLines = DefaultMaxLogLines
	}
	return maxBytes, maxFileBytes, maxLogBytes, maxLogLines
}

func ensureApplication(expected, actual domain.ID) error {
	if !actual.Empty() && actual != expected {
		return fmt.Errorf("%w: expected application %s", ErrCrossApplication, expected)
	}
	return nil
}

func normalizeLogWindow(log *LogWindow) {
	if log == nil {
		return
	}
	if log.Start.IsZero() {
		if !log.WindowStart.IsZero() {
			log.Start = log.WindowStart
		} else {
			log.Start = log.From
		}
	}
	if log.End.IsZero() {
		if !log.WindowEnd.IsZero() {
			log.End = log.WindowEnd
		} else {
			log.End = log.To
		}
	}
}

func normalizeScopes(scopes []string) (map[string]struct{}, []string) {
	set := make(map[string]struct{})
	for _, value := range scopes {
		scope := normalizeScope(value)
		if scope != "" {
			set[scope] = struct{}{}
		}
	}
	list := make([]string, 0, len(set))
	for scope := range set {
		list = append(list, scope)
	}
	sort.Strings(list)
	return set, list
}

func normalizeScope(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "source", "files", "source_files", "source.files":
		return ScopeSourceFiles
	case "logs", "build_logs", "build.logs", "log_window":
		return ScopeBuildLogs
	case "objects", "object_versions", "objects.versions", "versions":
		return ScopeObjectVersions
	case "secrets", "secret_metadata", "secrets.metadata":
		return ScopeSecretMetadata
	default:
		return ""
	}
}

func ensureScope(authorized map[string]struct{}, actual, fallback string) error {
	scope := normalizeScope(actual)
	if scope == "" {
		scope = fallback
	}
	if _, ok := authorized[scope]; !ok {
		return fmt.Errorf("%w: %s", ErrUnauthorizedScope, scope)
	}
	return nil
}

func safeSourcePath(value string) error {
	path := strings.TrimSpace(value)
	if path == "" {
		return fmt.Errorf("%w: empty path", ErrUnsafePath)
	}
	clean := filepath.Clean(filepath.ToSlash(path))
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." || strings.HasPrefix(clean, "/") {
		return fmt.Errorf("%w: path escapes source scope", ErrUnsafePath)
	}
	return nil
}

func relevantFile(path string, filter []string) bool {
	if len(filter) == 0 {
		return true
	}
	path = filepath.ToSlash(filepath.Clean(path))
	for _, value := range filter {
		if path == filepath.ToSlash(filepath.Clean(value)) {
			return true
		}
	}
	return false
}

func relevantLog(source string, filter []string) bool {
	if len(filter) == 0 {
		return true
	}
	for _, value := range filter {
		if source == value {
			return true
		}
	}
	return false
}

func relevantObject(id string, filter []string) bool {
	if len(filter) == 0 {
		return true
	}
	for _, value := range filter {
		if id == value {
			return true
		}
	}
	return false
}

func truncate(value string, maxBytes int) (string, bool) {
	if maxBytes <= 0 {
		return "", value != ""
	}
	if len(value) <= maxBytes {
		return value, false
	}
	cut := value[:maxBytes]
	// Drop an incomplete trailing rune instead of inserting a replacement
	// rune that could make the result larger than the byte budget.
	cut = strings.ToValidUTF8(cut, "")
	return cut, true
}

var canaryRE = regexp.MustCompile(`(?i)(?:[a-z0-9]+[-_ ])?(?:secret[-_ ])?canary(?:[-_ ][a-z0-9]+)*`)

func redactUntrusted(value string) string {
	if value == "" {
		return value
	}
	return canaryRE.ReplaceAllString(value, foundation.RedactedValue)
}

func scopesPresent(p Package) []string {
	set := make(map[string]struct{})
	if len(p.Files) > 0 {
		set[ScopeSourceFiles] = struct{}{}
	}
	if len(p.Logs) > 0 {
		set[ScopeBuildLogs] = struct{}{}
	}
	if len(p.Objects) > 0 {
		set[ScopeObjectVersions] = struct{}{}
	}
	if len(p.Secrets) > 0 {
		set[ScopeSecretMetadata] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for scope := range set {
		result = append(result, scope)
	}
	sort.Strings(result)
	return result
}

func buildRefs(p Package) []domain.EvidenceRef {
	refs := make([]domain.EvidenceRef, 0, len(p.Files)+len(p.Logs)+len(p.Objects)+len(p.Secrets))
	for _, file := range p.Files {
		digest := "sha256:" + hashText(ScopeSourceFiles, file.Path, file.Content)
		refs = append(refs, domain.EvidenceRef{ID: domain.ID("ctxref_" + hashText("file", file.Path)[:24]), Kind: ScopeSourceFiles, Digest: digest, Locator: "context://file/" + hashText(file.Path)[:24]})
	}
	for _, log := range p.Logs {
		digest := "sha256:" + hashText(ScopeBuildLogs, log.Source, log.Start.UTC().Format(time.RFC3339Nano), log.End.UTC().Format(time.RFC3339Nano), log.Content)
		refs = append(refs, domain.EvidenceRef{ID: domain.ID("ctxref_" + hashText("log", log.Source, log.Start.UTC().String())[:24]), Kind: ScopeBuildLogs, Digest: digest, Locator: "context://log/" + hashText(log.Source)[:24]})
	}
	for _, object := range p.Objects {
		digest := "sha256:" + hashText(ScopeObjectVersions, object.Kind, object.ID, object.Version)
		refs = append(refs, domain.EvidenceRef{ID: domain.ID("ctxref_" + hashText("object", object.Kind, object.ID)[:24]), Kind: ScopeObjectVersions, Digest: digest, Locator: "context://object/" + hashText(object.Kind, object.ID)[:24]})
	}
	for _, secret := range p.Secrets {
		digest := "sha256:" + hashText(ScopeSecretMetadata, secret.Name, fmt.Sprint(secret.Exists), fmt.Sprint(secret.Verified))
		refs = append(refs, domain.EvidenceRef{ID: domain.ID("ctxref_" + hashText("secret", secret.Name)[:24]), Kind: ScopeSecretMetadata, Digest: digest, Locator: "context://secret/" + hashText(secret.Name)[:24]})
	}
	sort.SliceStable(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	return refs
}

func payloadBytes(p Package) int64 {
	var total int64
	for _, file := range p.Files {
		total += int64(len(file.Content))
	}
	for _, log := range p.Logs {
		total += int64(len(log.Content))
	}
	for _, object := range p.Objects {
		total += int64(len(object.Kind) + len(object.ID) + len(object.Version))
	}
	for _, secret := range p.Secrets {
		total += int64(len(secret.Name) + len(secret.Scope))
	}
	return total
}

// enforcePayloadLimit accounts for object/secret metadata as well as source
// and log bytes. The first pass uses per-source limits; this second pass keeps
// the whole package within MaxBytes without dropping identity/version facts.
func enforcePayloadLimit(p *Package, maxBytes int) error {
	if p == nil || maxBytes <= 0 {
		return fmt.Errorf("%w: max bytes must be positive", ErrOversized)
	}
	for payloadBytes(*p) > int64(maxBytes) {
		changed := false
		for i := len(p.Logs) - 1; i >= 0 && payloadBytes(*p) > int64(maxBytes); i-- {
			current := len(p.Logs[i].Content)
			if current == 0 {
				continue
			}
			need := int(payloadBytes(*p) - int64(maxBytes))
			target := current - need
			if target < 0 {
				target = 0
			}
			content, _ := truncate(p.Logs[i].Content, target)
			p.Logs[i].Content = content
			p.Logs[i].Lines = splitLines(content)
			p.Logs[i].Bytes = len(content)
			p.Logs[i].Truncated = true
			p.Truncated = true
			changed = true
		}
		for i := len(p.Files) - 1; i >= 0 && payloadBytes(*p) > int64(maxBytes); i-- {
			current := len(p.Files[i].Content)
			if current == 0 {
				continue
			}
			need := int(payloadBytes(*p) - int64(maxBytes))
			target := current - need
			if target < 0 {
				target = 0
			}
			content, _ := truncate(p.Files[i].Content, target)
			p.Files[i].Content = content
			p.Files[i].Digest = "sha256:" + hashText(ScopeSourceFiles, p.Files[i].Path, content)
			p.Files[i].Bytes = len(content)
			p.Files[i].Truncated = true
			p.Truncated = true
			changed = true
		}
		if !changed {
			return fmt.Errorf("%w: object and secret metadata exceed max bytes", ErrOversized)
		}
	}
	return nil
}

func splitLines(content string) []string {
	if content == "" {
		return nil
	}
	return strings.Split(content, "\n")
}

func manifestDigest(p Package) string {
	value := struct {
		ApplicationID domain.ID
		TaskType      string
		Profile       string
		Scope         []string
		Objects       []ObjectVersion
		Files         []SourceFile
		Logs          []LogWindow
		Secrets       []SecretMetadata
		Template      string
	}{p.ApplicationID, p.TaskType, p.Profile, p.Scope, p.Objects, p.Files, p.Logs, p.Secrets, p.TemplateVersion}
	encoded, _ := json.Marshal(value)
	return "sha256:" + hashText(string(encoded))
}

func hashText(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func minPositive(left, right int) int {
	if right <= 0 {
		return left
	}
	if left <= 0 || right < left {
		return right
	}
	return left
}

func validProfile(value string) bool {
	switch value {
	case "china", "global", "local", "disabled":
		return true
	default:
		return false
	}
}

func normalizeProfile(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "china", "cn", "mainland", "中国", "中国大陆":
		return "china"
	case "global", "worldwide", "全球":
		return "global"
	case "local", "on-premise", "on_premise", "本地":
		return "local"
	case "disabled", "off", "none", "关闭":
		return "disabled"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}
