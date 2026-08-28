// Package tools contains the versioned, fail-closed allow-list used by the
// controlled AI action runner.  A catalog entry is a policy boundary, not a
// command template: the runner only implements the small set of operation
// kinds declared here and never evaluates model-provided shell text.
package tools

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

const (
	ToolWorkspaceRead        = "workspace.read"
	ToolWorkspaceInspect     = "workspace.inspect"
	ToolWorkspaceSearch      = "workspace.search"
	ToolWorkspaceBuildTest   = "workspace.build_test"
	ToolWorkspaceHealthCheck = "workspace.health_check"
	ToolWorkspaceDraftEdit   = "workspace.draft_edit"
	ToolWorkspacePatch       = "workspace.patch_candidate"

	ToolVersionV1 = "v1"
)

// Descriptive aliases keep callers from inventing a second serialized tool
// ID while accommodating the names used by the product and test documents.
const (
	ToolWorkspaceReadFile       = ToolWorkspaceRead
	ToolWorkspaceBuild          = ToolWorkspaceBuildTest
	ToolWorkspaceDraft          = ToolWorkspaceDraftEdit
	ToolWorkspacePatchCandidate = ToolWorkspacePatch
)

// RiskClass is intentionally a closed set.  It is serialized as R0-R3 so a
// provider cannot invent a more permissive risk name that bypasses policy.
type RiskClass string

const (
	RiskR0 RiskClass = "R0" // bounded read-only inspection
	RiskR1 RiskClass = "R1" // bounded, no-state-changing validation
	RiskR2 RiskClass = "R2" // unpublished candidate change
	RiskR3 RiskClass = "R3" // production/controller handoff only
)

func (r RiskClass) Valid() bool {
	switch r {
	case RiskR0, RiskR1, RiskR2, RiskR3:
		return true
	default:
		return false
	}
}

// ToolKind is the only execution vocabulary understood by the built-in
// runner.  In particular, there is no shell/exec kind.
type ToolKind string

const (
	KindRead        ToolKind = "read"
	KindInspect     ToolKind = "inspect"
	KindSearch      ToolKind = "search"
	KindBuildTest   ToolKind = "build_test"
	KindHealthCheck ToolKind = "health_check"
	KindDraftEdit   ToolKind = "draft_edit"
	KindPatch       ToolKind = "patch_candidate"
)

func (k ToolKind) Valid() bool {
	switch k {
	case KindRead, KindInspect, KindSearch, KindBuildTest, KindHealthCheck, KindDraftEdit, KindPatch:
		return true
	default:
		return false
	}
}

// WorkspaceScope describes where a tool may resolve its relative path.
type WorkspaceScope string

const (
	ScopeWorkspace WorkspaceScope = "workspace"
	ScopeDraft     WorkspaceScope = "draft"
)

func (s WorkspaceScope) Valid() bool {
	return s == ScopeWorkspace || s == ScopeDraft
}

// NetworkMode is deliberately small.  Built-in tools use NetworkDisabled;
// no built-in implementation opens sockets or contacts a provider.
type NetworkMode string

const (
	NetworkDisabled  NetworkMode = "disabled"
	NetworkAllowlist NetworkMode = "allowlist"
)

type NetworkPolicy struct {
	Mode          NetworkMode `json:"mode"`
	AllowedCIDRs  []string    `json:"allowed_cidrs,omitempty"`
	AllowMetadata bool        `json:"allow_metadata,omitempty"`
}

func (p NetworkPolicy) normalized() NetworkPolicy {
	if strings.TrimSpace(string(p.Mode)) == "" {
		p.Mode = NetworkDisabled
	}
	p.AllowedCIDRs = append([]string(nil), p.AllowedCIDRs...)
	sort.Strings(p.AllowedCIDRs)
	return p
}

func (p NetworkPolicy) Validate() error {
	p = p.normalized()
	switch p.Mode {
	case NetworkDisabled:
		if len(p.AllowedCIDRs) != 0 || p.AllowMetadata {
			return fmt.Errorf("%w: disabled network policy cannot allow cidrs or metadata", ErrPolicy)
		}
	case NetworkAllowlist:
		if len(p.AllowedCIDRs) == 0 {
			return fmt.Errorf("%w: allowlist network policy requires cidrs", ErrPolicy)
		}
		if p.AllowMetadata {
			return fmt.Errorf("%w: cloud metadata is never allowed", ErrPolicy)
		}
	default:
		return fmt.Errorf("%w: unsupported network mode %q", ErrPolicy, p.Mode)
	}
	return nil
}

// ResourceLimits are enforced by the runner in addition to the catalog's
// declaration. Zero means "use the catalog declaration" on a request and
// means "no override" on a descriptor.
type ResourceLimits struct {
	MaxDuration    time.Duration `json:"max_duration"`
	MaxInputBytes  int64         `json:"max_input_bytes"`
	MaxOutputBytes int64         `json:"max_output_bytes"`
	MaxFiles       int           `json:"max_files"`
	MaxFileBytes   int64         `json:"max_file_bytes"`
	MaxTotalBytes  int64         `json:"max_total_bytes"`
	MaxTokens      int64         `json:"max_tokens"`
	MaxMemoryBytes int64         `json:"max_memory_bytes"`
	MaxDiskBytes   int64         `json:"max_disk_bytes"`
}

func DefaultResourceLimits() ResourceLimits {
	return ResourceLimits{
		MaxDuration:    5 * time.Second,
		MaxInputBytes:  1 << 20,
		MaxOutputBytes: 1 << 20,
		MaxFiles:       256,
		MaxFileBytes:   256 << 10,
		MaxTotalBytes:  8 << 20,
		MaxTokens:      8192,
		MaxMemoryBytes: 256 << 20,
		MaxDiskBytes:   16 << 20,
	}
}

func (l ResourceLimits) Validate() error {
	if l.MaxDuration <= 0 || l.MaxInputBytes <= 0 || l.MaxOutputBytes <= 0 || l.MaxFiles <= 0 || l.MaxFileBytes <= 0 || l.MaxTotalBytes <= 0 || l.MaxTokens <= 0 || l.MaxMemoryBytes <= 0 || l.MaxDiskBytes <= 0 {
		return fmt.Errorf("%w: resource limits must be positive", ErrPolicy)
	}
	if l.MaxFileBytes > l.MaxTotalBytes || l.MaxOutputBytes > l.MaxTotalBytes {
		return fmt.Errorf("%w: per-operation limit exceeds total limit", ErrPolicy)
	}
	return nil
}

// ParameterType is a small JSON schema vocabulary. The validator is strict
// by default: unknown keys, missing required keys, wrong types, and overlarge
// values are all rejected before execution.
type ParameterType string

const (
	TypeString  ParameterType = "string"
	TypeInteger ParameterType = "integer"
	TypeNumber  ParameterType = "number"
	TypeBoolean ParameterType = "boolean"
	TypeObject  ParameterType = "object"
	TypeArray   ParameterType = "array"
)

type Parameter struct {
	Type            ParameterType        `json:"type"`
	Required        bool                 `json:"required,omitempty"`
	Enum            []string             `json:"enum,omitempty"`
	Properties      map[string]Parameter `json:"properties,omitempty"`
	Items           *Parameter           `json:"items,omitempty"`
	AllowAdditional bool                 `json:"allow_additional,omitempty"`
	MaxLength       int                  `json:"max_length,omitempty"`
	MaxItems        int                  `json:"max_items,omitempty"`
	MaxProperties   int                  `json:"max_properties,omitempty"`
	Minimum         *float64             `json:"minimum,omitempty"`
	Maximum         *float64             `json:"maximum,omitempty"`
}

type ParameterSchema struct {
	Properties      map[string]Parameter `json:"properties"`
	AllowAdditional bool                 `json:"allow_additional,omitempty"`
	MaxProperties   int                  `json:"max_properties,omitempty"`
}

func (s ParameterSchema) Validate(params map[string]any) error {
	if params == nil {
		params = map[string]any{}
	}
	if s.MaxProperties > 0 && len(params) > s.MaxProperties {
		return fmt.Errorf("%w: too many parameters", ErrParameters)
	}
	for key, value := range params {
		spec, ok := s.Properties[key]
		if !ok {
			if !s.AllowAdditional {
				return fmt.Errorf("%w: unknown parameter %q", ErrParameters, key)
			}
			continue
		}
		if err := spec.validate(value, key); err != nil {
			return err
		}
	}
	for key, spec := range s.Properties {
		if spec.Required {
			if _, ok := params[key]; !ok {
				return fmt.Errorf("%w: missing required parameter %q", ErrParameters, key)
			}
		}
	}
	return nil
}

func (s Parameter) validate(value any, path string) error {
	if !s.Type.valid() {
		return fmt.Errorf("%w: parameter %s has unsupported schema type %q", ErrPolicy, path, s.Type)
	}
	switch s.Type {
	case TypeString:
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("%w: parameter %s must be a string", ErrParameters, path)
		}
		if s.MaxLength > 0 && len([]rune(text)) > s.MaxLength {
			return fmt.Errorf("%w: parameter %s is too long", ErrParameters, path)
		}
		if len(s.Enum) > 0 {
			found := false
			for _, allowed := range s.Enum {
				if text == allowed {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%w: parameter %s has an unsupported value", ErrParameters, path)
			}
		}
	case TypeInteger, TypeNumber:
		number, ok := numberValue(value)
		if !ok || (s.Type == TypeInteger && math.Trunc(number) != number) {
			return fmt.Errorf("%w: parameter %s has the wrong numeric type", ErrParameters, path)
		}
		if s.Minimum != nil && number < *s.Minimum || s.Maximum != nil && number > *s.Maximum {
			return fmt.Errorf("%w: parameter %s is outside its bounds", ErrParameters, path)
		}
	case TypeBoolean:
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%w: parameter %s must be a boolean", ErrParameters, path)
		}
	case TypeObject:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: parameter %s must be an object", ErrParameters, path)
		}
		child := ParameterSchema{Properties: s.Properties, AllowAdditional: s.AllowAdditional, MaxProperties: s.MaxProperties}
		if err := child.Validate(object); err != nil {
			return fmt.Errorf("%w: %s", ErrParameters, err)
		}
	case TypeArray:
		items := reflect.ValueOf(value)
		if !items.IsValid() || (items.Kind() != reflect.Array && items.Kind() != reflect.Slice) {
			return fmt.Errorf("%w: parameter %s must be an array", ErrParameters, path)
		}
		if s.MaxItems > 0 && items.Len() > s.MaxItems {
			return fmt.Errorf("%w: parameter %s has too many items", ErrParameters, path)
		}
		if s.Items != nil {
			for i := 0; i < items.Len(); i++ {
				if err := s.Items.validate(items.Index(i).Interface(), path+"["+strconv.Itoa(i)+"]"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (t ParameterType) valid() bool {
	switch t {
	case TypeString, TypeInteger, TypeNumber, TypeBoolean, TypeObject, TypeArray:
		return true
	default:
		return false
	}
}

func numberValue(value any) (float64, bool) {
	switch number := value.(type) {
	case int:
		return float64(number), true
	case int8:
		return float64(number), true
	case int16:
		return float64(number), true
	case int32:
		return float64(number), true
	case int64:
		return float64(number), true
	case uint:
		return float64(number), true
	case uint8:
		return float64(number), true
	case uint16:
		return float64(number), true
	case uint32:
		return float64(number), true
	case uint64:
		return float64(number), true
	case float32:
		return float64(number), true
	case float64:
		return number, !math.IsNaN(number) && !math.IsInf(number, 0)
	default:
		return 0, false
	}
}

// ToolDescriptor is immutable once registered. Version is part of the
// lookup key; registering a new version never changes the meaning of v1.
type ToolDescriptor struct {
	ID                       string          `json:"id"`
	Version                  string          `json:"version"`
	Kind                     ToolKind        `json:"kind"`
	Risk                     RiskClass       `json:"risk"`
	ParameterSchema          ParameterSchema `json:"parameter_schema"`
	Workspace                WorkspaceScope  `json:"workspace_scope"`
	Limits                   ResourceLimits  `json:"limits"`
	Network                  NetworkPolicy   `json:"network"`
	ValidationID             string          `json:"validation_id"`
	RollbackID               string          `json:"rollback_id,omitempty"`
	CleanupID                string          `json:"cleanup_id,omitempty"`
	RequiresUserConfirmation bool            `json:"requires_user_confirmation"`
	ControllerHandoffOnly    bool            `json:"controller_handoff_only"`
}

func (d ToolDescriptor) Validate() error {
	if !toolIDPattern.MatchString(strings.TrimSpace(d.ID)) {
		return fmt.Errorf("%w: invalid tool id", ErrPolicy)
	}
	if !toolVersionPattern.MatchString(strings.TrimSpace(d.Version)) {
		return fmt.Errorf("%w: invalid tool version", ErrPolicy)
	}
	if !d.Kind.Valid() {
		return fmt.Errorf("%w: unsupported tool kind %q", ErrPolicy, d.Kind)
	}
	if !d.Risk.Valid() {
		return fmt.Errorf("%w: unsupported tool risk %q", ErrPolicy, d.Risk)
	}
	if d.Risk != RiskR3 && expectedRiskForKind(d.Kind) != d.Risk {
		return fmt.Errorf("%w: tool kind %q must use risk %q", ErrRisk, d.Kind, expectedRiskForKind(d.Kind))
	}
	if !d.Workspace.Valid() {
		return fmt.Errorf("%w: unsupported workspace scope %q", ErrPolicy, d.Workspace)
	}
	if err := d.ParameterSchema.validateSchema(); err != nil {
		return err
	}
	if err := d.Limits.Validate(); err != nil {
		return err
	}
	if err := d.Network.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(d.ValidationID) == "" {
		return fmt.Errorf("%w: validation id is required", ErrPolicy)
	}
	if d.Risk == RiskR2 && !d.RequiresUserConfirmation {
		return fmt.Errorf("%w: R2 tools require explicit confirmation", ErrPolicy)
	}
	if d.Risk == RiskR3 && !d.ControllerHandoffOnly {
		return fmt.Errorf("%w: R3 tools must be controller handoff only", ErrPolicy)
	}
	if d.Risk != RiskR3 && d.ControllerHandoffOnly {
		return fmt.Errorf("%w: only R3 tools may be controller handoff only", ErrPolicy)
	}
	if d.Risk == RiskR0 && d.RollbackID != "" {
		return fmt.Errorf("%w: read-only tools cannot declare rollback", ErrPolicy)
	}
	if forbiddenToolName(d.ID) {
		return fmt.Errorf("%w: tool name is not allowed", ErrForbidden)
	}
	return nil
}

func (s ParameterSchema) validateSchema() error {
	if s.MaxProperties < 0 {
		return fmt.Errorf("%w: schema max properties cannot be negative", ErrPolicy)
	}
	for name, parameter := range s.Properties {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("%w: schema contains an empty parameter name", ErrPolicy)
		}
		if err := parameter.validateSchema(name); err != nil {
			return err
		}
	}
	return nil
}

func (s Parameter) validateSchema(path string) error {
	if !s.Type.valid() {
		return fmt.Errorf("%w: parameter %s has unsupported schema type", ErrPolicy, path)
	}
	if s.MaxLength < 0 || s.MaxItems < 0 || s.MaxProperties < 0 {
		return fmt.Errorf("%w: parameter %s has negative bound", ErrPolicy, path)
	}
	if s.Type == TypeObject {
		if err := (ParameterSchema{Properties: s.Properties, AllowAdditional: s.AllowAdditional, MaxProperties: s.MaxProperties}).validateSchema(); err != nil {
			return err
		}
	}
	if s.Items != nil {
		if err := s.Items.validateSchema(path + "[]"); err != nil {
			return err
		}
	}
	return nil
}

// CatalogError sentinels make policy decisions machine-readable without
// exposing provider/model text.
var (
	ErrNotFound   = errors.New("tool not found")
	ErrVersion    = errors.New("tool version is not registered")
	ErrParameters = errors.New("tool parameters rejected")
	ErrPolicy     = errors.New("tool policy rejected")
	ErrForbidden  = errors.New("tool is forbidden")
	ErrRisk       = errors.New("tool risk rejected")
)

var (
	toolIDPattern      = regexp.MustCompile(`^[a-z][a-z0-9_-]*(?:\.[a-z0-9_-]+)+$`)
	toolVersionPattern = regexp.MustCompile(`^v[0-9]+(?:\.[0-9]+)*$`)
)

type catalogKey struct{ id, version string }

// ToolCatalog is safe for concurrent reads after construction. Register is
// intentionally explicit and rejects duplicate id/version pairs.
type ToolCatalog struct {
	entries map[catalogKey]ToolDescriptor
}

// AIToolCatalog is the product-language spelling used by the architecture
// documents. It is an alias, not a second policy implementation.
type AIToolCatalog = ToolCatalog

func NewToolCatalog(descriptors ...ToolDescriptor) (*ToolCatalog, error) {
	catalog := &ToolCatalog{entries: make(map[catalogKey]ToolDescriptor)}
	for _, descriptor := range descriptors {
		if err := catalog.Register(descriptor); err != nil {
			return nil, err
		}
	}
	return catalog, nil
}

// NewCatalog is a short stable alias used by callers that do not need to
// distinguish this package from future catalog implementations.
func NewCatalog(descriptors ...ToolDescriptor) (*ToolCatalog, error) {
	return NewToolCatalog(descriptors...)
}

func NewAIToolCatalog(descriptors ...ToolDescriptor) (*ToolCatalog, error) {
	return NewToolCatalog(descriptors...)
}

func (c *ToolCatalog) Register(descriptor ToolDescriptor) error {
	if c == nil {
		return fmt.Errorf("%w: nil catalog", ErrPolicy)
	}
	if err := descriptor.Validate(); err != nil {
		return err
	}
	if c.entries == nil {
		c.entries = make(map[catalogKey]ToolDescriptor)
	}
	key := catalogKey{id: descriptor.ID, version: descriptor.Version}
	if _, exists := c.entries[key]; exists {
		return fmt.Errorf("%w: %s@%s", ErrPolicy, descriptor.ID, descriptor.Version)
	}
	descriptor.ParameterSchema.Properties = cloneParameters(descriptor.ParameterSchema.Properties)
	descriptor.Network = descriptor.Network.normalized()
	c.entries[key] = descriptor
	return nil
}

func (c *ToolCatalog) Get(id, version string) (ToolDescriptor, error) {
	if c == nil {
		return ToolDescriptor{}, fmt.Errorf("%w: nil catalog", ErrNotFound)
	}
	descriptor, ok := c.entries[catalogKey{id: strings.TrimSpace(id), version: strings.TrimSpace(version)}]
	if !ok {
		if c.hasID(id) {
			return ToolDescriptor{}, fmt.Errorf("%w: %s@%s", ErrVersion, id, version)
		}
		return ToolDescriptor{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return cloneDescriptor(descriptor), nil
}

func (c *ToolCatalog) hasID(id string) bool {
	for key := range c.entries {
		if key.id == id {
			return true
		}
	}
	return false
}

// List returns deterministic descriptors ordered by id then version.
func (c *ToolCatalog) List() []ToolDescriptor {
	if c == nil {
		return nil
	}
	values := make([]ToolDescriptor, 0, len(c.entries))
	for _, descriptor := range c.entries {
		values = append(values, cloneDescriptor(descriptor))
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].ID == values[j].ID {
			return compareVersions(values[i].Version, values[j].Version) < 0
		}
		return values[i].ID < values[j].ID
	})
	return values
}

// ValidateAction performs the catalog half of AIActionPlan policy validation.
// The domain validator remains responsible for plan-level required fields.
func (c *ToolCatalog) ValidateAction(action domain.AIAction) (ToolDescriptor, error) {
	if err := action.Validate(); err != nil {
		return ToolDescriptor{}, err
	}
	descriptor, err := c.Get(action.ToolID, action.ToolVersion)
	if err != nil {
		return ToolDescriptor{}, err
	}
	if RiskClass(action.Risk) != descriptor.Risk {
		return ToolDescriptor{}, fmt.Errorf("%w: action risk %q does not match catalog risk %q", ErrRisk, action.Risk, descriptor.Risk)
	}
	if action.ValidationID != descriptor.ValidationID {
		return ToolDescriptor{}, fmt.Errorf("%w: action validation %q does not match catalog validation %q", ErrPolicy, action.ValidationID, descriptor.ValidationID)
	}
	if len([]rune(strings.TrimSpace(action.ExpectedResult))) > 4096 {
		return ToolDescriptor{}, fmt.Errorf("%w: expected result is too large", ErrParameters)
	}
	if err := descriptor.ParameterSchema.Validate(action.Parameters); err != nil {
		return ToolDescriptor{}, err
	}
	if err := validateSafeParameters(action.Parameters); err != nil {
		return ToolDescriptor{}, err
	}
	return descriptor, nil
}

// ValidatePlan applies the catalog policy to every action in a structured
// plan. It intentionally does not execute or mutate anything.
func (c *ToolCatalog) ValidatePlan(plan domain.AIActionPlan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	for _, action := range plan.Actions {
		if _, err := c.ValidateAction(action); err != nil {
			return err
		}
	}
	return nil
}

func validateSafeParameters(params map[string]any) error {
	var walk func(string, any) error
	walk = func(key string, value any) error {
		lowerKey := strings.ToLower(strings.TrimSpace(key))
		for _, forbidden := range []string{"shell", "command", "exec", "ssh", "docker_socket", "docker.sock", "kubectl", "kubernetes", "device", "host_path", "hostpath", "privileged", "capabilities", "publish", "deploy", "restart", "scale", "route", "secret", "password", "token", "cookie", "private_key", "access_key"} {
			if lowerKey == forbidden || strings.Contains(lowerKey, forbidden) {
				return fmt.Errorf("%w: parameter %q is not permitted", ErrForbidden, key)
			}
		}
		if text, ok := value.(string); ok {
			lower := strings.ToLower(text)
			for _, marker := range []string{"docker.sock", "/var/run/docker", "kubectl ", "ssh ", "ssh://", "--privileged", "hostnetwork", "hostpid", "hostipc", "/dev/"} {
				if strings.Contains(lower, marker) {
					return fmt.Errorf("%w: parameter %q contains a forbidden operation marker", ErrForbidden, key)
				}
			}
			return nil
		}
		valueOf := reflect.ValueOf(value)
		if !valueOf.IsValid() {
			return nil
		}
		switch valueOf.Kind() {
		case reflect.Map:
			iter := valueOf.MapRange()
			for iter.Next() {
				name, ok := iter.Key().Interface().(string)
				if !ok {
					return fmt.Errorf("%w: object parameter keys must be strings", ErrParameters)
				}
				if err := walk(name, iter.Value().Interface()); err != nil {
					return err
				}
			}
		case reflect.Array, reflect.Slice:
			for i := 0; i < valueOf.Len(); i++ {
				if err := walk(key, valueOf.Index(i).Interface()); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for key, value := range params {
		if err := walk(key, value); err != nil {
			return err
		}
	}
	return nil
}

func cloneParameters(source map[string]Parameter) map[string]Parameter {
	if source == nil {
		return nil
	}
	copyOf := make(map[string]Parameter, len(source))
	for key, parameter := range source {
		parameter.Enum = append([]string(nil), parameter.Enum...)
		parameter.Properties = cloneParameters(parameter.Properties)
		if parameter.Items != nil {
			items := *parameter.Items
			items.Enum = append([]string(nil), items.Enum...)
			items.Properties = cloneParameters(items.Properties)
			parameter.Items = &items
		}
		copyOf[key] = parameter
	}
	return copyOf
}

func cloneDescriptor(descriptor ToolDescriptor) ToolDescriptor {
	descriptor.ParameterSchema.Properties = cloneParameters(descriptor.ParameterSchema.Properties)
	descriptor.Network.AllowedCIDRs = append([]string(nil), descriptor.Network.AllowedCIDRs...)
	return descriptor
}

func compareVersions(left, right string) int {
	leftParts := strings.Split(strings.TrimPrefix(left, "v"), ".")
	rightParts := strings.Split(strings.TrimPrefix(right, "v"), ".")
	for index := 0; index < len(leftParts) || index < len(rightParts); index++ {
		leftValue, rightValue := 0, 0
		if index < len(leftParts) {
			leftValue, _ = strconv.Atoi(leftParts[index])
		}
		if index < len(rightParts) {
			rightValue, _ = strconv.Atoi(rightParts[index])
		}
		if leftValue < rightValue {
			return -1
		}
		if leftValue > rightValue {
			return 1
		}
	}
	return 0
}

func forbiddenToolName(id string) bool {
	lower := strings.ToLower(id)
	for _, marker := range []string{"shell", "exec", "ssh", "docker", "kubernetes", "kubectl", "socket", "production", "deploy", "restart", "scale", "rollback", "route"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func expectedRiskForKind(kind ToolKind) RiskClass {
	switch kind {
	case KindRead, KindInspect, KindSearch:
		return RiskR0
	case KindBuildTest, KindHealthCheck:
		return RiskR1
	case KindDraftEdit, KindPatch:
		return RiskR2
	default:
		return ""
	}
}

func descriptor(id string, kind ToolKind, risk RiskClass, schema ParameterSchema, scope WorkspaceScope, validation string, rollback string, confirmation, handoff bool) ToolDescriptor {
	return ToolDescriptor{
		ID:                       id,
		Version:                  ToolVersionV1,
		Kind:                     kind,
		Risk:                     risk,
		ParameterSchema:          schema,
		Workspace:                scope,
		Limits:                   DefaultResourceLimits(),
		Network:                  NetworkPolicy{Mode: NetworkDisabled},
		ValidationID:             validation,
		RollbackID:               rollback,
		RequiresUserConfirmation: confirmation,
		ControllerHandoffOnly:    handoff,
	}
}

func requiredString(max int) Parameter {
	return Parameter{Type: TypeString, Required: true, MaxLength: max}
}

func optionalString(max int) Parameter {
	return Parameter{Type: TypeString, MaxLength: max}
}

func optionalInteger(max int64) Parameter {
	maximum := float64(max)
	return Parameter{Type: TypeInteger, Maximum: &maximum}
}

// DefaultCatalog returns the only tools supported by the first runner. The
// build/test tools are deterministic fixtures; they do not invoke a command,
// daemon, network, Docker API, SSH, or Kubernetes API.
func DefaultCatalog() *ToolCatalog {
	maxBytes := int64(1 << 20)
	maxMatches := int64(256)
	fixture := Parameter{Type: TypeString, Enum: []string{"pass", "success", "failure", "diagnostic", "timeout", "resource"}, MaxLength: 32}
	pathOptional := optionalString(512)
	readSchema := ParameterSchema{Properties: map[string]Parameter{
		"path":      pathOptional,
		"max_bytes": optionalInteger(maxBytes),
	}}
	searchSchema := ParameterSchema{Properties: map[string]Parameter{
		"path":        pathOptional,
		"query":       requiredString(512),
		"max_matches": optionalInteger(maxMatches),
		"max_bytes":   optionalInteger(maxBytes),
	}}
	fixtureSchema := ParameterSchema{Properties: map[string]Parameter{
		"path":    pathOptional,
		"fixture": fixture,
	}}
	draftSchema := ParameterSchema{Properties: map[string]Parameter{
		"path":            requiredString(512),
		"content":         requiredString(1 << 20),
		"expected_digest": optionalString(128),
	}}
	patchSchema := ParameterSchema{Properties: map[string]Parameter{
		"path":            requiredString(512),
		"content":         requiredString(1 << 20),
		"expected_digest": optionalString(128),
	}}
	descriptors := []ToolDescriptor{
		descriptor(ToolWorkspaceRead, KindRead, RiskR0, readSchema, ScopeWorkspace, "workspace.read.v1", "", false, false),
		descriptor(ToolWorkspaceInspect, KindInspect, RiskR0, readSchema, ScopeWorkspace, "workspace.inspect.v1", "", false, false),
		descriptor(ToolWorkspaceSearch, KindSearch, RiskR0, searchSchema, ScopeWorkspace, "workspace.search.v1", "", false, false),
		descriptor(ToolWorkspaceBuildTest, KindBuildTest, RiskR1, fixtureSchema, ScopeWorkspace, "build.exit_and_artifact_check", "workspace.cleanup.v1", false, false),
		descriptor(ToolWorkspaceHealthCheck, KindHealthCheck, RiskR1, fixtureSchema, ScopeWorkspace, "health.exit_and_observation_check", "workspace.cleanup.v1", false, false),
		descriptor(ToolWorkspaceDraftEdit, KindDraftEdit, RiskR2, draftSchema, ScopeDraft, "draft.diff_and_scope.v1", "workspace.discard_changes.v1", true, false),
		descriptor(ToolWorkspacePatch, KindPatch, RiskR2, patchSchema, ScopeWorkspace, "patch.diff_and_no_write.v1", "workspace.discard_changes.v1", true, false),
	}
	catalog, err := NewToolCatalog(descriptors...)
	if err != nil {
		// These descriptors are package constants. A panic indicates a developer
		// error and is preferable to running with a partially populated policy.
		panic(err)
	}
	return catalog
}

func DefaultAIToolCatalog() *ToolCatalog { return DefaultCatalog() }

// MarshalJSON is useful for emitting a deterministic catalog evidence
// artifact. It deliberately serializes only descriptors, never closures.
func (c *ToolCatalog) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.List())
}
