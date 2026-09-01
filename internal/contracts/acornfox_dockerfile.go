package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/open-card/open-card/internal/domain"
)

type AcornFoxDockerfileStatus string

const (
	AcornFoxDockerfileReady        AcornFoxDockerfileStatus = "ready"
	AcornFoxDockerfileWaitingLater AcornFoxDockerfileStatus = "waiting_later"
	AcornFoxDockerfileUnsupported  AcornFoxDockerfileStatus = "unsupported"
)

type AcornFoxDockerfileStage struct {
	Name     string `json:"name"`
	Index    int    `json:"index"`
	From     string `json:"from"`
	Platform string `json:"platform,omitempty"`
}

type AcornFoxDockerfileCommand struct {
	Form   string   `json:"form,omitempty"`
	Values []string `json:"values,omitempty"`
}

type AcornFoxDockerfilePort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type AcornFoxDockerfileEnvironment struct {
	Name     string `json:"name"`
	Value    string `json:"value,omitempty"`
	Redacted bool   `json:"redacted,omitempty"`
}

type AcornFoxDockerfileHealthcheck struct {
	Present            bool     `json:"present"`
	Disabled           bool     `json:"disabled,omitempty"`
	Form               string   `json:"form,omitempty"`
	Test               []string `json:"test,omitempty"`
	IntervalSeconds    int      `json:"interval_seconds,omitempty"`
	TimeoutSeconds     int      `json:"timeout_seconds,omitempty"`
	StartPeriodSeconds int      `json:"start_period_seconds,omitempty"`
	Retries            int      `json:"retries,omitempty"`
}

// AcornFoxDockerfileDefinition is a read-only, deterministic view of one
// immutable source workspace's root Dockerfile. It is not a persisted
// ApplicationDeliveryDefinition and it never selects public access.
type AcornFoxDockerfileDefinition struct {
	Status              AcornFoxDockerfileStatus        `json:"status"`
	SourceRevisionID    domain.ID                       `json:"source_revision_id"`
	SourceContentDigest string                          `json:"source_content_digest"`
	DockerfileDigest    string                          `json:"dockerfile_digest,omitempty"`
	DefinitionDigest    string                          `json:"definition_digest"`
	StageCount          int                             `json:"stage_count"`
	FinalStage          *AcornFoxDockerfileStage        `json:"final_stage,omitempty"`
	Workdir             string                          `json:"workdir,omitempty"`
	Entrypoint          *AcornFoxDockerfileCommand      `json:"entrypoint,omitempty"`
	Command             *AcornFoxDockerfileCommand      `json:"command,omitempty"`
	ExposedPorts        []AcornFoxDockerfilePort        `json:"exposed_ports"`
	Environment         []AcornFoxDockerfileEnvironment `json:"environment"`
	Healthcheck         AcornFoxDockerfileHealthcheck   `json:"healthcheck"`
	Shell               []string                        `json:"shell,omitempty"`
	Gaps                []string                        `json:"gaps"`
	Warnings            []string                        `json:"warnings"`
}

var acornFoxDockerfileSHA = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var acornFoxDockerfilePlatform = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*(/[A-Za-z0-9][A-Za-z0-9_.-]*)*$`)

func (d AcornFoxDockerfileDefinition) Validate() error {
	if d.Status != AcornFoxDockerfileReady && d.Status != AcornFoxDockerfileWaitingLater && d.Status != AcornFoxDockerfileUnsupported {
		return fmt.Errorf("invalid AcornFox Dockerfile status")
	}
	if err := domain.RequireID(d.SourceRevisionID, "AcornFox Dockerfile source revision"); err != nil || !acornFoxDockerfileSHA.MatchString(d.SourceContentDigest) || !acornFoxDockerfileSHA.MatchString(d.DefinitionDigest) {
		return fmt.Errorf("invalid AcornFox Dockerfile identity")
	}
	if d.Status == AcornFoxDockerfileReady && (!acornFoxDockerfileSHA.MatchString(d.DockerfileDigest) || d.StageCount < 1 || d.FinalStage == nil) {
		return fmt.Errorf("incomplete ready AcornFox Dockerfile definition")
	}
	if d.FinalStage != nil && (strings.TrimSpace(d.FinalStage.Name) == "" || d.FinalStage.Index < 0 || d.FinalStage.Index >= d.StageCount || strings.TrimSpace(d.FinalStage.From) == "" || d.FinalStage.Platform != "" && !acornFoxDockerfilePlatform.MatchString(d.FinalStage.Platform)) {
		return fmt.Errorf("invalid AcornFox Dockerfile final stage")
	}
	if d.Status == AcornFoxDockerfileWaitingLater && (d.DockerfileDigest != "" || len(d.Gaps) != 1 || d.Gaps[0] != "root_dockerfile_missing" || len(d.Warnings) != 0) {
		return fmt.Errorf("waiting AcornFox Dockerfile definition lacks root gap")
	}
	if d.Status == AcornFoxDockerfileUnsupported && !containsAcornFoxDockerfileValue(d.Gaps, "dockerfile_unsupported") {
		return fmt.Errorf("unsupported AcornFox Dockerfile definition lacks gap")
	}
	if !sortedUniqueAcornFoxDockerfile(d.Gaps) || !sortedUniqueAcornFoxDockerfile(d.Warnings) {
		return fmt.Errorf("AcornFox Dockerfile gaps and warnings must be sorted unique")
	}
	for index, port := range d.ExposedPorts {
		if port.Port < 1 || port.Port > 65535 || (port.Protocol != "tcp" && port.Protocol != "udp") {
			return fmt.Errorf("invalid AcornFox Dockerfile exposed port")
		}
		if index > 0 && (d.ExposedPorts[index-1].Port > port.Port || d.ExposedPorts[index-1].Port == port.Port && d.ExposedPorts[index-1].Protocol >= port.Protocol) {
			return fmt.Errorf("AcornFox Dockerfile ports must be sorted unique")
		}
	}
	for index, value := range d.Environment {
		if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(value.Name) || value.Redacted && value.Value != "" || index > 0 && d.Environment[index-1].Name >= value.Name {
			return fmt.Errorf("invalid AcornFox Dockerfile environment")
		}
	}
	if err := validateAcornFoxDockerfileCommand(d.Entrypoint); err != nil || validateAcornFoxDockerfileCommand(d.Command) != nil {
		return fmt.Errorf("invalid AcornFox Dockerfile command")
	}
	for _, item := range d.Shell {
		if strings.TrimSpace(item) == "" {
			return fmt.Errorf("invalid AcornFox Dockerfile shell")
		}
	}
	if !d.Healthcheck.Present && (d.Healthcheck.Disabled || d.Healthcheck.Form != "" || len(d.Healthcheck.Test) != 0 || d.Healthcheck.IntervalSeconds != 0 || d.Healthcheck.TimeoutSeconds != 0 || d.Healthcheck.StartPeriodSeconds != 0 || d.Healthcheck.Retries != 0) {
		return fmt.Errorf("invalid absent AcornFox Dockerfile healthcheck")
	}
	if d.Healthcheck.Disabled && (!d.Healthcheck.Present || d.Healthcheck.Form != "" || len(d.Healthcheck.Test) != 0 || d.Healthcheck.IntervalSeconds != 0 || d.Healthcheck.TimeoutSeconds != 0 || d.Healthcheck.StartPeriodSeconds != 0 || d.Healthcheck.Retries != 0) {
		return fmt.Errorf("invalid disabled AcornFox Dockerfile healthcheck")
	}
	if d.Healthcheck.Present && !d.Healthcheck.Disabled && (d.Healthcheck.Form != "exec" && d.Healthcheck.Form != "shell" || len(d.Healthcheck.Test) == 0 || d.Healthcheck.Form == "shell" && len(d.Healthcheck.Test) != 1 || d.Healthcheck.IntervalSeconds <= 0 || d.Healthcheck.IntervalSeconds > 86400 || d.Healthcheck.TimeoutSeconds <= 0 || d.Healthcheck.TimeoutSeconds > 86400 || d.Healthcheck.StartPeriodSeconds < 0 || d.Healthcheck.StartPeriodSeconds > 86400 || d.Healthcheck.Retries <= 0 || d.Healthcheck.Retries > 100) {
		return fmt.Errorf("invalid AcornFox Dockerfile healthcheck")
	}
	for _, item := range d.Healthcheck.Test {
		if strings.TrimSpace(item) == "" {
			return fmt.Errorf("invalid AcornFox Dockerfile healthcheck")
		}
	}
	if (d.Status == AcornFoxDockerfileWaitingLater || d.Status == AcornFoxDockerfileUnsupported) && (d.StageCount != 0 || d.FinalStage != nil || d.Workdir != "" || d.Entrypoint != nil || d.Command != nil || len(d.ExposedPorts) != 0 || len(d.Environment) != 0 || d.Healthcheck.Present || len(d.Shell) != 0) {
		return fmt.Errorf("non-ready AcornFox Dockerfile definition has projected state")
	}
	return nil
}

func CanonicalAcornFoxDockerfileJSON(definition AcornFoxDockerfileDefinition) ([]byte, error) {
	copy := definition
	copy.DefinitionDigest = ""
	if err := copy.ValidateWithoutDefinitionDigest(); err != nil {
		return nil, err
	}
	return json.Marshal(copy)
}

func (d AcornFoxDockerfileDefinition) ValidateWithoutDefinitionDigest() error {
	copy := d
	copy.DefinitionDigest = "sha256:" + strings.Repeat("0", 64)
	return copy.Validate()
}

func FinalizeAcornFoxDockerfileDefinition(definition AcornFoxDockerfileDefinition) (AcornFoxDockerfileDefinition, error) {
	definition = cloneAcornFoxDockerfileDefinition(definition)
	definition.Gaps = normalizeAcornFoxDockerfileStrings(definition.Gaps)
	definition.Warnings = normalizeAcornFoxDockerfileStrings(definition.Warnings)
	sort.Slice(definition.ExposedPorts, func(i, j int) bool {
		if definition.ExposedPorts[i].Port == definition.ExposedPorts[j].Port {
			return definition.ExposedPorts[i].Protocol < definition.ExposedPorts[j].Protocol
		}
		return definition.ExposedPorts[i].Port < definition.ExposedPorts[j].Port
	})
	ports := make([]AcornFoxDockerfilePort, 0, len(definition.ExposedPorts))
	for _, value := range definition.ExposedPorts {
		if len(ports) == 0 || ports[len(ports)-1] != value {
			ports = append(ports, value)
		}
	}
	definition.ExposedPorts = ports
	sort.Slice(definition.Environment, func(i, j int) bool { return definition.Environment[i].Name < definition.Environment[j].Name })
	environment := make([]AcornFoxDockerfileEnvironment, 0, len(definition.Environment))
	for _, value := range definition.Environment {
		if len(environment) > 0 && environment[len(environment)-1].Name == value.Name {
			if environment[len(environment)-1] != value {
				return AcornFoxDockerfileDefinition{}, fmt.Errorf("conflicting AcornFox Dockerfile environment")
			}
			continue
		}
		environment = append(environment, value)
	}
	definition.Environment = environment
	canonical, err := CanonicalAcornFoxDockerfileJSON(definition)
	if err != nil {
		return AcornFoxDockerfileDefinition{}, err
	}
	digest := sha256.Sum256(canonical)
	definition.DefinitionDigest = "sha256:" + hex.EncodeToString(digest[:])
	if err := definition.Validate(); err != nil {
		return AcornFoxDockerfileDefinition{}, err
	}
	return definition, nil
}

func cloneAcornFoxDockerfileDefinition(value AcornFoxDockerfileDefinition) AcornFoxDockerfileDefinition {
	copy := value
	copy.ExposedPorts = append([]AcornFoxDockerfilePort(nil), value.ExposedPorts...)
	copy.Environment = append([]AcornFoxDockerfileEnvironment(nil), value.Environment...)
	copy.Shell = append([]string(nil), value.Shell...)
	copy.Gaps = append([]string(nil), value.Gaps...)
	copy.Warnings = append([]string(nil), value.Warnings...)
	copy.Healthcheck.Test = append([]string(nil), value.Healthcheck.Test...)
	if value.FinalStage != nil {
		stage := *value.FinalStage
		copy.FinalStage = &stage
	}
	if value.Entrypoint != nil {
		command := *value.Entrypoint
		command.Values = append([]string(nil), value.Entrypoint.Values...)
		copy.Entrypoint = &command
	}
	if value.Command != nil {
		command := *value.Command
		command.Values = append([]string(nil), value.Command.Values...)
		copy.Command = &command
	}
	return copy
}

func validateAcornFoxDockerfileCommand(value *AcornFoxDockerfileCommand) error {
	if value == nil {
		return nil
	}
	if value.Form != "exec" && value.Form != "shell" || len(value.Values) == 0 || value.Form == "shell" && len(value.Values) != 1 {
		return fmt.Errorf("invalid command")
	}
	for _, item := range value.Values {
		if strings.TrimSpace(item) == "" {
			return fmt.Errorf("invalid command")
		}
	}
	return nil
}

func normalizeAcornFoxDockerfileStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func containsAcornFoxDockerfileValue(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sortedUniqueAcornFoxDockerfile(values []string) bool {
	for index := range values {
		if strings.TrimSpace(values[index]) == "" || index > 0 && values[index-1] >= values[index] {
			return false
		}
	}
	return true
}
