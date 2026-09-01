// Package dockerfile creates a deterministic read-only definition from the
// exact root Dockerfile of an immutable SourceRevision workspace.
package dockerfile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

const maxRootDockerfileBytes int64 = 1 << 20

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var parserDirective = regexp.MustCompile(`^#\s*([A-Za-z]+)\s*=\s*([^\s]+)\s*$`)

type Importer struct{ afterWorkspaceHash func() }

func New() Importer { return Importer{} }
func Import(revision domain.SourceRevision) (contracts.AcornFoxDockerfileDefinition, error) {
	return New().Import(revision)
}

func (i Importer) Import(revision domain.SourceRevision) (contracts.AcornFoxDockerfileDefinition, error) {
	if err := revision.Validate(); err != nil {
		return contracts.AcornFoxDockerfileDefinition{}, fmt.Errorf("immutable source revision is invalid")
	}
	workspace, err := filepath.Abs(revision.WorkspaceRef)
	if err != nil {
		return contracts.AcornFoxDockerfileDefinition{}, fmt.Errorf("immutable source workspace is unavailable")
	}
	info, err := os.Lstat(workspace)
	if err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return contracts.AcornFoxDockerfileDefinition{}, fmt.Errorf("immutable source workspace is unavailable")
	}
	before, err := foundation.HashDirectory(workspace)
	if err != nil || revision.ContentDigest != "sha256:"+before {
		return contracts.AcornFoxDockerfileDefinition{}, fmt.Errorf("immutable source workspace changed")
	}
	base := contracts.AcornFoxDockerfileDefinition{SourceRevisionID: revision.ID, SourceContentDigest: revision.ContentDigest, ExposedPorts: []contracts.AcornFoxDockerfilePort{}, Environment: []contracts.AcornFoxDockerfileEnvironment{}, Gaps: []string{}, Warnings: []string{}}
	dockerfile := filepath.Join(workspace, "Dockerfile")
	if i.afterWorkspaceHash != nil {
		i.afterWorkspaceHash()
	}
	raw, missing, readErr := readRootDockerfileNoFollow(dockerfile)
	if missing {
		if !workspaceStillMatches(workspace, before, revision.ContentDigest) {
			return contracts.AcornFoxDockerfileDefinition{}, fmt.Errorf("immutable source workspace changed")
		}
		base.Status = contracts.AcornFoxDockerfileWaitingLater
		base.Gaps = []string{"root_dockerfile_missing"}
		return contracts.FinalizeAcornFoxDockerfileDefinition(base)
	}
	if readErr != nil {
		if !workspaceStillMatches(workspace, before, revision.ContentDigest) {
			return contracts.AcornFoxDockerfileDefinition{}, fmt.Errorf("immutable source workspace changed")
		}
		return unsupported(base)
	}
	after, err := foundation.HashDirectory(workspace)
	if err != nil || after != before {
		return contracts.AcornFoxDockerfileDefinition{}, fmt.Errorf("immutable source workspace changed")
	}
	digest := sha256.Sum256(raw)
	base.DockerfileDigest = "sha256:" + hex.EncodeToString(digest[:])
	lines, err := logicalLines(string(raw))
	if err != nil {
		return unsupported(base)
	}
	stages, warnings, gaps, err := parse(lines)
	if err != nil || len(stages) == 0 {
		return unsupported(base)
	}
	state, err := resolve(stages, len(stages)-1, map[int]bool{})
	if err != nil {
		return unsupported(base)
	}
	final := stages[len(stages)-1]
	base.Status, base.StageCount = contracts.AcornFoxDockerfileReady, len(stages)
	base.FinalStage = &contracts.AcornFoxDockerfileStage{Name: final.name, Index: len(stages) - 1, From: final.from, Platform: final.platform}
	base.Workdir, base.Entrypoint, base.Command = state.workdir, state.entrypoint, state.command
	base.ExposedPorts, base.Environment, base.Healthcheck, base.Shell = ports(state.ports), environments(state.env), state.health, append([]string(nil), state.shell...)
	base.Gaps, base.Warnings = append(gaps, state.gaps...), append(warnings, state.warnings...)
	if !state.health.Present {
		if stageHasExternalBase(stages, len(stages)-1) {
			base.Gaps = append(base.Gaps, "healthcheck_external_base_unobserved")
		} else {
			base.Gaps = append(base.Gaps, "healthcheck_missing")
		}
	}
	if stageHasExternalBase(stages, len(stages)-1) {
		base.Gaps = append(base.Gaps, "external_base_config_unobserved")
	}
	return contracts.FinalizeAcornFoxDockerfileDefinition(base)
}

func workspaceStillMatches(workspace, before, expected string) bool {
	after, err := foundation.HashDirectory(workspace)
	return err == nil && after == before && expected == "sha256:"+after
}

func stageHasExternalBase(stages []stage, index int) bool {
	for index >= 0 {
		if stages[index].parent < 0 && !strings.EqualFold(stages[index].from, "scratch") {
			return true
		}
		index = stages[index].parent
	}
	return false
}

func unsupported(base contracts.AcornFoxDockerfileDefinition) (contracts.AcornFoxDockerfileDefinition, error) {
	base.Status, base.Gaps = contracts.AcornFoxDockerfileUnsupported, []string{"dockerfile_unsupported"}
	return contracts.FinalizeAcornFoxDockerfileDefinition(base)
}

type stage struct {
	name, from, platform string
	parent               int
	instructions         []instruction
}
type instruction struct{ name, argument string }
type state struct {
	workdir               string
	workdirKnown          bool
	entrypoint, command   *contracts.AcornFoxDockerfileCommand
	ports                 map[string]contracts.AcornFoxDockerfilePort
	env                   map[string]contracts.AcornFoxDockerfileEnvironment
	health                contracts.AcornFoxDockerfileHealthcheck
	shell, gaps, warnings []string
}

func logicalLines(raw string) ([]string, error) {
	if strings.ContainsRune(raw, 0) || strings.Contains(raw, "<<") {
		return nil, errors.New("unsupported syntax")
	}
	physical := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	result := []string{}
	current := ""
	leading := true
	directives := map[string]bool{}
	for _, line := range physical {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			if leading {
				if match := parserDirective.FindStringSubmatch(trimmed); match != nil {
					key, value := strings.ToLower(match[1]), match[2]
					if directives[key] {
						return nil, errors.New("duplicate parser directive")
					}
					directives[key] = true
					if key == "syntax" && value == "docker/dockerfile:1" {
						continue
					}
					if key == "escape" && value == "\\" {
						continue
					}
					return nil, errors.New("unsupported parser directive")
				}
				if key, _, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(trimmed, "#")), "="); ok && strings.EqualFold(strings.TrimSpace(key), "check") {
					return nil, errors.New("unsupported parser directive")
				}
			}
			if current != "" {
				continue
			}
		}
		if current == "" && (trimmed == "" || strings.HasPrefix(trimmed, "#")) {
			continue
		}
		if trimmed != "" {
			leading = false
		}
		continued := strings.HasSuffix(trimmed, "\\")
		if continued {
			trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, "\\"))
		}
		if current == "" {
			current = trimmed
		} else {
			current += " " + trimmed
		}
		if !continued {
			if current == "" {
				return nil, errors.New("empty instruction")
			}
			result, current = append(result, current), ""
		}
	}
	if current != "" {
		return nil, errors.New("unterminated continuation")
	}
	return result, nil
}

func parse(lines []string) ([]stage, []string, []string, error) {
	stages := []stage{}
	aliases := map[string]int{}
	warnings, gaps := []string{}, []string{}
	for _, line := range lines {
		word, argument, ok := strings.Cut(line, " ")
		if !ok {
			return nil, nil, nil, errors.New("malformed instruction")
		}
		word, argument = strings.ToUpper(strings.TrimSpace(word)), strings.TrimSpace(argument)
		if word == "FROM" {
			from, alias, platform, fromGap, err := parseFrom(argument)
			if err != nil {
				return nil, nil, nil, err
			}
			parent := -1
			if found, ok := aliases[strings.ToLower(from)]; ok {
				parent = found
			}
			if alias == "" {
				alias = "stage-" + strconv.Itoa(len(stages))
			}
			if _, exists := aliases[strings.ToLower(alias)]; exists {
				return nil, nil, nil, errors.New("duplicate stage")
			}
			aliases[strings.ToLower(alias)] = len(stages)
			if fromGap {
				gaps = append(gaps, "unresolved_variable_expansion:from")
			}
			stages = append(stages, stage{name: alias, from: from, platform: platform, parent: parent})
			continue
		}
		if len(stages) == 0 {
			if word != "ARG" || !validGlobalARG(argument) {
				return nil, nil, nil, errors.New("unsupported pre-FROM instruction")
			}
			warnings = append(warnings, "instruction:arg_not_projected")
			continue
		}
		switch word {
		case "WORKDIR", "ENTRYPOINT", "CMD", "EXPOSE", "ENV", "HEALTHCHECK", "SHELL":
			if argument == "" {
				return nil, nil, nil, errors.New("empty instruction")
			}
			stages[len(stages)-1].instructions = append(stages[len(stages)-1].instructions, instruction{word, argument})
		default:
			if knownNonProjected(word) {
				warnings = append(warnings, "instruction:"+strings.ToLower(word)+"_not_projected")
			} else {
				return nil, nil, nil, errors.New("unknown Dockerfile instruction")
			}
		}
	}
	return stages, warnings, gaps, nil
}

func validGlobalARG(argument string) bool {
	name, value, hasValue := strings.Cut(strings.TrimSpace(argument), "=")
	return envName.MatchString(name) && (!hasValue || strings.TrimSpace(value) != "" && !strings.ContainsAny(value, "\r\n\x00"))
}

func parseFrom(argument string) (string, string, string, bool, error) {
	fields := strings.Fields(argument)
	platform := ""
	for len(fields) > 0 && strings.HasPrefix(fields[0], "--") {
		name, value, ok := strings.Cut(strings.TrimPrefix(fields[0], "--"), "=")
		if !ok || name != "platform" || value == "" || hasExpansion(value) || platform != "" {
			return "", "", "", false, errors.New("unsupported FROM flag")
		}
		platform = value
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return "", "", "", false, errors.New("missing FROM")
	}
	from, alias := fields[0], ""
	if len(fields) > 1 {
		if len(fields) != 3 || !strings.EqualFold(fields[1], "AS") || !validStage(fields[2]) {
			return "", "", "", false, errors.New("invalid FROM")
		}
		alias = fields[2]
	}
	if strings.ContainsAny(from, "\r\n\x00") {
		return "", "", "", false, errors.New("invalid FROM")
	}
	return from, alias, platform, hasExpansion(from), nil
}
func knownNonProjected(word string) bool {
	switch word {
	case "RUN", "COPY", "ADD", "USER", "LABEL", "VOLUME", "STOPSIGNAL", "ARG", "ONBUILD", "MAINTAINER":
		return true
	}
	return false
}
func validStage(value string) bool { return value != "" && !strings.ContainsAny(value, " \t\r\n$:{}") }

func resolve(stages []stage, index int, seen map[int]bool) (state, error) {
	if index < 0 || index >= len(stages) || seen[index] {
		return state{}, errors.New("invalid inheritance")
	}
	seen[index] = true
	defer delete(seen, index)
	result := state{ports: map[string]contracts.AcornFoxDockerfilePort{}, env: map[string]contracts.AcornFoxDockerfileEnvironment{}}
	if stages[index].parent >= 0 {
		parent, err := resolve(stages, stages[index].parent, seen)
		if err != nil {
			return state{}, err
		}
		result = clone(parent)
	} else {
		result.workdirKnown = false
	}
	localEntrypoint, localCommand := false, false
	for _, item := range stages[index].instructions {
		if item.name == "ENTRYPOINT" {
			localEntrypoint = true
		}
		if item.name == "CMD" {
			localCommand = true
		}
		if err := apply(&result, item); err != nil {
			return state{}, err
		}
	}
	if localEntrypoint && !localCommand {
		result.command = nil
	}
	return result, nil
}

func clone(input state) state {
	result := input
	result.ports = map[string]contracts.AcornFoxDockerfilePort{}
	for k, v := range input.ports {
		result.ports[k] = v
	}
	result.env = map[string]contracts.AcornFoxDockerfileEnvironment{}
	for k, v := range input.env {
		result.env[k] = v
	}
	result.gaps = append([]string(nil), input.gaps...)
	result.warnings = append([]string(nil), input.warnings...)
	result.shell = append([]string(nil), input.shell...)
	if input.entrypoint != nil {
		v := *input.entrypoint
		v.Values = append([]string(nil), v.Values...)
		result.entrypoint = &v
	}
	if input.command != nil {
		v := *input.command
		v.Values = append([]string(nil), v.Values...)
		result.command = &v
	}
	result.health.Test = append([]string(nil), input.health.Test...)
	return result
}

func apply(result *state, item instruction) error {
	if hasExpansion(item.argument) {
		result.gaps = append(result.gaps, "unresolved_variable_expansion:"+strings.ToLower(item.name))
	}
	switch item.name {
	case "WORKDIR":
		if strings.HasPrefix(item.argument, "/") {
			result.workdir = path.Clean(item.argument)
			result.workdirKnown = true
		} else if result.workdirKnown {
			result.workdir = path.Clean(path.Join(result.workdir, item.argument))
		} else {
			result.workdir = ""
			result.gaps = append(result.gaps, "workdir_external_base_unresolved")
		}
	case "ENTRYPOINT":
		value, err := command(item.argument)
		if err != nil {
			return err
		}
		result.entrypoint = &value
	case "CMD":
		value, err := command(item.argument)
		if err != nil {
			return err
		}
		result.command = &value
	case "SHELL":
		value, err := jsonCommand(item.argument)
		if err != nil {
			return err
		}
		result.shell = value.Values
	case "EXPOSE":
		values, err := expose(item.argument)
		if err != nil {
			return err
		}
		for _, v := range values {
			result.ports[strconv.Itoa(v.Port)+"/"+v.Protocol] = v
		}
	case "ENV":
		values, gaps, err := environment(item.argument)
		if err != nil {
			return err
		}
		for _, v := range values {
			result.env[v.Name] = v
		}
		result.gaps = append(result.gaps, gaps...)
	case "HEALTHCHECK":
		health, gaps, err := healthcheck(item.argument)
		if err != nil {
			return err
		}
		result.health = health
		result.gaps = append(result.gaps, gaps...)
	}
	return nil
}

func command(argument string) (contracts.AcornFoxDockerfileCommand, error) {
	if strings.HasPrefix(argument, "[") {
		return jsonCommand(argument)
	}
	return contracts.AcornFoxDockerfileCommand{Form: "shell", Values: []string{argument}}, nil
}
func jsonCommand(argument string) (contracts.AcornFoxDockerfileCommand, error) {
	var values []string
	if err := json.Unmarshal([]byte(argument), &values); err != nil || len(values) == 0 {
		return contracts.AcornFoxDockerfileCommand{}, errors.New("invalid JSON command")
	}
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			return contracts.AcornFoxDockerfileCommand{}, errors.New("empty JSON command")
		}
	}
	return contracts.AcornFoxDockerfileCommand{Form: "exec", Values: values}, nil
}
func expose(argument string) ([]contracts.AcornFoxDockerfilePort, error) {
	values := []contracts.AcornFoxDockerfilePort{}
	for _, field := range strings.Fields(argument) {
		parts := strings.Split(field, "/")
		if len(parts) > 2 {
			return nil, errors.New("invalid EXPOSE")
		}
		port, err := strconv.Atoi(parts[0])
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid EXPOSE")
		}
		protocol := "tcp"
		if len(parts) == 2 {
			protocol = strings.ToLower(parts[1])
		}
		if protocol != "tcp" && protocol != "udp" {
			return nil, errors.New("invalid EXPOSE")
		}
		values = append(values, contracts.AcornFoxDockerfilePort{Port: port, Protocol: protocol})
	}
	return values, nil
}
func environment(argument string) ([]contracts.AcornFoxDockerfileEnvironment, []string, error) {
	if strings.ContainsAny(argument, "\"'") {
		return nil, nil, errors.New("unsupported quoted ENV")
	}
	fields := strings.Fields(argument)
	if len(fields) == 0 {
		return nil, nil, errors.New("invalid ENV")
	}
	if !strings.Contains(fields[0], "=") {
		if len(fields) < 2 {
			return nil, nil, errors.New("invalid ENV")
		}
		fields = []string{fields[0] + "=" + strings.Join(fields[1:], " ")}
	}
	values, gaps := []contracts.AcornFoxDockerfileEnvironment{}, []string{}
	for _, field := range fields {
		name, value, ok := strings.Cut(field, "=")
		if !ok || !envName.MatchString(name) {
			return nil, nil, errors.New("invalid ENV")
		}
		if sensitive(name) {
			values = append(values, contracts.AcornFoxDockerfileEnvironment{Name: name, Redacted: true})
			gaps = append(gaps, "sensitive_env_value_redacted:"+name)
			continue
		}
		values = append(values, contracts.AcornFoxDockerfileEnvironment{Name: name, Value: value})
		if hasExpansion(value) {
			gaps = append(gaps, "unresolved_variable_expansion:env:"+name)
		}
	}
	return values, gaps, nil
}
func healthcheck(argument string) (contracts.AcornFoxDockerfileHealthcheck, []string, error) {
	if strings.EqualFold(strings.TrimSpace(argument), "NONE") {
		return contracts.AcornFoxDockerfileHealthcheck{Present: true, Disabled: true}, nil, nil
	}
	fields := strings.Fields(argument)
	health := contracts.AcornFoxDockerfileHealthcheck{Present: true}
	gaps := []string{}
	for len(fields) > 0 && strings.HasPrefix(fields[0], "--") {
		name, value, ok := strings.Cut(strings.TrimPrefix(fields[0], "--"), "=")
		if !ok {
			return health, nil, errors.New("invalid HEALTHCHECK option")
		}
		if name == "retries" {
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed <= 0 || parsed > 100 {
				return health, nil, errors.New("invalid HEALTHCHECK retries")
			}
			health.Retries = parsed
		} else {
			seconds, err := durationSeconds(value)
			if err != nil {
				return health, nil, err
			}
			switch name {
			case "interval":
				health.IntervalSeconds = seconds
			case "timeout":
				health.TimeoutSeconds = seconds
			case "start-period":
				health.StartPeriodSeconds = seconds
			default:
				return health, nil, errors.New("unsupported HEALTHCHECK option")
			}
		}
		fields = fields[1:]
	}
	if len(fields) < 2 || (fields[0] != "CMD" && fields[0] != "CMD-SHELL") {
		return health, nil, errors.New("invalid HEALTHCHECK")
	}
	body := strings.TrimSpace(strings.TrimPrefix(strings.Join(fields, " "), fields[0]))
	if fields[0] == "CMD" && strings.HasPrefix(body, "[") {
		parsed, err := jsonCommand(body)
		if err != nil {
			return health, nil, err
		}
		health.Form, health.Test = parsed.Form, parsed.Values
	} else {
		health.Form, health.Test = "shell", []string{body}
	}
	if hasExpansion(strings.Join(health.Test, " ")) {
		gaps = append(gaps, "unresolved_variable_expansion:healthcheck")
	}
	if health.IntervalSeconds == 0 {
		health.IntervalSeconds = 30
	}
	if health.TimeoutSeconds == 0 {
		health.TimeoutSeconds = 30
	}
	if health.Retries == 0 {
		health.Retries = 3
	}
	return health, gaps, nil
}
func durationSeconds(value string) (int, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 || duration > 24*time.Hour || duration%time.Second != 0 {
		return 0, errors.New("invalid duration")
	}
	return int(duration / time.Second), nil
}
func hasExpansion(value string) bool { return strings.Contains(value, "$") }
func sensitive(name string) bool {
	upper := strings.ToUpper(name)
	for _, marker := range []string{"TOKEN", "PASSWORD", "SECRET", "COOKIE", "AUTHORIZATION", "API_KEY", "PRIVATE_KEY", "KEY", "PASS", "CREDENTIAL", "ACCESS", "SESSION", "SSH", "CERT", "DSN", "DATABASE_URL", "DB_PASS", "AWS_ACCESS_KEY_ID"} {
		if upper == marker || strings.HasPrefix(upper, marker+"_") || strings.HasSuffix(upper, "_"+marker) || strings.Contains(upper, "_"+marker+"_") {
			return true
		}
	}
	return false
}
func ports(input map[string]contracts.AcornFoxDockerfilePort) []contracts.AcornFoxDockerfilePort {
	values := make([]contracts.AcornFoxDockerfilePort, 0, len(input))
	for _, v := range input {
		values = append(values, v)
	}
	return values
}
func environments(input map[string]contracts.AcornFoxDockerfileEnvironment) []contracts.AcornFoxDockerfileEnvironment {
	values := make([]contracts.AcornFoxDockerfileEnvironment, 0, len(input))
	for _, v := range input {
		values = append(values, v)
	}
	return values
}
