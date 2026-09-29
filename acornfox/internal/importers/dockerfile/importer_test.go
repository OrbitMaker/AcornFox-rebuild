package dockerfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/foundation"
)

func dockerfileRevision(t *testing.T, files map[string]string) domain.SourceRevision {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	digest, err := foundation.HashDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	return domain.SourceRevision{ID: "src_dockerfile", ApplicationID: "app_dockerfile", Kind: domain.SourceUpload, Locator: "upload://dockerfile_fixture", ContentDigest: "sha256:" + digest, WorkspaceRef: root, CreatedAt: time.Unix(1, 0).UTC(), Immutable: true}
}

func TestImportRootDockerfileMultiStageInheritanceAndDeterminism(t *testing.T) {
	revision := dockerfileRevision(t, map[string]string{"Dockerfile": `# syntax=docker/dockerfile:1
FROM alpine:3.20 AS build
RUN make all
ENV BUILD_ONLY=1
FROM build AS runtime
WORKDIR /srv/app
ENTRYPOINT ["/srv/app/server"]
CMD --listen $PORT
EXPOSE 8080 \
  53/udp 8080/tcp
ENV APP_ENV=production DATABASE_PASSWORD=secret-canary
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/srv/app/server", "health"]
SHELL ["/bin/bash", "-c"]
USER app
`})
	beforeDigest, err := foundation.HashDirectory(revision.WorkspaceRef)
	if err != nil {
		t.Fatal(err)
	}
	beforeMode, err := os.Stat(filepath.Join(revision.WorkspaceRef, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := Import(revision)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Import(revision)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) || first.DefinitionDigest != second.DefinitionDigest {
		t.Fatalf("non-deterministic definition\n%s\n%s", firstJSON, secondJSON)
	}
	if first.Status != contracts.AcornFoxDockerfileReady || first.StageCount != 2 || first.FinalStage == nil || first.FinalStage.Name != "runtime" || first.FinalStage.From != "build" {
		t.Fatalf("stage definition=%+v", first)
	}
	if first.Entrypoint == nil || first.Entrypoint.Form != "exec" || first.Command == nil || first.Command.Form != "shell" {
		t.Fatalf("command forms=%+v", first)
	}
	if len(first.ExposedPorts) != 2 || first.ExposedPorts[0] != (contracts.AcornFoxDockerfilePort{Port: 53, Protocol: "udp"}) || first.ExposedPorts[1] != (contracts.AcornFoxDockerfilePort{Port: 8080, Protocol: "tcp"}) {
		t.Fatalf("ports=%+v", first.ExposedPorts)
	}
	if len(first.Environment) != 3 || first.Environment[1].Name != "BUILD_ONLY" || !first.Environment[2].Redacted || first.Environment[2].Value != "" {
		t.Fatalf("environment=%+v", first.Environment)
	}
	if !first.Healthcheck.Present || first.Healthcheck.Form != "exec" || first.Healthcheck.IntervalSeconds != 30 || first.Healthcheck.TimeoutSeconds != 5 || first.Healthcheck.StartPeriodSeconds != 10 || first.Healthcheck.Retries != 3 {
		t.Fatalf("health=%+v", first.Healthcheck)
	}
	for _, forbidden := range []string{"secret-canary", "public", "default_port"} {
		if strings.Contains(string(firstJSON), forbidden) {
			t.Fatalf("unsafe projection %q in %s", forbidden, firstJSON)
		}
	}
	for _, expected := range []string{"external_base_config_unobserved", "sensitive_env_value_redacted:DATABASE_PASSWORD", "unresolved_variable_expansion:cmd", "instruction:run_not_projected", "instruction:user_not_projected"} {
		if !contains(first.Gaps, expected) && !contains(first.Warnings, expected) {
			t.Fatalf("missing %q gaps=%v warnings=%v", expected, first.Gaps, first.Warnings)
		}
	}
	afterDigest, err := foundation.HashDirectory(revision.WorkspaceRef)
	afterMode, modeErr := os.Stat(filepath.Join(revision.WorkspaceRef, "Dockerfile"))
	if err != nil || modeErr != nil || beforeDigest != afterDigest || beforeMode.Mode() != afterMode.Mode() {
		t.Fatalf("import mutated source digest=%s/%s mode=%v/%v err=%v/%v", beforeDigest, afterDigest, beforeMode.Mode(), afterMode.Mode(), err, modeErr)
	}
}

func TestImportRootDockerfileWaitingUnsupportedAndMutationFailClosed(t *testing.T) {
	missing := dockerfileRevision(t, map[string]string{"README.md": "fixture\n"})
	definition, err := Import(missing)
	if err != nil || definition.Status != contracts.AcornFoxDockerfileWaitingLater || !contains(definition.Gaps, "root_dockerfile_missing") {
		t.Fatalf("missing root=%+v err=%v", definition, err)
	}
	unsafe := dockerfileRevision(t, map[string]string{"Dockerfile": "FROM alpine\nRUN cat <<EOF\nhello\nEOF\n"})
	definition, err = Import(unsafe)
	if err != nil || definition.Status != contracts.AcornFoxDockerfileUnsupported || !contains(definition.Gaps, "dockerfile_unsupported") {
		t.Fatalf("heredoc=%+v err=%v", definition, err)
	}
	symlink := dockerfileRevision(t, map[string]string{"actual": "FROM alpine\n"})
	if err := os.Symlink(filepath.Join(symlink.WorkspaceRef, "actual"), filepath.Join(symlink.WorkspaceRef, "Dockerfile")); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(symlink); err == nil {
		t.Fatal("symlink Dockerfile accepted")
	}
	mutated := dockerfileRevision(t, map[string]string{"Dockerfile": "FROM alpine\n"})
	if err := os.WriteFile(filepath.Join(mutated.WorkspaceRef, "changed"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(mutated); err == nil || strings.Contains(err.Error(), mutated.WorkspaceRef) {
		t.Fatalf("mutated source err=%v", err)
	}
}

func TestImportRootDockerfileHealthNoneAndInvalidEnv(t *testing.T) {
	revision := dockerfileRevision(t, map[string]string{"Dockerfile": "FROM alpine\nENV APP_MODE=dev\nHEALTHCHECK NONE\n"})
	definition, err := Import(revision)
	if err != nil || !definition.Healthcheck.Present || !definition.Healthcheck.Disabled || contains(definition.Gaps, "healthcheck_missing") {
		t.Fatalf("health none=%+v err=%v", definition, err)
	}
	missingHealth := dockerfileRevision(t, map[string]string{"Dockerfile": "# comment\nFROM alpine\nCMD echo hello\n"})
	definition, err = Import(missingHealth)
	if err != nil || definition.Status != contracts.AcornFoxDockerfileReady || !contains(definition.Gaps, "healthcheck_external_base_unobserved") || contains(definition.Gaps, "healthcheck_missing") {
		t.Fatalf("missing health=%+v err=%v", definition, err)
	}
	invalid := dockerfileRevision(t, map[string]string{"Dockerfile": "FROM alpine\nENV INVALID-NAME=value\n"})
	definition, err = Import(invalid)
	if err != nil || definition.Status != contracts.AcornFoxDockerfileUnsupported {
		t.Fatalf("invalid env=%+v err=%v", definition, err)
	}
}

func TestImportRootDockerfileOversizeIsUnsupported(t *testing.T) {
	revision := dockerfileRevision(t, map[string]string{"Dockerfile": strings.Repeat("x", int(maxRootDockerfileBytes+1))})
	definition, err := Import(revision)
	if err != nil || definition.Status != contracts.AcornFoxDockerfileUnsupported {
		t.Fatalf("oversize=%+v err=%v", definition, err)
	}
}

func TestImportEffectiveWorkdirAndEntrypointCMDInheritance(t *testing.T) {
	external := dockerfileRevision(t, map[string]string{"Dockerfile": "FROM alpine\nWORKDIR relative\n"})
	definition, err := Import(external)
	if err != nil || definition.Workdir != "" || !contains(definition.Gaps, "workdir_external_base_unresolved") {
		t.Fatalf("external workdir=%+v err=%v", definition, err)
	}
	inherited := dockerfileRevision(t, map[string]string{"Dockerfile": "FROM alpine AS base\nWORKDIR /srv/base\nCMD [\"base\"]\nFROM base AS final\nWORKDIR child\nENTRYPOINT [\"entry\"]\n"})
	definition, err = Import(inherited)
	if err != nil || definition.Workdir != "/srv/base/child" || definition.Command != nil {
		t.Fatalf("inherited=%+v err=%v", definition, err)
	}
	local := dockerfileRevision(t, map[string]string{"Dockerfile": "FROM alpine AS base\nCMD [\"base\"]\nFROM base\nCMD [\"local\"]\nENTRYPOINT [\"entry\"]\n"})
	definition, err = Import(local)
	if err != nil || definition.Command == nil || definition.Command.Values[0] != "local" {
		t.Fatalf("local CMD=%+v err=%v", definition, err)
	}
}

func TestImportRejectsUnknownGrammarAndMutationInEveryTerminalStatus(t *testing.T) {
	for _, content := range []string{"# escape=^\nFROM alpine\n", "FROM --bad=x alpine\n", "FROM alpine\nFROBULATE x\n", "FROM ${BASE}\n"} {
		revision := dockerfileRevision(t, map[string]string{"Dockerfile": content})
		definition, err := Import(revision)
		if err != nil || definition.Status != contracts.AcornFoxDockerfileUnsupported && !contains(definition.Gaps, "unresolved_variable_expansion:from") {
			t.Fatalf("grammar %q => %+v err=%v", content, definition, err)
		}
	}
	missing := dockerfileRevision(t, map[string]string{"README": "x"})
	if _, err := (Importer{afterWorkspaceHash: func() { _ = os.WriteFile(filepath.Join(missing.WorkspaceRef, "mutation"), []byte("x"), 0o600) }}).Import(missing); err == nil {
		t.Fatal("waiting mutation bypassed hash")
	}
	unsupported := dockerfileRevision(t, map[string]string{"Dockerfile": "FROM alpine\nRUN cat <<EOF\nEOF\n"})
	if _, err := (Importer{afterWorkspaceHash: func() { _ = os.WriteFile(filepath.Join(unsupported.WorkspaceRef, "mutation"), []byte("x"), 0o600) }}).Import(unsupported); err == nil {
		t.Fatal("unsupported mutation bypassed hash")
	}
}

func TestDockerfileDefinitionContractRejectsInvalidValues(t *testing.T) {
	invalid := contracts.AcornFoxDockerfileDefinition{Status: contracts.AcornFoxDockerfileReady, SourceRevisionID: "src_1", SourceContentDigest: "sha256:" + strings.Repeat("a", 64), DefinitionDigest: "sha256:" + strings.Repeat("b", 64), DockerfileDigest: "sha256:" + strings.Repeat("c", 64), StageCount: 1, FinalStage: &contracts.AcornFoxDockerfileStage{}}
	if err := invalid.Validate(); err == nil {
		t.Fatal("invalid definition accepted")
	}
}

func TestDirectiveVariantsHealthDefaultsAndStrictInputs(t *testing.T) {
	for _, content := range []string{"#syntax=docker/dockerfile:1\n# Escape = \\\nFROM scratch\n", "# SYNTAX = docker/dockerfile:1\n#escape=\\\nFROM scratch\n"} {
		revision := dockerfileRevision(t, map[string]string{"Dockerfile": content})
		definition, err := Import(revision)
		if err != nil || definition.Status != contracts.AcornFoxDockerfileReady {
			t.Fatalf("directive=%+v err=%v", definition, err)
		}
	}
	for _, content := range []string{"# syntax=docker/dockerfile:1\n# syntax=docker/dockerfile:1\nFROM alpine\n", "#escape=`\nFROM alpine\n", "# check=skip=all\nFROM alpine\n", "FROM --platform=linux/amd64 --platform=linux/arm64 alpine\n", "RUN true\nFROM alpine\n", "FROBULATE x\nFROM alpine\n"} {
		revision := dockerfileRevision(t, map[string]string{"Dockerfile": content})
		definition, err := Import(revision)
		if err != nil || definition.Status != contracts.AcornFoxDockerfileUnsupported {
			t.Fatalf("unsafe grammar=%+v err=%v", definition, err)
		}
	}
	revision := dockerfileRevision(t, map[string]string{"Dockerfile": "FROM scratch\nHEALTHCHECK CMD echo ok\n"})
	definition, err := Import(revision)
	if err != nil || definition.Healthcheck.IntervalSeconds != 30 || definition.Healthcheck.TimeoutSeconds != 30 || definition.Healthcheck.Retries != 3 {
		t.Fatalf("defaults=%+v err=%v", definition.Healthcheck, err)
	}
	for _, content := range []string{"FROM scratch\nHEALTHCHECK --interval=0s CMD echo ok\n", "FROM scratch\nHEALTHCHECK --timeout=0s CMD echo ok\n", "FROM scratch\nHEALTHCHECK --retries=0 CMD echo ok\n"} {
		revision := dockerfileRevision(t, map[string]string{"Dockerfile": content})
		definition, err = Import(revision)
		if err != nil || definition.Status != contracts.AcornFoxDockerfileUnsupported {
			t.Fatalf("invalid health=%+v err=%v", definition, err)
		}
	}
	waiting := contracts.AcornFoxDockerfileDefinition{Status: contracts.AcornFoxDockerfileWaitingLater, SourceRevisionID: "src_1", SourceContentDigest: "sha256:" + strings.Repeat("a", 64), DefinitionDigest: "sha256:" + strings.Repeat("b", 64), DockerfileDigest: "sha256:" + strings.Repeat("c", 64), Gaps: []string{"root_dockerfile_missing"}}
	if err := waiting.Validate(); err == nil {
		t.Fatal("waiting digest accepted")
	}
}

func TestScratchAndContractStrictEvidence(t *testing.T) {
	for _, content := range []string{"# Check dependencies\n# healthcheck notes\nFROM scratch\n", "FROM scratch AS base\nFROM base AS final\n"} {
		revision := dockerfileRevision(t, map[string]string{"Dockerfile": content})
		definition, err := Import(revision)
		if err != nil || !contains(definition.Gaps, "healthcheck_missing") || contains(definition.Gaps, "healthcheck_external_base_unobserved") || contains(definition.Gaps, "external_base_config_unobserved") {
			t.Fatalf("scratch=%+v err=%v", definition, err)
		}
	}
	base := func() contracts.AcornFoxDockerfileDefinition {
		return contracts.AcornFoxDockerfileDefinition{Status: contracts.AcornFoxDockerfileReady, SourceRevisionID: "src_1", SourceContentDigest: "sha256:" + strings.Repeat("a", 64), DefinitionDigest: "sha256:" + strings.Repeat("b", 64), DockerfileDigest: "sha256:" + strings.Repeat("c", 64), StageCount: 1, FinalStage: &contracts.AcornFoxDockerfileStage{Name: "stage", Index: 0, From: "scratch"}, Healthcheck: contracts.AcornFoxDockerfileHealthcheck{Present: true, Form: "exec", Test: []string{"echo", "ok"}, IntervalSeconds: 30, TimeoutSeconds: 30, Retries: 3}}
	}
	for _, edit := range []func(*contracts.AcornFoxDockerfileDefinition){func(d *contracts.AcornFoxDockerfileDefinition) { d.FinalStage.Platform = "linux/amd64$" }, func(d *contracts.AcornFoxDockerfileDefinition) { d.FinalStage.Platform = "linux amd64" }, func(d *contracts.AcornFoxDockerfileDefinition) { d.FinalStage.Platform = "linux:amd64" }, func(d *contracts.AcornFoxDockerfileDefinition) {
		d.Healthcheck = contracts.AcornFoxDockerfileHealthcheck{Present: false, Test: []string{"x"}}
	}, func(d *contracts.AcornFoxDockerfileDefinition) {
		d.Healthcheck = contracts.AcornFoxDockerfileHealthcheck{Present: true, Disabled: true, Retries: 1}
	}, func(d *contracts.AcornFoxDockerfileDefinition) { d.Healthcheck.Test = []string{" "} }, func(d *contracts.AcornFoxDockerfileDefinition) { d.Healthcheck.IntervalSeconds = 0 }, func(d *contracts.AcornFoxDockerfileDefinition) { d.Healthcheck.TimeoutSeconds = 0 }, func(d *contracts.AcornFoxDockerfileDefinition) { d.Healthcheck.Retries = 0 }, func(d *contracts.AcornFoxDockerfileDefinition) { d.Healthcheck.IntervalSeconds = 86401 }, func(d *contracts.AcornFoxDockerfileDefinition) { d.Healthcheck.Retries = 101 }} {
		definition := base()
		edit(&definition)
		if err := definition.Validate(); err == nil {
			t.Fatal("malformed contract accepted")
		}
	}
	definition := base()
	definition.ExposedPorts = []contracts.AcornFoxDockerfilePort{{Port: 81, Protocol: "tcp"}, {Port: 80, Protocol: "tcp"}, {Port: 80, Protocol: "tcp"}}
	definition.Environment = []contracts.AcornFoxDockerfileEnvironment{{Name: "Z", Value: "z"}, {Name: "A", Value: "a"}, {Name: "A", Value: "a"}}
	definition.Gaps = []string{"z", "a", "a"}
	definition.Warnings = []string{"w", "a", "w"}
	definition.Shell = []string{"/bin/sh", "-c"}
	definition.Entrypoint = &contracts.AcornFoxDockerfileCommand{Form: "exec", Values: []string{"entry", "arg"}}
	definition.Healthcheck.Test = []string{"echo", "ok"}
	before, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	final, err := contracts.FinalizeAcornFoxDockerfileDefinition(definition)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(definition)
	if err != nil || string(before) != string(after) {
		t.Fatalf("Finalize mutated input err=%v", err)
	}
	if len(final.ExposedPorts) != 2 || len(final.Environment) != 2 || len(final.Gaps) != 2 || len(final.Warnings) != 2 {
		t.Fatalf("normalization=%+v", final)
	}
	definition.Environment[2].Value = "conflict"
	if _, err := contracts.FinalizeAcornFoxDockerfileDefinition(definition); err == nil {
		t.Fatal("conflicting ENV accepted")
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
