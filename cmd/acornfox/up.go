package main

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

func (c *cli) upProject(args []string) error {
	args, noDeploy, err := parseBooleanFlag(args, "--no-deploy")
	if err != nil {
		return err
	}
	positionals, values, err := parseFlags(args, "--name", "--ref", "--port", "--runtime-file", "--app", "--base-source", "--idempotency-key")
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("usage: acornfox up REPOSITORY_OR_DIRECTORY [--name NAME] [--port PORT] [--runtime-file JSON_FILE] [--app APP_ID --base-source SOURCE_ID] [--no-deploy]")
	}
	runtime, err := readRuntimeInput(values["--runtime-file"])
	if err != nil {
		return err
	}
	selectedPort := 0
	if raw := values["--port"]; raw != "" {
		selectedPort, err = parsePort(raw)
		if err != nil {
			return err
		}
	}
	target := positionals[0]
	isGit := strings.HasPrefix(target, "https://")
	name := strings.TrimSpace(values["--name"])
	ref := strings.TrimSpace(values["--ref"])
	if isGit {
		target, err = normalizePublicGit(target)
		if err != nil {
			return err
		}
		if ref == "" {
			ref = "main"
		}
		if _, err := requireRef(ref); err != nil {
			return err
		}
		if name == "" {
			name = acornFoxDefaultAppName(target)
		}
	} else {
		if ref != "" {
			return errors.New("--ref applies only to a Git repository")
		}
		if _, err := c.inspectLocalProject(target); err != nil {
			return err
		}
		if name == "" {
			absolute, _ := filepath.Abs(target)
			name = acornFoxDefaultAppName("https://local.invalid/" + filepath.Base(absolute))
		}
	}
	appID := values["--app"]
	base := values["--base-source"]
	if (appID == "") != (base == "") {
		return errors.New("existing local applications require both --app and --base-source")
	}
	if appID != "" {
		if isGit {
			return errors.New("use sources update to update an existing Git application")
		}
		if _, err := requireID(appID, "application ID"); err != nil {
			return err
		}
		if _, err := requireID(base, "source ID"); err != nil {
			return err
		}
	}
	key, err := idempotencyKey(values)
	if err != nil {
		return err
	}
	state, err := loadState(c.env)
	if err != nil {
		return err
	}
	source := map[string]string{"type": "public_git", "repository_url": target, "ref": ref}
	if !isGit {
		upload, err := c.uploadLocalProject(state, target, key+":upload")
		if err != nil {
			return err
		}
		source = map[string]string{"type": "upload", "upload_id": upload.ID}
	}
	var app apiApplication
	var sourceID string
	if appID == "" {
		value, err := c.performCall(state, http.MethodPost, "/apps", map[string]any{"name": name, "source": source}, true, key+":app", 3*time.Minute, shapeCreateApp)
		if err != nil {
			return err
		}
		created := value.(apiCreateApp)
		app = created.Application
		sourceID = created.SourceRevisionID
	} else {
		value, err := c.performCall(state, http.MethodGet, "/apps/"+pathID(appID), nil, false, "", 15*time.Second, shapeApplication)
		if err != nil {
			return err
		}
		app = value.(apiApplication)
		updated, err := c.performCall(state, http.MethodPost, "/apps/"+pathID(appID)+"/sources", map[string]string{"base_source_revision_id": base, "upload_id": source["upload_id"]}, true, key+":source", 3*time.Minute, shapeSourceUpdate)
		if err != nil {
			return err
		}
		sourceID = updated.(apiSourceUpdate).SourceRevisionID
	}
	value, err := c.performCall(state, http.MethodGet, "/apps/"+pathID(app.ID)+"/sources/"+pathID(sourceID)+"/deployment-plan", nil, false, "", 15*time.Second, shapeDeploymentPlan)
	if err != nil {
		return err
	}
	plan := value.(apiDeploymentPlan)
	if selectedPort == 0 && plan.PortSelection.SelectedPort != nil {
		selectedPort = *plan.PortSelection.SelectedPort
	}
	result := map[string]any{"application": app, "source_revision_id": sourceID, "deployment_plan": plan, "accepted": false, "deployed": false}
	if noDeploy {
		return c.emit(result)
	}
	if plan.Dockerfile.Status != "ready" || selectedPort == 0 {
		message := "Dockerfile configuration is required; ask your AI to prepare it and resubmit this application"
		if selectedPort == 0 && plan.Dockerfile.Status == "ready" {
			message = fmt.Sprintf("container port is required; detected candidates: %v", plan.PortSelection.Candidates)
		}
		result["status"] = "configuration_required"
		result["blocking_reason"] = message
		result["next_actions"] = []map[string]any{{"command": "plan", "arguments": []string{app.ID, sourceID}}}
		if err := c.emit(result); err != nil {
			return err
		}
		return reportedCLIResult{2, message}
	}
	body := map[string]any{"source_revision_id": sourceID, "container_port": selectedPort}
	if runtime != nil {
		body["runtime"] = runtime
	}
	delivered, err := c.performCall(state, http.MethodPost, "/apps/"+pathID(app.ID)+"/deliveries", body, true, key+":delivery", 10*time.Minute, shapeCommand)
	if err != nil {
		return err
	}
	command := delivered.(apiCommand)
	result["accepted"] = true
	result["status"] = "accepted"
	result["deployment"] = command
	result["next_actions"] = []map[string]any{{"command": "status", "arguments": []string{app.ID, command.DeploymentID}}, {"command": "logs", "arguments": []string{app.ID, command.DeploymentID, "--source", "build"}}, {"command": "logs", "arguments": []string{app.ID, command.DeploymentID, "--source", "runtime"}}}
	return c.emit(result)
}
func (c *cli) uploadSourceUpdate(args []string) error {
	if len(args) < 3 {
		return errors.New("usage: acornfox sources upload APP_ID BASE_SOURCE_ID PROJECT_DIRECTORY [--idempotency-key KEY]")
	}
	app, err := requireID(args[0], "application ID")
	if err != nil {
		return err
	}
	base, err := requireID(args[1], "source ID")
	if err != nil {
		return err
	}
	paths, values, err := parseFlags(args[2:], "--idempotency-key")
	if err != nil {
		return err
	}
	if len(paths) != 1 {
		return errors.New("one local project directory is required")
	}
	key, err := idempotencyKey(values)
	if err != nil {
		return err
	}
	state, err := loadState(c.env)
	if err != nil {
		return err
	}
	upload, err := c.uploadLocalProject(state, paths[0], key+":upload")
	if err != nil {
		return err
	}
	return c.callWithState(state, http.MethodPost, "/apps/"+pathID(app)+"/sources", map[string]string{"base_source_revision_id": base, "upload_id": upload.ID}, true, key+":source", 3*time.Minute, shapeSourceUpdate)
}
