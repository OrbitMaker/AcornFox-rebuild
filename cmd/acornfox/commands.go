package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (c *cli) command(args []string) error {
	switch args[0] {
	case "login":
		return c.login(args[1:])
	case "logout":
		return c.logout(args[1:])
	case "session":
		if len(args) != 1 {
			return errors.New("usage: acornfox session")
		}
		return c.callCommand(http.MethodGet, "/auth/session", nil, false, "", 15*time.Second, shapeSession)
	case "host":
		return c.host(args[1:])
	case "password":
		return c.passwordCommand(args[1:])
	case "apps":
		return c.apps(args[1:])
	case "sources":
		return c.sources(args[1:])
	case "deployments":
		return c.deployments(args[1:])
	case "deploy":
		return c.deploy(args[1:])
	case "status":
		return c.status(args[1:])
	case "operation":
		return c.operation(args[1:])
	case "logs":
		return c.logs(args[1:])
	case "restart", "redeploy", "probe":
		return c.deliveryAction(args[0], args[1:])
	case "public-access":
		return c.publicAccess(args[1:])
	case "delivery-source":
		return c.deliverySource(args[1:])
	case "fix-candidate":
		return c.fixCandidate(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func (c *cli) login(args []string) error {
	args, stdin, err := parseBooleanFlag(args, "--password-stdin")
	if err != nil {
		return err
	}
	positionals, values, err := parseFlags(args, "--server")
	if err != nil {
		return err
	}
	if len(positionals) != 0 || values["--server"] == "" {
		return errors.New("usage: acornfox login --server HTTPS_ORIGIN [--password-stdin]")
	}
	origin, err := normalizeOrigin(values["--server"], false)
	if err != nil {
		return err
	}
	if existing, stateErr := loadState(c.env); stateErr == nil && existing.Origin != origin {
		return errors.New("server differs from saved session")
	}
	password := ""
	if stdin {
		password, err = readLines(c.in, 1)
	} else {
		fmt.Fprint(c.err, "Password: ")
		password, err = readInteractivePassword(c.in)
	}
	if err != nil {
		return err
	}
	if password == "" {
		return errors.New("password is required")
	}
	c.secrets = append(c.secrets, password)
	state := sessionState{Origin: origin}
	response, err := c.request(context.Background(), state, http.MethodPost, "/auth/login", map[string]string{"password": password}, false, "", 15*time.Second)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return decodeError(response)
	}
	state.Session, state.CSRF = cookie(response, "__Host-acornfox_session"), cookie(response, "__Host-acornfox_csrf")
	if state.Session == "" || state.CSRF == "" {
		return invalidResponse("login response omitted session cookies")
	}
	value, err := decodeResponse(response.Body, shapeSession)
	if err != nil {
		return err
	}
	session, ok := value.(apiSession)
	if !ok {
		return invalidResponse("login response does not match the AcornFox API contract")
	}
	state.ExpiresAt, err = responseExpiry(session, true)
	if err != nil {
		return invalidResponse("login response expiry is invalid")
	}
	if err = saveState(c.env, state); err != nil {
		return err
	}
	return c.emit(value)
}
func (c *cli) logout(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: acornfox logout")
	}
	state, err := loadState(c.env)
	if err != nil {
		return err
	}
	value, err := c.performCall(state, http.MethodPost, "/auth/logout", nil, true, "", 30*time.Second, shapeSession)
	if err != nil {
		return err
	}
	if cleanupErr := removeState(c.env); cleanupErr != nil {
		return localStateError()
	}
	return c.emit(value)
}
func (c *cli) passwordCommand(args []string) error {
	if len(args) < 1 || args[0] != "change" {
		return errors.New("usage: acornfox password change [--password-stdin]")
	}
	return c.password(args[1:])
}
func (c *cli) password(args []string) error {
	args, stdin, err := parseBooleanFlag(args, "--password-stdin")
	if err != nil {
		return err
	}
	if len(args) != 0 {
		return errors.New("usage: acornfox password change [--password-stdin]")
	}
	state, err := loadState(c.env)
	if err != nil {
		return err
	}
	values := []string{}
	if stdin {
		values, err = readLinesN(c.in, 3)
	} else {
		values, err = c.readPasswordChange()
	}
	if err != nil {
		return err
	}
	if values[1] != values[2] {
		return errors.New("new password confirmation does not match")
	}
	if values[0] == "" || values[1] == "" {
		return errors.New("password is required")
	}
	c.secrets = append(c.secrets, values...)
	response, err := c.performCall(state, http.MethodPost, "/auth/password", map[string]string{"current_password": values[0], "new_password": values[1]}, true, "", 30*time.Second, shapeSession)
	if err != nil {
		return err
	}
	if cleanupErr := removeState(c.env); cleanupErr != nil {
		return localStateError()
	}
	return c.emit(response)
}
func (c *cli) readPasswordChange() ([]string, error) {
	fmt.Fprint(c.err, "Current password: ")
	current, err := readInteractivePassword(c.in)
	if err != nil {
		return nil, err
	}
	fmt.Fprint(c.err, "New password: ")
	fresh, err := readInteractivePassword(c.in)
	if err != nil {
		return nil, err
	}
	fmt.Fprint(c.err, "Confirm new password: ")
	confirmation, err := readInteractivePassword(c.in)
	if err != nil {
		return nil, err
	}
	return []string{current, fresh, confirmation}, nil
}
func (c *cli) apps(args []string) error {
	if len(args) == 1 && args[0] == "list" {
		return c.callCommand(http.MethodGet, "/apps", nil, false, "", 15*time.Second, shapeApps)
	}
	if len(args) == 2 && args[0] == "get" {
		id, err := requireID(args[1], "application ID")
		if err != nil {
			return err
		}
		return c.callCommand(http.MethodGet, "/apps/"+pathID(id), nil, false, "", 15*time.Second, shapeApplication)
	}
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: acornfox apps list|get|create")
	}
	positionals, values, err := parseFlags(args[1:], "--name", "--repository", "--ref", "--idempotency-key")
	if err != nil {
		return err
	}
	if len(positionals) != 0 || strings.TrimSpace(values["--name"]) == "" {
		return errors.New("apps create requires --name --repository --ref")
	}
	repository, err := normalizePublicGit(values["--repository"])
	if err != nil {
		return err
	}
	ref, err := requireRef(values["--ref"])
	if err != nil {
		return err
	}
	key, err := idempotencyKey(values)
	if err != nil {
		return err
	}
	body := map[string]any{"name": values["--name"], "source": map[string]string{"type": "public_git", "repository_url": repository, "ref": ref}}
	return c.callCommand(http.MethodPost, "/apps", body, true, key, 3*time.Minute, shapeCreateApp)
}
func (c *cli) sources(args []string) error {
	if len(args) >= 2 && args[0] == "list" {
		id, err := requireID(args[1], "application ID")
		if err != nil {
			return err
		}
		p, values, err := parseFlags(args[2:], "--limit", "--cursor")
		if err != nil {
			return err
		}
		if len(p) != 0 {
			return errors.New("usage: acornfox sources list APP_ID")
		}
		if err := parseLimit(values); err != nil {
			return err
		}
		return c.callCommand(http.MethodGet, "/apps/"+pathID(id)+"/sources"+optionalQuery(values), nil, false, "", 15*time.Second, shapeSourceList)
	}
	if len(args) == 3 && args[0] == "get" {
		app, err := requireID(args[1], "application ID")
		if err != nil {
			return err
		}
		source, err := requireID(args[2], "source ID")
		if err != nil {
			return err
		}
		return c.callCommand(http.MethodGet, "/apps/"+pathID(app)+"/sources/"+pathID(source), nil, false, "", 15*time.Second, shapeSource)
	}
	if len(args) == 3 && args[0] == "metadata" {
		app, err := requireID(args[1], "application ID")
		if err != nil {
			return err
		}
		source, err := requireID(args[2], "source ID")
		if err != nil {
			return err
		}
		return c.callCommand(http.MethodGet, "/apps/"+pathID(app)+"/sources/"+pathID(source)+"/metadata", nil, false, "", 15*time.Second, shapeSourceMetadata)
	}
	if len(args) < 4 || args[0] != "update" {
		return errors.New("usage: acornfox sources list|get|metadata APP_ID [SOURCE_ID]")
	}
	app, err := requireID(args[1], "application ID")
	if err != nil {
		return err
	}
	base, err := requireID(args[2], "base source revision ID")
	if err != nil {
		return err
	}
	positionals, values, err := parseFlags(args[3:], "--idempotency-key")
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("usage: acornfox sources update APP_ID BASE_SOURCE_REVISION_ID REF [--idempotency-key]")
	}
	ref, err := requireRef(positionals[0])
	if err != nil {
		return err
	}
	key, err := idempotencyKey(values)
	if err != nil {
		return err
	}
	body := map[string]string{"base_source_revision_id": base, "ref": ref}
	return c.callCommand(http.MethodPost, "/apps/"+pathID(app)+"/sources", body, true, key, 3*time.Minute, shapeSourceUpdate)
}

func (c *cli) host(args []string) error {
	if len(args) != 1 || args[0] != "metrics" {
		return errors.New("usage: acornfox host metrics")
	}
	return c.callCommand(http.MethodGet, "/host/metrics", nil, false, "", 15*time.Second, shapeHostMetrics)
}
func (c *cli) deployments(args []string) error {
	if len(args) < 2 || args[0] != "list" {
		return errors.New("usage: acornfox deployments list APP_ID")
	}
	app, err := requireID(args[1], "application ID")
	if err != nil {
		return err
	}
	p, values, err := parseFlags(args[2:], "--limit", "--cursor")
	if err != nil {
		return err
	}
	if len(p) != 0 {
		return errors.New("usage: acornfox deployments list APP_ID")
	}
	if err := parseLimit(values); err != nil {
		return err
	}
	return c.callCommand(http.MethodGet, "/apps/"+pathID(app)+"/deliveries"+optionalQuery(values), nil, false, "", 15*time.Second, shapeDeploymentList)
}
func (c *cli) deploy(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: acornfox deploy APP_ID --source SOURCE_ID [--port PORT]")
	}
	app, err := requireID(args[0], "application ID")
	if err != nil {
		return err
	}
	p, values, err := parseFlags(args[1:], "--source", "--port", "--idempotency-key")
	if err != nil {
		return err
	}
	if len(p) != 0 {
		return errors.New("usage: acornfox deploy APP_ID --source SOURCE_ID [--port PORT]")
	}
	source, err := requireID(values["--source"], "source ID")
	if err != nil {
		return err
	}
	key, err := idempotencyKey(values)
	if err != nil {
		return err
	}
	body := map[string]any{"source_revision_id": source}
	if raw := values["--port"]; raw != "" {
		port, err := parsePort(raw)
		if err != nil {
			return err
		}
		body["container_port"] = port
	}
	return c.callCommand(http.MethodPost, "/apps/"+pathID(app)+"/deliveries", body, true, key, 10*time.Minute, shapeCommand)
}
func (c *cli) status(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: acornfox status APP_ID DEPLOYMENT_ID")
	}
	app, err := requireID(args[0], "application ID")
	if err != nil {
		return err
	}
	deployment, err := requireID(args[1], "deployment ID")
	if err != nil {
		return err
	}
	return c.callCommand(http.MethodGet, "/apps/"+pathID(app)+"/deliveries/"+pathID(deployment), nil, false, "", 15*time.Second, shapeStatus)
}
func (c *cli) operation(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: acornfox operation APP_ID OPERATION_ID")
	}
	app, err := requireID(args[0], "application ID")
	if err != nil {
		return err
	}
	operationID, err := requireID(args[1], "operation ID")
	if err != nil {
		return err
	}
	return c.callCommand(http.MethodGet, "/apps/"+pathID(app)+"/operations/"+pathID(operationID), nil, false, "", 15*time.Second, shapeOperationResult)
}
func (c *cli) deliverySource(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: acornfox delivery-source APP_ID DEPLOYMENT_ID")
	}
	app, err := requireID(args[0], "application ID")
	if err != nil {
		return err
	}
	deployment, err := requireID(args[1], "deployment ID")
	if err != nil {
		return err
	}
	return c.callCommand(http.MethodGet, "/apps/"+pathID(app)+"/deliveries/"+pathID(deployment)+"/source", nil, false, "", 15*time.Second, shapeDeliverySource)
}
func (c *cli) logs(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: acornfox logs APP_ID DEPLOYMENT_ID --source build|runtime")
	}
	app, err := requireID(args[0], "application ID")
	if err != nil {
		return err
	}
	deployment, err := requireID(args[1], "deployment ID")
	if err != nil {
		return err
	}
	p, values, err := parseFlags(args[2:], "--source", "--limit", "--cursor")
	if err != nil {
		return err
	}
	if len(p) != 0 || (values["--source"] != "build" && values["--source"] != "runtime") {
		return errors.New("logs requires --source build|runtime")
	}
	if err := parseLimit(values); err != nil {
		return err
	}
	query := optionalQuery(values)
	if query == "" {
		query = "?source=" + values["--source"]
	} else {
		query = "?source=" + values["--source"] + "&" + strings.TrimPrefix(query, "?")
	}
	return c.callCommand(http.MethodGet, "/apps/"+pathID(app)+"/deliveries/"+pathID(deployment)+"/logs"+query, nil, false, "", 30*time.Second, shapeLogs)
}
func (c *cli) deliveryAction(action string, args []string) error {
	if len(args) < 2 {
		return errors.New("usage: acornfox restart|redeploy|probe APP_ID DEPLOYMENT_ID")
	}
	app, err := requireID(args[0], "application ID")
	if err != nil {
		return err
	}
	deployment, err := requireID(args[1], "deployment ID")
	if err != nil {
		return err
	}
	p, values, err := parseFlags(args[2:], "--idempotency-key")
	if err != nil {
		return err
	}
	if len(p) != 0 {
		return errors.New("usage: acornfox restart|redeploy|probe APP_ID DEPLOYMENT_ID")
	}
	key, err := idempotencyKey(values)
	if err != nil {
		return err
	}
	body := map[string]any{}
	if action == "probe" {
		action = "probes"
		body = map[string]any{"protocol": "http", "path": "/"}
	}
	return c.callCommand(http.MethodPost, "/apps/"+pathID(app)+"/deliveries/"+pathID(deployment)+"/"+action, body, true, key, 30*time.Second, shapeCommand)
}
func (c *cli) publicAccess(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "check":
			return c.publicAccessCheck(args[1:])
		case "observation":
			return c.publicAccessObservation(args[1:])
		}
	}

	if len(args) < 3 {
		return errors.New("usage: acornfox public-access get|enable|disable|check|observation APP_ID DEPLOYMENT_ID")
	}
	action, appRaw, deploymentRaw := args[0], args[1], args[2]
	app, err := requireID(appRaw, "application ID")
	if err != nil {
		return err
	}
	deployment, err := requireID(deploymentRaw, "deployment ID")
	if err != nil {
		return err
	}
	path := "/apps/" + pathID(app) + "/deliveries/" + pathID(deployment) + "/public-access"
	if action == "get" {
		if len(args) != 3 {
			return errors.New("usage: acornfox public-access get APP_ID DEPLOYMENT_ID")
		}
		return c.callCommand(http.MethodGet, path, nil, false, "", 30*time.Second, shapePublicAccess)
	}
	if action != "enable" && action != "disable" {
		return errors.New("usage: acornfox public-access get|enable|disable|check|observation APP_ID DEPLOYMENT_ID")
	}
	p, values, err := parseFlags(args[3:], "--idempotency-key")
	if err != nil {
		return err
	}
	if len(p) != 0 {
		return errors.New("usage: acornfox public-access enable|disable APP_ID DEPLOYMENT_ID")
	}
	key, err := idempotencyKey(values)
	if err != nil {
		return err
	}
	return c.callCommand(http.MethodPut, path, map[string]bool{"enabled": action == "enable"}, true, key, 30*time.Second, shapePublicAccess)
}
