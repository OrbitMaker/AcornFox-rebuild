package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

func (c *cli) command(args []string) error {
	switch args[0] {
	case "help", "--help", "-h":
		if len(args) != 1 {
			return errors.New("usage: acornfox help [--json]")
		}
		return c.emit(map[string]any{"product": "AcornFox", "commands": []string{"login --server HTTPS_ORIGIN [--password-stdin]", "login --local --server http://127.0.0.1:PORT [--password-stdin]", "logout", "session", "password", "source-build prepare --name NAME --repository HTTPS_GIT --commit PINNED_SHA --idempotency-key KEY", "source-build get INTENT_ID", "source-build build-confirm PREPARE_INTENT_ID --source-revision ID --source-digest SHA256 --service NAME --repository TARGET --disk-bytes N --timeout-seconds N --idempotency-key KEY", "source-build run-plan BUILD_INTENT_ID --artifact ID --port N --idempotency-key KEY", "source-build run-plan get PLAN_ID", "source-build run-confirm PLAN_ID --digest SHA256 --idempotency-key KEY", "image apps [--limit N]", "image status DEPLOYMENT_ID", "image metrics DEPLOYMENT_ID", "image metrics-recent DEPLOYMENT_ID [--limit N]", "image logs DEPLOYMENT_ID [--tail N] [--since RFC3339]", "image plan --image REF --name NAME [--port N] [--env KEY=VALUE]", "image plan get PLAN_ID", "image confirm PLAN_ID --digest SHA256 --idempotency-key KEY", "image operation OP_ID", "image stop|start|restart DEPLOYMENT_ID --idempotency-key KEY", "image lifecycle-operation OP_ID", "domain bind|remove DEPLOYMENT_ID --hostname HOST --idempotency-key KEY", "domain get DEPLOYMENT_ID", "domain operation OP_ID", "host metrics", "host recent [--limit N]"}, "note": "Source prepare, Build approval, Run plan, and Run confirmation are separate; accepted/pending is not a completed build or deployment; query source-build get and image operation for results; 127.0.0.1 endpoints are accessible on the server machine only"})
	case "login":
		return c.login(args[1:])
	case "logout":
		return c.logout(args[1:])
	case "session":
		if len(args) != 1 {
			return errors.New("usage: acornfox session")
		}
		return c.callCommand(http.MethodGet, "/auth/session", nil, false, "", 15*time.Second, shapeSession)
	case "image":
		return c.imageCommand(args[1:])
	case "domain":
		return c.domainCommand(args[1:])
	case "source-build":
		return c.sourceBuildCommand(args[1:])
	case "host":
		return c.host(args[1:])
	case "password":
		return c.passwordCommand(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func (c *cli) login(args []string) error {
	args, local, err := parseBooleanFlag(args, "--local")
	if err != nil {
		return err
	}
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
	origin, err := normalizeOrigin(values["--server"], local)
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
	state := sessionState{Origin: origin, Local: local}
	response, err := c.request(context.Background(), state, http.MethodPost, "/auth/login", map[string]string{"password": password}, false, "", 15*time.Second)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return decodeError(response)
	}
	state.Session, state.CSRF = cookie(response, sessionCookieName(state)), cookie(response, csrfCookieName(state))
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

func acornFoxDefaultAppName(repository string) string {
	parsed, err := url.Parse(repository)
	if err != nil {
		return "app"
	}
	name := strings.TrimSuffix(strings.TrimSuffix(parsed.Path, "/"), ".git")
	if index := strings.LastIndex(name, "/"); index >= 0 {
		name = name[index+1:]
	}
	name = strings.TrimSpace(strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, name))
	name = strings.Trim(name, "-_")
	if name == "" {
		return "app"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

func (c *cli) host(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: acornfox host metrics|recent [--limit N]")
	}
	switch args[0] {
	case "metrics":
		if len(args) != 1 {
			return errors.New("usage: acornfox host metrics")
		}
		return c.callCommand(http.MethodGet, "/host/metrics", nil, false, "", 15*time.Second, shapeHostMetrics)
	case "recent":
		positionals, values, err := parseFlags(args[1:], "--limit")
		if err != nil {
			return err
		}
		if len(positionals) != 0 {
			return errors.New("usage: acornfox host recent [--limit N]")
		}
		query := ""
		if raw, ok := values["--limit"]; ok && raw != "" {
			val, parseErr := strconv.Atoi(raw)
			if parseErr != nil || val < 1 || val > 360 || strconv.Itoa(val) != raw {
				return errors.New("limit must be between 1 and 360")
			}
			query = fmt.Sprintf("?limit=%d", val)
		}
		return c.callCommand(http.MethodGet, "/host/metrics/recent"+query, nil, false, "", 15*time.Second, shapeHostMetricsRecent)
	default:
		return errors.New("usage: acornfox host metrics|recent [--limit N]")
	}
}

// imageCommand uses the Native image API; confirmation is always explicit.
func (c *cli) imageCommand(args []string) error {
	usage := errors.New("usage: acornfox image metrics DEPLOYMENT_ID | metrics-recent DEPLOYMENT_ID [--limit N] | status DEPLOYMENT_ID | logs DEPLOYMENT_ID [--tail N] [--since RFC3339] | apps [--limit N] | plan --image REF --name NAME [--port N] [--env KEY=VALUE] | plan get PLAN_ID | confirm PLAN_ID --digest SHA256 --idempotency-key KEY | operation OP_ID | stop|start|restart DEPLOYMENT_ID --idempotency-key KEY | lifecycle-operation OP_ID")
	if len(args) == 0 {
		return usage
	}
	if args[0] == "metrics" || args[0] == "metrics-recent" {
		allowed := []string{}
		if args[0] == "metrics-recent" {
			allowed = []string{"--limit"}
		}
		positionals, values, err := parseFlags(args[1:], allowed...)
		if err != nil {
			return err
		}
		if len(positionals) != 1 {
			return usage
		}
		id, err := requireID(positionals[0], "deployment ID")
		if err != nil {
			return err
		}
		path, shape := "/image-deployments/"+pathID(id)+"/metrics", shapeImageMetrics
		if args[0] == "metrics-recent" {
			path, shape = path+"/recent", shapeImageMetricsRecent
			if raw, present := values["--limit"]; present {
				limit, err := strconv.Atoi(raw)
				if err != nil || limit < 1 || limit > appcontracts.ImageMetricsHistorySamples || strconv.Itoa(limit) != raw {
					return errors.New("limit must be between 1 and 360")
				}
				path += "?limit=" + raw
			}
		}
		state, err := loadState(c.env)
		if err != nil {
			return err
		}
		value, err := c.performCall(state, http.MethodGet, path, nil, false, "", 30*time.Second, shape)
		if err != nil {
			return err
		}
		if !c.json {
			if recent, ok := value.(appcontracts.ImageMetricsRecentResult); ok && recent.RecordingStatus == "not_selected" {
				fmt.Fprintln(c.err, "This deployment is not selected for sampling; missing measurements do not mean zero usage.")
			}
			if recent, ok := value.(appcontracts.ImageMetricsRecentResult); ok && recent.RecordingStatus == "stale" && (recent.Reason == "not_running" || recent.Reason == "read_unavailable" || recent.Reason == "runtime_changed") {
				fmt.Fprintln(c.err, "Latest measurements are unavailable; stale does not mean zero usage or endpoint failure.")
			}
			if current, ok := value.(appcontracts.ImageMetricsResult); ok && !current.Available {
				fmt.Fprintln(c.err, "Current measurements are unavailable; missing values do not mean zero usage.")
			}
		}
		return c.emit(value)
	}
	if args[0] == "status" || args[0] == "logs" {
		allowed := []string{}
		if args[0] == "logs" {
			allowed = []string{"--tail", "--since"}
		}
		positionals, values, err := parseFlags(args[1:], allowed...)
		if err != nil {
			return err
		}
		if len(positionals) != 1 {
			return usage
		}
		id, err := requireID(positionals[0], "deployment ID")
		if err != nil {
			return err
		}
		path, shape := "/image-deployments/"+pathID(id)+"/observation", shapeImageObservation
		if args[0] == "logs" {
			path, shape = "/image-deployments/"+pathID(id)+"/logs", shapeImageLogObservation
			query := url.Values{}
			if raw, present := values["--tail"]; present {
				tail, err := strconv.Atoi(raw)
				if err != nil || tail < 1 || tail > appcontracts.ImageObservationLogTail || strconv.Itoa(tail) != raw {
					return errors.New("tail must be between 1 and 64")
				}
				query.Set("tail", raw)
			}
			if raw, present := values["--since"]; present {
				since, err := time.Parse(time.RFC3339Nano, raw)
				now := time.Now().UTC()
				// Coarse age guard allows small host skew; server decides the exact30m/future bounds.
				if err != nil || since.Before(now.Add(-32*time.Minute)) {
					return errors.New("since must be an RFC3339 timestamp within the past 30 minutes")
				}
				query.Set("since", since.UTC().Format(time.RFC3339Nano))
			}
			if len(query) > 0 {
				path += "?" + query.Encode()
			}
		}
		state, err := loadState(c.env)
		if err != nil {
			return err
		}
		value, err := c.performCall(state, http.MethodGet, path, nil, false, "", 30*time.Second, shape)
		if err != nil {
			return err
		}
		if !c.json {
			fmt.Fprintln(c.err, "Endpoint readiness was not probed; endpoint_ready=false does not mean access failed.")
		}
		return c.emit(value)
	}
	if args[0] == "apps" {
		positionals, values, err := parseFlags(args[1:], "--limit")
		if err != nil {
			return err
		}
		if len(positionals) != 0 {
			return usage
		}
		path := "/image-apps"
		if raw, present := values["--limit"]; present {
			limit, err := strconv.Atoi(raw)
			if err != nil || limit < 1 || limit > 100 || strconv.Itoa(limit) != raw {
				return errors.New("limit must be between 1 and 100")
			}
			path += "?limit=" + raw
		}
		return c.callCommand(http.MethodGet, path, nil, false, "", 30*time.Second, shapeManagedImageApps)
	}
	if args[0] == "stop" || args[0] == "start" || args[0] == "restart" || args[0] == "lifecycle-operation" {
		return c.imageLifecycleCommand(args)
	}
	if args[0] == "operation" || (args[0] == "plan" && len(args) > 1 && args[1] == "get") {
		idIndex, path, shape := 1, "/operations/", shapeNativeImageOperation
		if args[0] == "plan" {
			idIndex, path, shape = 2, "/image-plans/", shapeNativeImagePlan
		}
		if len(args) != idIndex+1 {
			return usage
		}
		id, err := requireID(args[idIndex], "image ID")
		if err != nil {
			return err
		}
		state, err := loadState(c.env)
		if err != nil {
			return err
		}
		value, err := c.performCall(state, http.MethodGet, path+pathID(id), nil, false, "", 30*time.Second, shape)
		if err != nil {
			return err
		}
		switch actual := value.(type) {
		case appcontracts.ImagePlan:
			if actual.ID.String() != id {
				return invalidResponse("image plan response does not match requested plan")
			}
		case appcontracts.ImageOperationDetailWithResult:
			if actual.OperationID.String() != id {
				return invalidResponse("image operation response does not match requested operation")
			}
		default:
			return invalidResponse("image response does not match requested contract")
		}
		if operation, ok := value.(appcontracts.ImageOperationDetailWithResult); ok && operation.Result != nil && operation.Result.Endpoint != "" && !c.json {
			fmt.Fprintln(c.err, "127.0.0.1 endpoint is accessible on the server machine only.")
		}
		return c.emit(value)
	}
	if args[0] == "confirm" {
		positionals, values, err := parseFlags(args[1:], "--digest", "--idempotency-key")
		if err != nil {
			return err
		}
		if len(positionals) != 1 || strings.TrimSpace(values["--idempotency-key"]) == "" || !validImageDigest(values["--digest"]) {
			return usage
		}
		id, err := requireID(positionals[0], "plan ID")
		if err != nil {
			return err
		}
		key := values["--idempotency-key"]
		state, err := loadState(c.env)
		if err != nil {
			return err
		}
		if state.CSRF == "" {
			return errors.New("session omitted CSRF token; log in again")
		}
		body := appcontracts.ConfirmImagePlanInput{PlanID: domain.ID(id), PlanDigest: values["--digest"], IdempotencyKey: key}
		value, err := c.performCall(state, http.MethodPost, "/image-plans/"+pathID(id)+"/confirm", body, true, key, 30*time.Second, shapeNativeImageConfirm)
		if err == nil {
			actual, ok := value.(appcontracts.ConfirmImagePlanResult)
			if !ok || actual.PlanID != body.PlanID || actual.PlanDigest != body.PlanDigest {
				err = invalidResponse("image confirmation response does not match requested plan and digest")
			}
		}
		if err != nil {
			var apiErr apiError
			if errors.As(err, &apiErr) && (apiErr.network || apiErr.contract || apiErr.status >= 500) {
				apiErr.Message += "; confirmation outcome is unknown; retry this command with the same --idempotency-key"
				return apiErr
			}
			return err
		}
		return c.emit(value)
	}
	if args[0] != "plan" {
		return usage
	}
	// Extract only the repeatable env flag, then retain the existing strict flag parser.
	clean := []string{}
	environment := map[string]string{}
	for i := 1; i < len(args); i++ {
		if args[i] != "--env" {
			clean = append(clean, args[i])
			continue
		}
		if i+1 >= len(args) {
			return errors.New("--env requires KEY=VALUE")
		}
		i++
		name, value, ok := strings.Cut(args[i], "=")
		if !ok || strings.TrimSpace(name) == "" {
			return errors.New("--env requires KEY=VALUE")
		}
		if _, exists := environment[name]; exists {
			return errors.New("duplicate environment name")
		}
		environment[name] = value
		// Prevent even server error text from echoing supplied environment values.
		if value != "" {
			c.secrets = append(c.secrets, value)
		}
	}
	positionals, values, err := parseFlags(clean, "--image", "--name", "--port")
	if err != nil {
		return err
	}
	if len(positionals) != 0 || strings.TrimSpace(values["--image"]) == "" || strings.TrimSpace(values["--name"]) == "" {
		return usage
	}
	port := 0
	if raw, present := values["--port"]; present {
		port, err = strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			return errors.New("--port must be between 1 and 65535")
		}
	}
	state, err := loadState(c.env)
	if err != nil {
		return err
	}
	if state.CSRF == "" {
		return errors.New("session omitted CSRF token; log in again")
	}
	body := appcontracts.ImagePlanInput{AppName: values["--name"], Image: values["--image"], Port: port, Environment: environment}
	return c.callWithState(state, http.MethodPost, "/image-plans", body, true, "", 30*time.Second, shapeNativeImagePlan)
}

// sourceBuildCommand exposes the existing Core source/build and source-origin
// image APIs. Each mutating phase has its own explicit key and is never
// advanced automatically by a preceding accepted response.
func (c *cli) sourceBuildCommand(args []string) error {
	usage := errors.New("usage: acornfox source-build prepare|get|build-confirm|run-plan|run-confirm (see acornfox help)")
	if len(args) == 0 {
		return usage
	}
	if args[0] == "get" {
		if len(args) != 2 {
			return usage
		}
		id, err := requireID(args[1], "source-build intent ID")
		if err != nil {
			return err
		}
		state, err := loadState(c.env)
		if err != nil {
			return err
		}
		value, err := c.performCall(state, http.MethodGet, "/source-build/intents/"+pathID(id), nil, false, "", 30*time.Second, shapeSourceBuildIntent)
		if err != nil {
			return err
		}
		intent, ok := value.(appcontracts.SourceBuildPublicIntent)
		if !ok || intent.IntentID.String() != id {
			return invalidResponse("source-build intent response does not match requested ID")
		}
		return c.emit(value)
	}
	if args[0] == "run-plan" && len(args) > 1 && args[1] == "get" {
		if len(args) != 3 {
			return usage
		}
		id, err := requireID(args[2], "source-run plan ID")
		if err != nil {
			return err
		}
		state, err := loadState(c.env)
		if err != nil {
			return err
		}
		value, err := c.performCall(state, http.MethodGet, "/source-build/run-plans/"+pathID(id), nil, false, "", 30*time.Second, shapeNativeImagePlan)
		if err != nil {
			return err
		}
		plan, ok := value.(appcontracts.ImagePlan)
		if !ok || plan.ID.String() != id || plan.ResolverProvenance.Provider != "source-build" {
			return invalidResponse("source-run plan response does not match requested ID")
		}
		return c.emit(value)
	}
	state, err := loadState(c.env)
	if err != nil {
		return err
	}
	if state.CSRF == "" {
		return errors.New("session omitted CSRF token; log in again")
	}
	switch args[0] {
	case "prepare":
		positionals, flags, err := parseFlags(args[1:], "--name", "--repository", "--commit", "--expected-source-digest", "--timeout-seconds", "--idempotency-key")
		if err != nil {
			return err
		}
		key, err := sourceExplicitKey(flags)
		if err != nil {
			return err
		}
		if len(positionals) != 0 || strings.TrimSpace(flags["--name"]) == "" || !validSourceHTTPS(flags["--repository"]) || !validPinnedCommit(flags["--commit"]) {
			return usage
		}
		timeout := int64(120)
		if raw := flags["--timeout-seconds"]; raw != "" {
			timeout, err = strconv.ParseInt(raw, 10, 64)
			if err != nil || timeout < 1 || timeout > 120 {
				return errors.New("prepare timeout must be between 1 and 120 seconds")
			}
		}
		if digest := flags["--expected-source-digest"]; digest != "" && !validImageDigest(digest) {
			return errors.New("expected source digest must be sha256")
		}
		body := appcontracts.CreateSourcePrepareIntentInput{AppName: flags["--name"], Repository: flags["--repository"], Commit: flags["--commit"], ExpectedContentDigest: flags["--expected-source-digest"], TimeoutSeconds: timeout, IdempotencyKey: key}
		return c.sourceBuildPost(state, "/source-build/prepare", body, key, 30*time.Second, shapeSourceBuildIntent, func(v any) bool {
			result, ok := v.(appcontracts.SourceBuildPublicIntent)
			return ok && result.Stage == appcontracts.SourceBuildPrepare && result.State == "pending"
		})
	case "build-confirm":
		positionals, flags, err := parseFlags(args[1:], "--source-revision", "--source-digest", "--service", "--repository", "--disk-bytes", "--timeout-seconds", "--idempotency-key")
		if err != nil {
			return err
		}
		key, err := sourceExplicitKey(flags)
		if err != nil {
			return err
		}
		if len(positionals) != 1 || !validImageDigest(flags["--source-digest"]) || !appcontracts.ValidPublicSourceBuildServiceName(flags["--service"]) || flags["--repository"] == "" {
			return usage
		}
		prepareID, err := requireID(positionals[0], "prepare intent ID")
		if err != nil {
			return err
		}
		revisionID, err := requireID(flags["--source-revision"], "prepared source revision ID")
		if err != nil {
			return err
		}
		disk, diskErr := strconv.ParseInt(flags["--disk-bytes"], 10, 64)
		seconds, timeErr := strconv.ParseInt(flags["--timeout-seconds"], 10, 64)
		if diskErr != nil || disk <= 0 || timeErr != nil || seconds < 1 || seconds > 3600 {
			return errors.New("build requires positive --disk-bytes and --timeout-seconds between 1 and 3600")
		}
		body := appcontracts.SourceBuildPublicApprovalInput{PrepareIntentID: domain.ID(prepareID), SourceRevisionID: domain.ID(revisionID), SourceDigest: flags["--source-digest"], ServiceName: flags["--service"], ContextPath: ".", DockerfilePath: "Dockerfile", TargetRepository: flags["--repository"], Resources: appcontracts.SourceBuildResourcesFact{CPUMillis: appcontracts.SourceBuildPublicCPUMillis, MemoryBytes: appcontracts.SourceBuildPublicMemoryBytes, DiskBytes: disk, TimeoutSeconds: seconds, ConcurrencySlot: 1, PIDs: 0}, IdempotencyKey: key}
		return c.sourceBuildPost(state, "/source-build/approve", body, key, 30*time.Second, shapeSourceBuildIntent, func(v any) bool {
			result, ok := v.(appcontracts.SourceBuildPublicIntent)
			return ok && result.Stage == appcontracts.SourceBuildBuild && result.State == "pending" && result.PrepareIntentID == body.PrepareIntentID && result.SourceRevisionID == body.SourceRevisionID && result.SourceDigest == body.SourceDigest
		})
	case "run-plan":
		positionals, flags, err := parseFlags(args[1:], "--artifact", "--port", "--idempotency-key")
		if err != nil {
			return err
		}
		key, err := sourceExplicitKey(flags)
		if err != nil {
			return err
		}
		if len(positionals) != 1 {
			return usage
		}
		buildID, err := requireID(positionals[0], "build intent ID")
		if err != nil {
			return err
		}
		artifactID, err := requireID(flags["--artifact"], "built artifact ID")
		if err != nil {
			return err
		}
		port, err := strconv.Atoi(flags["--port"])
		if err != nil || port < 1 || port > 65535 {
			return errors.New("run plan requires --port between 1 and 65535")
		}
		body := appcontracts.SourceRunPlanInput{BuildIntentID: domain.ID(buildID), ArtifactID: domain.ID(artifactID), Port: port, IdempotencyKey: key}
		return c.sourceBuildPost(state, "/source-build/run-plans", body, key, 11*time.Minute, shapeNativeImagePlan, func(v any) bool {
			plan, ok := v.(appcontracts.ImagePlan)
			return ok && plan.Status == appcontracts.ImagePlanStatusPlanned && plan.ResolverProvenance.Provider == "source-build" && plan.ResolverProvenance.EvidenceRef == artifactID && plan.CanonicalInput.Port == port
		})
	case "run-confirm":
		positionals, flags, err := parseFlags(args[1:], "--digest", "--idempotency-key")
		if err != nil {
			return err
		}
		key, err := sourceExplicitKey(flags)
		if err != nil {
			return err
		}
		if len(positionals) != 1 || !validImageDigest(flags["--digest"]) {
			return usage
		}
		id, err := requireID(positionals[0], "source-run plan ID")
		if err != nil {
			return err
		}
		body := appcontracts.ConfirmImagePlanInput{PlanID: domain.ID(id), PlanDigest: flags["--digest"], IdempotencyKey: key}
		return c.sourceBuildPost(state, "/source-build/run-plans/"+pathID(id)+"/confirm", body, key, 30*time.Second, shapeNativeImageConfirm, func(v any) bool {
			result, ok := v.(appcontracts.ConfirmImagePlanResult)
			return ok && result.PlanID == body.PlanID && result.PlanDigest == body.PlanDigest && result.Status == "pending"
		})
	}
	return usage
}

func sourceExplicitKey(flags map[string]string) (string, error) {
	key := flags["--idempotency-key"]
	if key == "" || key != strings.TrimSpace(key) || len(key) > 256 {
		return "", errors.New("an explicit --idempotency-key of at most 256 characters is required")
	}
	return key, nil
}
func validPinnedCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			if ch < 'a' || ch > 'f' {
				return false
			}
		}
	}
	return true
}
func validSourceHTTPS(value string) bool {
	u, err := url.Parse(value)
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimRight(u.Hostname(), "."))
	return u.Scheme == "https" && host != "" && host != "localhost" && !strings.HasSuffix(host, ".local") && !strings.HasSuffix(host, ".internal") && net.ParseIP(host) == nil && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}
func (c *cli) sourceBuildPost(state sessionState, path string, body any, key string, timeout time.Duration, shape responseShape, matches func(any) bool) error {
	value, err := c.performCall(state, http.MethodPost, path, body, true, key, timeout, shape)
	if err == nil && !matches(value) {
		err = invalidResponse("source-build response identity or phase differs from the requested command")
	}
	if err != nil {
		var apiErr apiError
		if errors.As(err, &apiErr) && apiErr.status == http.StatusConflict {
			apiErr.Message += "; request was not confirmed; inspect the original intent or plan and only retry with the exact same body and --idempotency-key; do not submit a new key"
			return apiErr
		}
		if errors.As(err, &apiErr) && (apiErr.network || apiErr.contract || apiErr.status >= 500) {
			apiErr.Message += "; outcome is unknown; query the original intent or plan and retry this command with the same --idempotency-key; do not submit a new key"
			return apiErr
		}
		return err
	}
	return c.emit(value)
}

func (c *cli) imageLifecycleCommand(args []string) error {
	usage := errors.New("usage: acornfox image stop|start|restart DEPLOYMENT_ID --idempotency-key KEY | lifecycle-operation OP_ID")
	if args[0] == "lifecycle-operation" {
		if len(args) != 2 {
			return usage
		}
		id, err := requireID(args[1], "lifecycle operation ID")
		if err != nil {
			return err
		}
		state, err := loadState(c.env)
		if err != nil {
			return err
		}
		value, err := c.performCall(state, http.MethodGet, "/image-lifecycle-operations/"+pathID(id), nil, false, "", 30*time.Second, shapeNativeImageLifecycle)
		if err != nil {
			return err
		}
		actual, ok := value.(appcontracts.ImageLifecycleOperation)
		if !ok || actual.OperationID.String() != id {
			return invalidResponse("lifecycle response does not match requested operation")
		}
		if actual.State == "unknown" && !c.json {
			fmt.Fprintln(c.err, "Lifecycle outcome is unknown; retry the original action with the same --idempotency-key and query this operation for recovery; do not submit a new command key.")
		}
		return c.emit(value)
	}
	positionals, flags, err := parseFlags(args[1:], "--idempotency-key")
	if err != nil {
		return err
	}
	key := strings.TrimSpace(flags["--idempotency-key"])
	if len(positionals) != 1 || key == "" || len(key) > 256 {
		return usage
	}
	id, err := requireID(positionals[0], "deployment ID")
	if err != nil {
		return err
	}
	state, err := loadState(c.env)
	if err != nil {
		return err
	}
	if state.CSRF == "" {
		return errors.New("session omitted CSRF token; log in again")
	}
	input := appcontracts.ImageLifecycleCommandInput{Action: appcontracts.ImageLifecycleAction(args[0]), IdempotencyKey: key}
	value, err := c.performCall(state, http.MethodPost, "/image-deployments/"+pathID(id)+"/lifecycle", input, true, key, 30*time.Second, shapeNativeImageLifecycle)
	if err == nil {
		actual, ok := value.(appcontracts.ImageLifecycleOperation)
		if !ok || actual.DeploymentID.String() != id || actual.Action != input.Action || actual.State != "pending" || actual.Result != nil {
			err = invalidResponse("lifecycle response does not match the accepted pending deployment/action command")
		}
	}
	if err != nil {
		var apiErr apiError
		if errors.As(err, &apiErr) && (apiErr.network || apiErr.contract || apiErr.status >= 500) {
			apiErr.Message += "; lifecycle outcome is unknown; retry this command with the same --idempotency-key"
			return apiErr
		}
		return err
	}
	return c.emit(value)
}

func (c *cli) domainCommand(args []string) error {
	usage := errors.New("usage: acornfox domain bind|remove DEPLOYMENT_ID --hostname HOST --idempotency-key KEY | get DEPLOYMENT_ID | operation OP_ID")
	if len(args) == 0 {
		return usage
	}
	if args[0] == "operation" {
		if len(args) != 2 {
			return usage
		}
		id, err := requireID(args[1], "domain operation ID")
		if err != nil {
			return err
		}
		state, err := loadState(c.env)
		if err != nil {
			return err
		}
		value, err := c.performCall(state, http.MethodGet, "/image-domain-operations/"+pathID(id), nil, false, "", 30*time.Second, shapeNativeImageDomainOperation)
		if err != nil {
			return err
		}
		actual, ok := value.(appcontracts.ImagePublicAccessOperation)
		if !ok || actual.OperationID.String() != id {
			return invalidResponse("domain operation response does not match requested ID")
		}
		if actual.State == "unknown" && !c.json {
			fmt.Fprintln(c.err, "Local route outcome is unknown; retry the original action, hostname and deployment with the same --idempotency-key. Do not submit a new key.")
		}
		return c.emit(value)
	}
	if args[0] == "get" {
		if len(args) != 2 {
			return usage
		}
		id, err := requireID(args[1], "deployment ID")
		if err != nil {
			return err
		}
		state, err := loadState(c.env)
		if err != nil {
			return err
		}
		value, err := c.performCall(state, http.MethodGet, "/image-deployments/"+pathID(id)+"/domain", nil, false, "", 30*time.Second, shapeNativeImageDomainCurrent)
		if err != nil {
			return err
		}
		actual, ok := value.(appcontracts.ImagePublicAccessCurrent)
		if !ok || actual.Operation.DeploymentID.String() != id {
			return invalidResponse("domain state response does not match requested deployment")
		}
		if !c.json {
			fmt.Fprintln(c.err, "Local route state is not a DNS, certificate or external HTTPS readiness check.")
			if actual.Availability == "degraded" {
				fmt.Fprintln(c.err, "This hostname is retained, but the current deployment or route is unavailable or unverified.")
			}
		}
		return c.emit(value)
	}
	if args[0] != "bind" && args[0] != "remove" {
		return usage
	}
	positionals, flags, err := parseFlags(args[1:], "--hostname", "--idempotency-key")
	if err != nil {
		return err
	}
	host, key := flags["--hostname"], strings.TrimSpace(flags["--idempotency-key"])
	if len(positionals) != 1 || appcontracts.ValidateImagePublicHostname(host) != nil || key == "" || len(key) > 256 {
		return usage
	}
	id, err := requireID(positionals[0], "deployment ID")
	if err != nil {
		return err
	}
	state, err := loadState(c.env)
	if err != nil {
		return err
	}
	if state.CSRF == "" {
		return errors.New("session omitted CSRF token; log in again")
	}
	action := appcontracts.ImagePublicAccessEnsure
	if args[0] == "remove" {
		action = appcontracts.ImagePublicAccessRemove
	}
	input := appcontracts.ImagePublicAccessCommandInput{Hostname: host, Action: action, IdempotencyKey: key}
	value, err := c.performCall(state, http.MethodPost, "/image-deployments/"+pathID(id)+"/domain-commands", input, true, key, 30*time.Second, shapeNativeImageDomainOperation)
	if err == nil {
		actual, ok := value.(appcontracts.ImagePublicAccessOperation)
		if !ok || actual.DeploymentID.String() != id || actual.Hostname != host || actual.Action != action || actual.State != "pending" || actual.Result != nil {
			err = invalidResponse("domain command response differs from accepted deployment, hostname or action")
		}
	}
	if err != nil {
		var apiErr apiError
		if errors.As(err, &apiErr) && (apiErr.network || apiErr.contract || apiErr.status == http.StatusConflict || apiErr.status >= 500) {
			apiErr.Message += "; route outcome may be unknown; query the operation and retry only the same deployment, action, hostname and --idempotency-key; do not create a new key"
			return apiErr
		}
		return err
	}
	if !c.json {
		fmt.Fprintln(c.err, "Domain command accepted; the local route, DNS and HTTPS are not yet confirmed. Query domain operation for the actual result.")
	}
	return c.emit(value)
}
