package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (c *cli) fixCandidate(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: acornfox fix-candidate create|list|get|match|publish")
	}
	switch args[0] {
	case "list":
		if len(args) != 2 {
			return errors.New("usage: acornfox fix-candidate list APP_ID")
		}
		app, err := requireID(args[1], "application ID")
		if err != nil {
			return err
		}
		return c.callCommand(http.MethodGet, "/apps/"+pathID(app)+"/fix-candidates", nil, false, "", 15*time.Second, shapeFixCandidateList)
	case "get":
		if len(args) != 3 {
			return errors.New("usage: acornfox fix-candidate get APP_ID CANDIDATE_ID")
		}
		app, candidate, err := fixCandidateIDs(args[1], args[2])
		if err != nil {
			return err
		}
		return c.callCommand(http.MethodGet, "/apps/"+pathID(app)+"/fix-candidates/"+pathID(candidate), nil, false, "", 15*time.Second, shapeFixCandidate)
	case "match":
		if len(args) != 4 {
			return errors.New("usage: acornfox fix-candidate match APP_ID CANDIDATE_ID SOURCE_REVISION_ID")
		}
		app, candidate, err := fixCandidateIDs(args[1], args[2])
		if err != nil {
			return err
		}
		source, err := requireID(args[3], "source revision ID")
		if err != nil {
			return err
		}
		return c.callCommand(http.MethodPost, "/apps/"+pathID(app)+"/fix-candidates/"+pathID(candidate)+"/source-match", map[string]string{"source_revision_id": source}, true, "", 30*time.Second, shapeFixCandidate)
	case "publish":
		if len(args) < 3 {
			return errors.New("usage: acornfox fix-candidate publish APP_ID CANDIDATE_ID [--idempotency-key]")
		}
		app, candidate, err := fixCandidateIDs(args[1], args[2])
		if err != nil {
			return err
		}
		positionals, values, err := parseFlags(args[3:], "--idempotency-key")
		if err != nil || len(positionals) != 0 {
			return errors.New("usage: acornfox fix-candidate publish APP_ID CANDIDATE_ID [--idempotency-key]")
		}
		key, err := idempotencyKey(values)
		if err != nil {
			return err
		}
		return c.callCommand(http.MethodPost, "/apps/"+pathID(app)+"/fix-candidates/"+pathID(candidate)+"/publish", nil, true, key, 10*time.Minute, shapeCommand)
	case "create":
		return c.createFixCandidate(args[1:])
	default:
		return errors.New("usage: acornfox fix-candidate create|list|get|match|publish")
	}
}

func (c *cli) createFixCandidate(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: acornfox fix-candidate create APP_ID BASE_SOURCE_ID --paths PATHS --diff FILE --port PORT [--idempotency-key]")
	}
	app, err := requireID(args[0], "application ID")
	if err != nil {
		return err
	}
	base, err := requireID(args[1], "base source revision ID")
	if err != nil {
		return err
	}
	positionals, values, err := parseFlags(args[2:], "--paths", "--diff", "--port", "--idempotency-key")
	if err != nil || len(positionals) != 0 || values["--paths"] == "" || values["--diff"] == "" || values["--port"] == "" {
		return errors.New("usage: acornfox fix-candidate create APP_ID BASE_SOURCE_ID --paths PATHS --diff FILE --port PORT [--idempotency-key]")
	}
	paths := strings.Split(values["--paths"], ",")
	if len(paths) < 1 || len(paths) > 32 {
		return errors.New("candidate paths must contain 1 to 32 comma-separated paths")
	}
	seen := map[string]bool{}
	for index := range paths {
		paths[index] = strings.TrimSpace(paths[index])
		if paths[index] == "" || seen[paths[index]] {
			return errors.New("candidate paths must be nonempty and unique")
		}
		seen[paths[index]] = true
	}
	diffPath, err := filepath.Abs(values["--diff"])
	if err != nil {
		return errors.New("candidate diff file is invalid")
	}
	info, err := os.Lstat(diffPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 128<<10 {
		return errors.New("candidate diff file must be a regular file of at most 128 KiB")
	}
	diff, err := os.ReadFile(diffPath)
	if err != nil || int64(len(diff)) != info.Size() {
		return errors.New("candidate diff file could not be read")
	}
	port, err := strconv.Atoi(values["--port"])
	if err != nil || port < 1 || port > 65535 {
		return errors.New("candidate port must be between 1 and 65535")
	}
	key, err := idempotencyKey(values)
	if err != nil {
		return err
	}
	body := map[string]any{"base_source_revision_id": base, "paths": paths, "unified_diff": string(diff), "container_port": port}
	return c.callCommand(http.MethodPost, "/apps/"+pathID(app)+"/fix-candidates", body, true, key, 15*time.Second, shapeFixCandidate)
}

func fixCandidateIDs(rawApp, rawCandidate string) (string, string, error) {
	app, err := requireID(rawApp, "application ID")
	if err != nil {
		return "", "", err
	}
	candidate, err := requireID(rawCandidate, "candidate ID")
	if err != nil {
		return "", "", err
	}
	if !strings.HasPrefix(candidate, "candidate_") {
		return "", "", errors.New("candidate ID is invalid")
	}
	return app, candidate, nil
}
