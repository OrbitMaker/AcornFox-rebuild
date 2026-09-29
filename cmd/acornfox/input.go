package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func consumeGlobalJSON(args []string) ([]string, bool, error) {
	clean := make([]string, 0, len(args))
	jsonOutput := false
	for _, arg := range args {
		if arg != "--json" {
			clean = append(clean, arg)
			continue
		}
		if jsonOutput {
			return nil, false, errors.New("--json may be specified once")
		}
		jsonOutput = true
	}
	return clean, jsonOutput, nil
}

// parseFlags accepts only explicitly-declared value flags, once each.
func parseFlags(args []string, allowed ...string) ([]string, map[string]string, error) {
	known := map[string]bool{}
	for _, name := range allowed {
		known[name] = true
	}
	positionals, values := []string{}, map[string]string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			positionals = append(positionals, arg)
			continue
		}
		if !known[arg] {
			return nil, nil, fmt.Errorf("unknown flag %q", arg)
		}
		if _, exists := values[arg]; exists {
			return nil, nil, fmt.Errorf("duplicate flag %q", arg)
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			return nil, nil, fmt.Errorf("flag %s requires a value", arg)
		}
		values[arg] = args[i+1]
		i++
	}
	return positionals, values, nil
}

func parseBooleanFlag(args []string, name string) ([]string, bool, error) {
	clean := make([]string, 0, len(args))
	present := false
	for _, arg := range args {
		if arg != name {
			clean = append(clean, arg)
			continue
		}
		if present {
			return nil, false, fmt.Errorf("duplicate flag %q", name)
		}
		present = true
	}
	return clean, present, nil
}

func requireID(value, label string) (string, error) {
	if value == "" || strings.HasPrefix(value, "-") || strings.ContainsAny(value, "/?#") {
		return "", fmt.Errorf("invalid %s", label)
	}
	return value, nil
}
func parseLimit(values map[string]string) error {
	if raw, ok := values["--limit"]; ok {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			return errors.New("limit must be between 1 and 100")
		}
	}
	if cursor, ok := values["--cursor"]; ok && cursor == "" {
		return errors.New("cursor must not be empty")
	}
	return nil
}
func parsePort(raw string) (int, error) {
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 || value > 65535 {
		return 0, errors.New("port must be between 0 and 65535")
	}
	return value, nil
}

func normalizeOrigin(raw string, allowHTTP bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && !(allowHTTP && u.Scheme == "http" && net.ParseIP(u.Hostname()).IsLoopback())) {
		return "", errors.New("server must be an HTTPS origin")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("server origin must not include a path")
	}
	return strings.TrimRight(u.String(), "/"), nil
}
func normalizePublicGit(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path == "" || u.Path == "/" {
		return "", errors.New("repository must be a public HTTPS Git URL")
	}
	return u.String(), nil
}
func requireRef(value string) (string, error) {
	if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("ref is required")
	}
	return value, nil
}

func readLines(r io.Reader, n int) (string, error) {
	values, err := readLinesN(r, n)
	if err != nil {
		return "", err
	}
	return values[0], nil
}
func readLinesN(r io.Reader, n int) ([]string, error) {
	data, err := io.ReadAll(r)
	if err != nil || !bytes.HasSuffix(data, []byte("\n")) {
		return nil, errors.New("password input must contain exactly the required newline-terminated values")
	}
	values := strings.Split(string(data[:len(data)-1]), "\n")
	if len(values) != n {
		return nil, errors.New("password input must contain exactly the required newline-terminated values")
	}
	for index := range values {
		values[index] = strings.TrimSuffix(values[index], "\r")
	}
	return values, nil
}

func readInteractiveLine(reader *bufio.Reader) (string, error) {
	value, err := reader.ReadString('\n')
	if err != nil {
		return "", errors.New("interactive password input requires a newline")
	}
	return strings.TrimSuffix(strings.TrimSuffix(value, "\n"), "\r"), nil
}
