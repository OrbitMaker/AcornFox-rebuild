package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/open-card/open-card/internal/desktopupdate"
)

// Supported canonical platforms for host release tooling.
var supportedPlatforms = map[string]struct{}{
	"darwin/arm64": {},
	"linux/amd64":  {},
	"linux/arm64":  {},
}

func isSupportedPlatform(osName, archName string) bool {
	key := osName + "/" + archName
	_, ok := supportedPlatforms[key]
	return ok
}

type ReleaseSpec struct {
	SchemaVersion      int                            `json:"schema_version"`
	Product            string                         `json:"product"`
	Kind               string                         `json:"kind"`
	OS                 string                         `json:"os"`
	Architecture       string                         `json:"arch"`
	Version            string                         `json:"version"`
	ControllerProtocol int                            `json:"controller_protocol"`
	InstanceProtocol   int                            `json:"instance_protocol"`
	Launcher           string                         `json:"launcher"`
	Controller         string                         `json:"controller,omitempty"`
	Backend            BackendSpec                    `json:"backend"`
	Files              []desktopupdate.HostBundleFile `json:"files,omitempty"`
}

type BackendSpec struct {
	Mode         string `json:"mode"`
	Binding      string `json:"binding,omitempty"` // convenience alias for unchanged mode
	FromBinding  string `json:"from_binding,omitempty"`
	ToBinding    string `json:"to_binding,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	HelperSHA256 string `json:"helper_sha256,omitempty"`
	APIProtocol  int    `json:"api_protocol,omitempty"`
}

func parseReleaseSpec(data []byte) (*ReleaseSpec, error) {
	if len(data) == 0 || len(data) > 2<<20 {
		return nil, errors.New("invalid release spec size")
	}

	allowedTopFields := map[string]struct{}{
		"schema_version":      {},
		"product":             {},
		"kind":                {},
		"os":                  {},
		"arch":                {},
		"version":             {},
		"controller_protocol": {},
		"instance_protocol":   {},
		"launcher":            {},
		"controller":          {},
		"backend":             {},
		"files":               {},
	}

	if err := checkStrictJSONKeys(data, allowedTopFields); err != nil {
		return nil, fmt.Errorf("invalid release spec keys: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s ReleaseSpec
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("failed to decode release spec: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected trailing data in release spec")
	}

	// Apply defaults
	if s.SchemaVersion == 0 {
		s.SchemaVersion = 1
	}
	if s.Product == "" {
		s.Product = "acornfox"
	}
	if s.Kind == "" {
		s.Kind = "host-update-v1"
	}
	if s.ControllerProtocol == 0 {
		s.ControllerProtocol = 1
	}
	if s.InstanceProtocol == 0 {
		s.InstanceProtocol = 1
	}
	if s.Controller == "" {
		s.Controller = "controller/acornfox-host-update"
		if s.OS == "windows" {
			s.Controller += ".exe"
		}
	}
	if s.Backend.APIProtocol == 0 {
		s.Backend.APIProtocol = 1
	}
	if s.Backend.Architecture == "" {
		s.Backend.Architecture = s.Architecture
	}
	if s.Backend.Mode == "unchanged" && s.Backend.Binding != "" {
		if s.Backend.FromBinding == "" {
			s.Backend.FromBinding = s.Backend.Binding
		}
		if s.Backend.ToBinding == "" {
			s.Backend.ToBinding = s.Backend.Binding
		}
	}

	if err := s.Validate(); err != nil {
		return nil, err
	}

	return &s, nil
}

func (s *ReleaseSpec) Validate() error {
	if s.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schema_version %d (must be 1)", s.SchemaVersion)
	}
	if s.Product != "acornfox" {
		return fmt.Errorf("unsupported product %q (must be 'acornfox')", s.Product)
	}
	if s.Kind != "host-update-v1" {
		return fmt.Errorf("unsupported kind %q (must be 'host-update-v1')", s.Kind)
	}
	if !isSupportedPlatform(s.OS, s.Architecture) {
		return fmt.Errorf("unsupported platform %s/%s (supported: darwin/arm64, linux/amd64, linux/arm64)", s.OS, s.Architecture)
	}
	if _, err := desktopupdate.ParseSemver(s.Version); err != nil {
		return fmt.Errorf("invalid semver version %q: %w", s.Version, err)
	}
	if s.ControllerProtocol != 1 {
		return fmt.Errorf("controller_protocol must be 1, got %d", s.ControllerProtocol)
	}
	if s.InstanceProtocol != 1 {
		return fmt.Errorf("instance_protocol must be 1, got %d", s.InstanceProtocol)
	}
	expectedController := "controller/acornfox-host-update"
	if s.OS == "windows" {
		expectedController += ".exe"
	}
	if s.Controller != expectedController {
		return fmt.Errorf("invalid controller %q (must be %q)", s.Controller, expectedController)
	}
	if !strings.HasPrefix(s.Launcher, "launcher/") {
		return fmt.Errorf("launcher %q must start with 'launcher/'", s.Launcher)
	}
	if s.Backend.APIProtocol != 1 {
		return fmt.Errorf("backend api_protocol must be 1, got %d", s.Backend.APIProtocol)
	}
	if s.Backend.Architecture != s.Architecture {
		return fmt.Errorf("backend architecture %q does not match host architecture %q", s.Backend.Architecture, s.Architecture)
	}

	switch s.Backend.Mode {
	case "unchanged":
		if s.Backend.FromBinding == "" || s.Backend.ToBinding == "" {
			return errors.New("unchanged backend mode requires binding (or from_binding and to_binding)")
		}
		if s.Backend.FromBinding != s.Backend.ToBinding {
			return errors.New("unchanged backend mode requires from_binding == to_binding")
		}
		if s.Backend.HelperSHA256 != "" {
			return errors.New("unchanged backend mode must not specify helper_sha256")
		}
		if err := validateHexSHA256(s.Backend.FromBinding); err != nil {
			return fmt.Errorf("invalid backend binding: %w", err)
		}
	case "candidate":
		if s.Backend.FromBinding == "" || s.Backend.ToBinding == "" {
			return errors.New("candidate backend mode requires both from_binding and to_binding")
		}
		if s.Backend.FromBinding == s.Backend.ToBinding {
			return errors.New("candidate backend mode requires from_binding != to_binding")
		}
		if err := validateHexSHA256(s.Backend.FromBinding); err != nil {
			return fmt.Errorf("invalid backend from_binding: %w", err)
		}
		if err := validateHexSHA256(s.Backend.ToBinding); err != nil {
			return fmt.Errorf("invalid backend to_binding: %w", err)
		}
		if err := validateHexSHA256(s.Backend.HelperSHA256); err != nil {
			return fmt.Errorf("invalid backend helper_sha256: %w", err)
		}
	default:
		return fmt.Errorf("invalid backend mode %q (must be 'unchanged' or 'candidate')", s.Backend.Mode)
	}

	return nil
}

func (s *ReleaseSpec) ToManifest(files []desktopupdate.HostBundleFile) desktopupdate.HostBundleManifest {
	return desktopupdate.HostBundleManifest{
		SchemaVersion:      s.SchemaVersion,
		Product:            s.Product,
		Kind:               s.Kind,
		OS:                 s.OS,
		Architecture:       s.Architecture,
		Version:            s.Version,
		ControllerProtocol: s.ControllerProtocol,
		InstanceProtocol:   s.InstanceProtocol,
		Launcher:           s.Launcher,
		Controller:         s.Controller,
		Backend: desktopupdate.HostBackendPlan{
			Mode:         s.Backend.Mode,
			FromBinding:  s.Backend.FromBinding,
			ToBinding:    s.Backend.ToBinding,
			Architecture: s.Backend.Architecture,
			HelperSHA256: s.Backend.HelperSHA256,
			APIProtocol:  s.Backend.APIProtocol,
		},
		Files: files,
	}
}

func validateHexSHA256(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("sha256 must be 64 characters, got %d", len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("sha256 must be lowercase hex, got %c", c)
		}
	}
	return nil
}

func checkStrictJSONKeys(data []byte, topLevelAllowed map[string]struct{}) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return errors.New("JSON root must be an object")
	}
	return checkStrictObjectKeys(dec, topLevelAllowed)
}

func checkStrictObjectKeys(dec *json.Decoder, allowedExact map[string]struct{}) error {
	seenLower := make(map[string]string)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("expected object key string")
		}
		if allowedExact != nil {
			if _, ok := allowedExact[key]; !ok {
				return fmt.Errorf("field %q not allowed or casing mismatch", key)
			}
		}
		lower := strings.ToLower(key)
		if prev, exists := seenLower[lower]; exists {
			return fmt.Errorf("duplicate or case-conflicting key %q (conflicts with %q)", key, prev)
		}
		seenLower[lower] = key

		vTok, err := dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := vTok.(json.Delim); ok {
			switch delim {
			case '{':
				if err := checkStrictObjectKeys(dec, nil); err != nil {
					return err
				}
			case '[':
				if err := checkStrictArrayKeys(dec); err != nil {
					return err
				}
			}
		}
	}
	_, err := dec.Token()
	return err
}

func checkStrictArrayKeys(dec *json.Decoder) error {
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				if err := checkStrictObjectKeys(dec, nil); err != nil {
					return err
				}
			case '[':
				if err := checkStrictArrayKeys(dec); err != nil {
					return err
				}
			}
		}
	}
	_, err := dec.Token()
	return err
}
