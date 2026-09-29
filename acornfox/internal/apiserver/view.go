package apiserver

import (
	"fmt"

	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

// deploymentView is the deployment as returned by the API. It is a distinct
// type from state.Deployment so the wire shape is explicit and stable; the
// fields mirror the store row directly (no secrets live on a deployment).
func deploymentView(d state.Deployment) state.Deployment { return d }

// envKeyView describes one environment variable without ever exposing a secret
// value. Non-secret values are returned; secret values are omitted entirely.
type envKeyView struct {
	Key    string `json:"key"`
	Secret bool   `json:"secret"`
	Value  string `json:"value,omitempty"` // empty and omitted when Secret is true
}

// makeEnvView converts store env vars into the redacted wire form. A secret's
// value is never copied into the result, so it cannot leak through JSON.
func makeEnvView(vars []state.EnvVar) []envKeyView {
	out := make([]envKeyView, 0, len(vars))
	for _, v := range vars {
		item := envKeyView{Key: v.Key, Secret: v.Secret}
		if !v.Secret {
			item.Value = v.Value
		}
		out = append(out, item)
	}
	return out
}

// observedContainer is the best-effort observed state of an app's live
// container. When the runner is unavailable the whole app view carries
// Observed=nil and ObservedState="unavailable".
type observedContainer struct {
	Name         string `json:"name"`
	State        string `json:"state"`
	Running      bool   `json:"running"`
	RestartCount int    `json:"restart_count"`
	HostPort     int    `json:"host_port"`
	StartedAt    string `json:"started_at,omitempty"`
}

func makeObserved(c runner.ContainerInfo) observedContainer {
	return observedContainer{
		Name:         c.Name,
		State:        c.State,
		Running:      c.Running,
		RestartCount: c.RestartCount,
		HostPort:     c.HostPort,
		StartedAt:    c.StartedAt,
	}
}

// appView is the app list/detail wire form.
type appView struct {
	Name              string             `json:"name"`
	Desired           string             `json:"desired"`
	Port              int                `json:"port"`
	HealthPath        string             `json:"health_path"`
	PublicPort        int                `json:"public_port"`
	CurrentDeployment string             `json:"current_deployment"`
	MemoryMB          int                `json:"memory_mb"`
	CPUMilli          int                `json:"cpu_milli"`
	URL               string             `json:"url"`
	ObservedState     string             `json:"observed_state"` // running | stopped | missing | unavailable
	Observed          *observedContainer `json:"observed,omitempty"`
	Live              *state.Deployment  `json:"live,omitempty"`
	Env               []envKeyView       `json:"env,omitempty"`
	Volumes           []state.Volume     `json:"volumes,omitempty"`
	Domains           []state.Domain     `json:"domains,omitempty"`
}

// appURL builds the public URL for an app: http://<public-host>:<PublicPort>.
func appURL(publicHost string, publicPort int) string {
	if publicHost == "" || publicPort == 0 {
		return ""
	}
	return fmt.Sprintf("http://%s:%d", publicHost, publicPort)
}
