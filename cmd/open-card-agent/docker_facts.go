package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type DockerFacts struct {
	ServerVersion     string `json:"server_version"`
	APIVersion        string `json:"api_version"`
	OperatingSystem   string `json:"operating_system"`
	Architecture      string `json:"architecture"`
	CPUs              int    `json:"cpus"`
	MemoryBytes       int64  `json:"memory_bytes"`
	Containers        int    `json:"containers"`
	ContainersRunning int    `json:"containers_running"`
	ContainersPaused  int    `json:"containers_paused"`
	ContainersStopped int    `json:"containers_stopped"`
}

type DockerFactsReader interface {
	ReadFacts(context.Context) (DockerFacts, error)
}

// UnixDockerFactsReader uses two hard-coded read-only Docker Engine endpoints.
// The socket path is process configuration, never task input, and is not
// returned to the control plane or user workloads.
type UnixDockerFactsReader struct {
	client *http.Client
}

func NewUnixDockerFactsReader(socketPath string) (*UnixDockerFactsReader, error) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" || !strings.HasPrefix(socketPath, "/") {
		return nil, errors.New("docker socket path must be absolute")
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		DisableCompression: true,
	}
	return &UnixDockerFactsReader{client: &http.Client{Transport: transport, Timeout: 5 * time.Second}}, nil
}

func (r *UnixDockerFactsReader) ReadFacts(ctx context.Context) (DockerFacts, error) {
	if r == nil || r.client == nil {
		return DockerFacts{}, errors.New("docker facts reader is not initialized")
	}
	var version struct {
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
		OS         string `json:"Os"`
		Arch       string `json:"Arch"`
	}
	if err := r.get(ctx, "/version", &version); err != nil {
		return DockerFacts{}, err
	}
	var info struct {
		OperatingSystem   string `json:"OperatingSystem"`
		Architecture      string `json:"Architecture"`
		NCPU              int    `json:"NCPU"`
		MemTotal          int64  `json:"MemTotal"`
		Containers        int    `json:"Containers"`
		ContainersRunning int    `json:"ContainersRunning"`
		ContainersPaused  int    `json:"ContainersPaused"`
		ContainersStopped int    `json:"ContainersStopped"`
	}
	if err := r.get(ctx, "/info", &info); err != nil {
		return DockerFacts{}, err
	}
	facts := DockerFacts{
		ServerVersion: version.Version, APIVersion: version.APIVersion,
		OperatingSystem: info.OperatingSystem, Architecture: info.Architecture,
		CPUs: info.NCPU, MemoryBytes: info.MemTotal, Containers: info.Containers,
		ContainersRunning: info.ContainersRunning, ContainersPaused: info.ContainersPaused,
		ContainersStopped: info.ContainersStopped,
	}
	if facts.OperatingSystem == "" {
		facts.OperatingSystem = version.OS
	}
	if facts.Architecture == "" {
		facts.Architecture = version.Arch
	}
	if strings.TrimSpace(facts.ServerVersion) == "" || facts.CPUs <= 0 || facts.MemoryBytes <= 0 {
		return DockerFacts{}, errors.New("docker returned incomplete node facts")
	}
	return facts, nil
}

func (r *UnixDockerFactsReader) get(ctx context.Context, path string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	response, err := r.client.Do(request)
	if err != nil {
		return fmt.Errorf("read docker facts %s: %w", path, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("read docker facts %s: status %s", path, response.Status)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode docker facts %s: %w", path, err)
	}
	return nil
}
