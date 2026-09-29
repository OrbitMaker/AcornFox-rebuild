package main

import "github.com/open-card/open-card/internal/dockermetrics"

// Legacy Agent names stay source-compatible; production behavior remains the
// reader's default inspect+stats+changes collection.
type DockerRuntimeMetrics = dockermetrics.DockerRuntimeMetrics
type DockerRuntimeMetricsReader = dockermetrics.DockerRuntimeMetricsReader
type UnixDockerRuntimeMetricsReader = dockermetrics.UnixDockerRuntimeMetricsReader

func NewUnixDockerRuntimeMetricsReader(socketPath string) (*UnixDockerRuntimeMetricsReader, error) {
	return dockermetrics.NewUnixDockerRuntimeMetricsReader(socketPath)
}
func ValidateDockerContainerIdentifier(containerID string) error {
	return dockermetrics.ValidateDockerContainerIdentifier(containerID)
}
