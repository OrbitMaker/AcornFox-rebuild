package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/moby/moby/client"
)

const (
	// DefaultRequestTimeout is the fallback bounded deadline for engine operations.
	DefaultRequestTimeout = 10 * time.Second
)

// Config configures the EngineClient adapter.
// Explicit local Unix domain socket configuration only; no FromEnv, no remote host.
type Config struct {
	SocketPath     string
	RequestTimeout time.Duration
}

// EngineClient defines the narrow read-only boundary for Docker Engine operations.
type EngineClient interface {
	Ping(ctx context.Context) (EngineHealth, error)
	InspectEngine(ctx context.Context) (EngineInfo, error)
	InspectContainer(ctx context.Context, containerID string) (ContainerFacts, error)
	InspectImage(ctx context.Context, imageRef string) (ImageFacts, error)
	InspectNetwork(ctx context.Context, networkID string) (NetworkFacts, error)
	InspectVolume(ctx context.Context, volumeName string) (VolumeFacts, error)
	Close() error
}

// Client implements EngineClient using the official Docker Go SDK (github.com/moby/moby/client).
type Client struct {
	socketPath string
	sdkClient  *client.Client
}

// ValidateSocketPath verifies that the socket path is an explicit, absolute local path.
// It rejects TCP, HTTP, remote schemes, empty strings, and control characters.
func ValidateSocketPath(socketPath string) error {
	trimmed := strings.TrimSpace(socketPath)
	if trimmed == "" {
		return fmt.Errorf("%w: socket path must not be empty", ErrInvalidConfig)
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "tcp://") || strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return fmt.Errorf("%w: TCP and remote HTTP endpoints are forbidden; explicit local Unix socket required", ErrInvalidConfig)
	}
	if strings.HasPrefix(lower, "unix://") {
		trimmed = strings.TrimPrefix(trimmed, "unix://")
	}
	if !strings.HasPrefix(trimmed, "/") {
		return fmt.Errorf("%w: socket path must be an absolute path starting with '/'", ErrInvalidConfig)
	}
	if strings.ContainsAny(trimmed, "\r\n\t") {
		return fmt.Errorf("%w: socket path contains invalid control characters", ErrInvalidConfig)
	}
	return nil
}

// NewClient constructs an EngineClient for the specified configuration using the official SDK.
// It explicitly configures the Unix socket endpoint and timeout; no environment variables are read.
func NewClient(cfg Config) (*Client, error) {
	if err := ValidateSocketPath(cfg.SocketPath); err != nil {
		return nil, err
	}
	socketPath := strings.TrimSpace(cfg.SocketPath)
	if strings.HasPrefix(socketPath, "unix://") {
		socketPath = strings.TrimPrefix(socketPath, "unix://")
	}

	timeout := cfg.RequestTimeout
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}

	// Use official SDK constructor with explicit host and timeout options.
	// client.WithHost explicitly configures the host without reading DOCKER_HOST.
	// API version negotiation is enabled by default in client.New.
	sdk, err := client.New(
		client.WithHost("unix://"+socketPath),
		client.WithTimeout(timeout),
	)
	if err != nil {
		return nil, mapSDKError(err)
	}

	return &Client{
		socketPath: socketPath,
		sdkClient:  sdk,
	}, nil
}

// Close closes the underlying SDK client transport.
func (c *Client) Close() error {
	if c.sdkClient != nil {
		return c.sdkClient.Close()
	}
	return nil
}

// Ping checks engine responsiveness via the official SDK Ping method.
func (c *Client) Ping(ctx context.Context) (EngineHealth, error) {
	now := time.Now().UTC()
	if c.sdkClient == nil {
		return EngineHealth{Available: false, ObservedAt: now}, ErrUnavailable
	}

	_, err := c.sdkClient.Ping(ctx, client.PingOptions{})
	if err != nil {
		return EngineHealth{Available: false, ObservedAt: now}, mapSDKError(err)
	}

	return EngineHealth{
		Available:  true,
		Message:    "OK",
		ObservedAt: now,
	}, nil
}

// InspectEngine gathers system-wide facts using SDK ServerVersion and Info methods.
func (c *Client) InspectEngine(ctx context.Context) (EngineInfo, error) {
	now := time.Now().UTC()
	if c.sdkClient == nil {
		return EngineInfo{ObservedAt: now}, ErrUnavailable
	}

	vResp, err := c.sdkClient.ServerVersion(ctx, client.ServerVersionOptions{})
	if err != nil {
		return EngineInfo{ObservedAt: now}, mapSDKError(err)
	}

	iResp, err := c.sdkClient.Info(ctx, client.InfoOptions{})
	if err != nil {
		return EngineInfo{ObservedAt: now}, mapSDKError(err)
	}

	osName := iResp.Info.OperatingSystem
	if osName == "" {
		osName = vResp.Os
	}
	arch := iResp.Info.Architecture
	if arch == "" {
		arch = vResp.Arch
	}

	return EngineInfo{
		ServerVersion:     vResp.Version,
		APIVersion:        vResp.APIVersion,
		MinAPIVersion:     vResp.MinAPIVersion,
		OperatingSystem:   osName,
		Architecture:      arch,
		KernelVersion:     iResp.Info.KernelVersion,
		CPUs:              iResp.Info.NCPU,
		MemoryBytes:       iResp.Info.MemTotal,
		Containers:        iResp.Info.Containers,
		ContainersRunning: iResp.Info.ContainersRunning,
		ContainersPaused:  iResp.Info.ContainersPaused,
		ContainersStopped: iResp.Info.ContainersStopped,
		Images:            iResp.Info.Images,
		ObservedAt:        now,
	}, nil
}

// InspectContainer inspects a container using SDK ContainerInspect and validates identity.
func (c *Client) InspectContainer(ctx context.Context, idOrName string) (ContainerFacts, error) {
	isHex, err := ValidateContainerIdentifier(idOrName)
	if err != nil {
		return ContainerFacts{}, err
	}
	if c.sdkClient == nil {
		return ContainerFacts{}, ErrUnavailable
	}

	res, err := c.sdkClient.ContainerInspect(ctx, idOrName, client.ContainerInspectOptions{})
	if err != nil {
		return ContainerFacts{}, mapSDKError(err)
	}

	if err := MatchContainerIdentity(idOrName, isHex, &res.Container); err != nil {
		return ContainerFacts{}, err
	}

	return projectContainerFacts(&res.Container), nil
}

// InspectImage inspects an image using SDK ImageInspect and validates identity.
func (c *Client) InspectImage(ctx context.Context, imageRef string) (ImageFacts, error) {
	parsed, err := ParseImageReference(imageRef)
	if err != nil {
		return ImageFacts{}, err
	}
	if c.sdkClient == nil {
		return ImageFacts{}, ErrUnavailable
	}

	res, err := c.sdkClient.ImageInspect(ctx, imageRef)
	if err != nil {
		return ImageFacts{}, mapSDKError(err)
	}

	if err := MatchImageIdentity(imageRef, parsed, &res.InspectResponse); err != nil {
		return ImageFacts{}, err
	}

	return projectImageFacts(&res.InspectResponse), nil
}

// InspectNetwork inspects a network using SDK NetworkInspect and validates identity.
func (c *Client) InspectNetwork(ctx context.Context, networkID string) (NetworkFacts, error) {
	isHex, err := ValidateNetworkIdentifier(networkID)
	if err != nil {
		return NetworkFacts{}, err
	}
	if c.sdkClient == nil {
		return NetworkFacts{}, ErrUnavailable
	}

	res, err := c.sdkClient.NetworkInspect(ctx, networkID, client.NetworkInspectOptions{})
	if err != nil {
		return NetworkFacts{}, mapSDKError(err)
	}

	if err := MatchNetworkIdentity(networkID, isHex, &res.Network); err != nil {
		return NetworkFacts{}, err
	}

	return projectNetworkFacts(&res.Network), nil
}

// InspectVolume inspects a volume using SDK VolumeInspect and validates identity.
func (c *Client) InspectVolume(ctx context.Context, volumeName string) (VolumeFacts, error) {
	if err := ValidateVolumeName(volumeName); err != nil {
		return VolumeFacts{}, err
	}
	if c.sdkClient == nil {
		return VolumeFacts{}, ErrUnavailable
	}

	res, err := c.sdkClient.VolumeInspect(ctx, volumeName, client.VolumeInspectOptions{})
	if err != nil {
		return VolumeFacts{}, mapSDKError(err)
	}

	if err := MatchVolumeIdentity(volumeName, &res.Volume); err != nil {
		return VolumeFacts{}, err
	}

	return projectVolumeFacts(&res.Volume), nil
}
