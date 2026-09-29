package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/acornfox/acornfox/internal/hosthelper"
	"github.com/acornfox/acornfox/internal/imageexecution"
	"github.com/acornfox/acornfox/internal/localpeer"
)

type containerConfig struct {
	bindingPath      string
	workRoot         string
	imageStoreRoot   string
	taskPrefix       string
	registryBaseURL  string
	dockerSocketPath string
	socketGID        uint32
}

func parseFlags(args []string) (containerConfig, error) {
	fs := flag.NewFlagSet("acornfox-container", flag.ContinueOnError)

	var cfg containerConfig
	fs.StringVar(&cfg.bindingPath, "runtime-binding", os.Getenv("ACORNFOX_CONTAINER_BINDING"), "Path to root-protected runtime peer binding JSON (/run/acornfox/runtime-binding.json)")
	fs.StringVar(&cfg.workRoot, "work-root", os.Getenv("ACORNFOX_CONTAINER_WORK_ROOT"), "Runtime work directory for staging OCI containers")
	fs.StringVar(&cfg.imageStoreRoot, "image-store", os.Getenv("ACORNFOX_CONTAINER_IMAGE_STORE"), "Filesystem directory for immutable OCI archives")
	fs.StringVar(&cfg.taskPrefix, "task-prefix", "acornfox-", "Prefix namespace for task-owned Docker objects")
	fs.StringVar(&cfg.registryBaseURL, "registry-url", "", "Optional registry base URL override")
	fs.StringVar(&cfg.dockerSocketPath, "docker-socket", "/var/run/docker.sock", "Pinned local Docker Engine Unix socket")
	socketGID := fs.Uint64("socket-gid", 0, "Optional dedicated IPC group ID for the role socket; 0 keeps legacy mode and nonzero requires a publisher-prepared parent")

	if err := fs.Parse(args); err != nil {
		return containerConfig{}, err
	}
	if *socketGID > math.MaxUint32 {
		return containerConfig{}, errors.New("socket-gid exceeds uint32 range")
	}
	cfg.socketGID = uint32(*socketGID)

	cfg.bindingPath = strings.TrimSpace(cfg.bindingPath)
	if cfg.bindingPath == "" {
		return containerConfig{}, errors.New("runtime binding path (-runtime-binding or ACORNFOX_CONTAINER_BINDING) is required")
	}
	cfg.bindingPath = filepath.Clean(cfg.bindingPath)

	cfg.workRoot = strings.TrimSpace(cfg.workRoot)
	if cfg.workRoot == "" {
		return containerConfig{}, errors.New("work root (-work-root or ACORNFOX_CONTAINER_WORK_ROOT) is required")
	}
	cfg.workRoot = filepath.Clean(cfg.workRoot)

	cfg.imageStoreRoot = strings.TrimSpace(cfg.imageStoreRoot)
	if cfg.imageStoreRoot == "" {
		return containerConfig{}, errors.New("image store root (-image-store or ACORNFOX_CONTAINER_IMAGE_STORE) is required")
	}
	cfg.imageStoreRoot = filepath.Clean(cfg.imageStoreRoot)

	cfg.taskPrefix = strings.TrimSpace(cfg.taskPrefix)
	if cfg.taskPrefix == "" {
		cfg.taskPrefix = "acornfox-"
	}
	cfg.dockerSocketPath = strings.TrimSpace(cfg.dockerSocketPath)
	if !filepath.IsAbs(cfg.dockerSocketPath) || cfg.dockerSocketPath == "/" || strings.Contains(cfg.dockerSocketPath, "..") {
		return containerConfig{}, errors.New("docker socket path must be absolute and constrained")
	}

	return cfg, nil
}

func run(args []string) error {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}

	currentUID := uint32(os.Getuid())
	currentPID := int32(os.Getpid())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigChan)

	// Keep the same process and PID alive, waiting for root-protected binding file
	log.Printf("container role started (pid=%d, uid=%d), awaiting protected binding file %s", currentPID, currentUID, cfg.bindingPath)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var binding *localpeer.RuntimePeerBinding
	for binding == nil {
		select {
		case sig := <-sigChan:
			log.Printf("container role received signal %v while awaiting binding, exiting cleanly", sig)
			return nil
		case <-ticker.C:
			b, err := localpeer.LoadProtectedRuntimePeerBinding(cfg.bindingPath)
			if err != nil {
				log.Printf("check protected binding: %v", err)
				continue
			}
			if b == nil {
				continue
			}

			// Verify self identity matches bound container tuple
			if currentUID != b.ContainerUID {
				log.Printf("self UID %d does not match bound container UID %d; waiting", currentUID, b.ContainerUID)
				continue
			}
			if currentPID != b.ContainerPID {
				log.Printf("self PID %d does not match bound container PID %d; waiting", currentPID, b.ContainerPID)
				continue
			}
			if err := localpeer.VerifyProcessIdentity(currentPID, b.ContainerUID, b.ContainerExeSHA, b.ContainerStartTime); err != nil {
				log.Printf("self process verification failed against binding: %v; waiting", err)
				continue
			}

			helperClient := hosthelper.NewClient(hosthelper.DefaultHelperSocketPath, 5*time.Second)

			// Verify counterpart Core process is alive and matches binding tuple via helper
			if err := imageexecution.VerifyCounterpartPeerViaHelper(context.Background(), helperClient, "core", b.CorePID, b.CoreUID, b); err != nil {
				log.Printf("counterpart Core process %d verification failed: %v; waiting", b.CorePID, err)
				continue
			}

			binding = b
		}
	}

	ticker.Stop()
	log.Printf("bound to installation %s (core_pid=%d, container_pid=%d)", binding.InstallationID, binding.CorePID, binding.ContainerPID)

	helperClient := hosthelper.NewClient(hosthelper.DefaultHelperSocketPath, 5*time.Second)

	// Now proceed with provider and server initialization
	if err := os.MkdirAll(cfg.workRoot, 0o700); err != nil {
		return fmt.Errorf("create work root directory: %w", err)
	}
	if err := os.MkdirAll(cfg.imageStoreRoot, 0o700); err != nil {
		return fmt.Errorf("create image store directory: %w", err)
	}
	if err := prepareContainerSocketParent(binding.ContainerSocket, cfg.socketGID); err != nil {
		return err
	}

	runtime, err := imageexecution.NewContainerRuntime(imageexecution.RuntimeConfig{
		TaskPrefix:          cfg.taskPrefix,
		WorkRoot:            cfg.workRoot,
		ImageStoreRoot:      cfg.imageStoreRoot,
		RegistryBaseURL:     cfg.registryBaseURL,
		DockerSocketPath:    cfg.dockerSocketPath,
		AuthoritySocketPath: binding.AuthoritySocket,
		ExpectedCoreUID:     binding.CoreUID,
		ExpectedCorePID:     binding.CorePID,
		CorePeerValidator: func(pid int32, uid uint32) error {
			return imageexecution.VerifyCounterpartPeerViaHelper(context.Background(), helperClient, "core", pid, uid, binding)
		},
	})
	if err != nil {
		return fmt.Errorf("init container runtime: %w", err)
	}

	server, err := imageexecution.NewContainerServer(imageexecution.ContainerServerConfig{
		EnableLifecycle: true,
		Runtime:         runtime,
		SocketPath:      binding.ContainerSocket,
		SocketGID:       cfg.socketGID,
		ExpectedCoreUID: binding.CoreUID,
		ExpectedCorePID: binding.CorePID,
		PeerValidator: func(pid int32, uid uint32) error {
			return imageexecution.VerifyCounterpartPeerViaHelper(context.Background(), helperClient, "core", pid, uid, binding)
		},
	})
	if err != nil {
		return fmt.Errorf("start container server: %w", err)
	}
	defer server.Close()

	sig := <-sigChan
	log.Printf("container role received signal %v, shutting down", sig)
	return nil
}

func prepareContainerSocketParent(socketPath string, socketGID uint32) error {
	if socketGID != 0 {
		// The accepted listener verifies the publisher's existing role:IPC
		// setgid parent; this entry must not create a 0755 substitute.
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return fmt.Errorf("create socket parent directory: %w", err)
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatalf("acornfox-container error: %v", err)
	}
}
