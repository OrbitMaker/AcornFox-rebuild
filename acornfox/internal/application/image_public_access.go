package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
)

const GatewayProjectionLockPath = "/run/acornfox/trust/gateway-projection.lock"

// GatewayProjectionLock serializes the short Core Begin transaction with the
// Gateway's complete snapshot/check/Caddy CAS. It is a root-published inode,
// not a SQLite transaction or a role-created path.
type GatewayProjectionLock struct {
	Path             string
	ExpectedOwnerUID uint32
	IPCGID           uint32
}

func (l GatewayProjectionLock) WithLock(ctx context.Context, fn func(context.Context) error) error {
	if ctx == nil || fn == nil || l.IPCGID == 0 || !filepath.IsAbs(l.Path) || filepath.Clean(l.Path) != l.Path ||
		(l.ExpectedOwnerUID == 0 && l.Path != GatewayProjectionLockPath) {
		return errors.New("protected Gateway projection lock is not configured")
	}
	parent := filepath.Dir(l.Path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o750 {
		return errors.New("Gateway projection lock parent is not protected")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != l.ExpectedOwnerUID || owner.Gid != l.IPCGID {
		return errors.New("Gateway projection lock parent owner differs")
	}
	if l.ExpectedOwnerUID == 0 {
		for dir := filepath.Dir(parent); ; dir = filepath.Dir(dir) {
			ancestor, err := os.Lstat(dir)
			if err != nil || !ancestor.IsDir() || ancestor.Mode()&os.ModeSymlink != 0 || ancestor.Mode().Perm()&0o022 != 0 {
				return errors.New("Gateway projection lock ancestry is unsafe")
			}
			stat, ok := ancestor.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 {
				return errors.New("Gateway projection lock ancestry is not root-owned")
			}
			if dir == "/" {
				break
			}
		}
	}
	file, err := os.OpenFile(l.Path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o660 {
		return errors.New("Gateway projection lock is not regular 0660")
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != l.ExpectedOwnerUID || stat.Gid != l.IPCGID || stat.Nlink != 1 {
		return errors.New("Gateway projection lock inode identity differs")
	}
	lockCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return err
		}
		select {
		case <-lockCtx.Done():
			return lockCtx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	current, err := os.Lstat(l.Path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		return errors.New("Gateway projection lock path changed")
	}
	return fn(lockCtx)
}

// Begin is the only Core-facing command entry to wire into the future HTTP
// handler. Its lock closes the Store.Begin versus Gateway PATCH race without
// holding a SQLite transaction across network I/O.
type ImagePublicAccessCommands struct {
	Store appcontracts.ImagePublicAccessStore
	Lock  GatewayProjectionLock
}

func (s ImagePublicAccessCommands) Begin(ctx context.Context, admin domain.ID, in appcontracts.ImagePublicAccessRequest) (appcontracts.ImagePublicAccessCommand, error) {
	var command appcontracts.ImagePublicAccessCommand
	if s.Store == nil {
		return command, errors.New("durable image public access Store required")
	}
	err := s.Lock.WithLock(ctx, func(locked context.Context) error {
		var err error
		command, err = s.Store.BeginImagePublicAccess(locked, admin, in)
		return err
	})
	return command, err
}

type ImagePublicAccessGatewayClient interface {
	ExecuteImagePublicAccess(context.Context, appcontracts.ImagePublicAccessCommand, appcontracts.ImagePublicAccessAuthority) (appcontracts.ImagePublicAccessObservation, error)
}

// ImagePublicAccessWorker is the finite image.public_access task consumer.
// Existing task leases supply renewal/fencing; no second queue is introduced.
type ImagePublicAccessWorker struct {
	Store         appcontracts.ImagePublicAccessStore
	Tasks         appcontracts.TaskRepository
	Gateway       ImagePublicAccessGatewayClient
	WorkerID      string
	LeaseDuration time.Duration
	PollInterval  time.Duration
	Clock         func() time.Time
	done          chan struct{}
	once          sync.Once
}

func (w *ImagePublicAccessWorker) PollOnce(ctx context.Context) (bool, error) {
	if w.Store == nil || w.Tasks == nil || w.Gateway == nil || w.WorkerID == "" {
		return false, errors.New("public access worker dependencies are incomplete")
	}
	if w.Clock == nil {
		w.Clock = time.Now
	}
	lease := w.LeaseDuration
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	task, ok, err := w.Tasks.ClaimTask(ctx, appcontracts.ClaimTaskRequest{Kinds: []string{appcontracts.ImagePublicAccessTaskKind}, Owner: w.WorkerID, Now: w.Clock().UTC(), LeasePolicy: appcontracts.LeasePolicy{Duration: lease, MaxAttempts: 3}})
	if err != nil || !ok {
		return false, err
	}
	var payload struct {
		Kind    string                                `json:"kind"`
		Binding appcontracts.ImagePublicAccessCommand `json:"binding"`
	}
	if json.Unmarshal(task.Payload, &payload) != nil || payload.Kind != appcontracts.ImagePublicAccessTaskKind || payload.Binding.TaskID != task.ID || payload.Binding.OperationID != task.OperationID {
		return true, errors.New("claimed public access task payload is inconsistent")
	}
	b := payload.Binding
	authority := appcontracts.ImagePublicAccessAuthority{BeginImageExecutionInput: appcontracts.BeginImageExecutionInput{TaskID: task.ID, OperationID: task.OperationID, Owner: w.WorkerID, CoreGeneration: task.CoreGeneration, LeaseGeneration: task.LeaseGeneration, Now: w.Clock().UTC()}, ApprovalID: b.ApprovalID, DeploymentID: b.DeploymentID, EndpointVersion: b.EndpointVersion, ContainerID: b.ContainerID, Action: b.Action}
	approved, err := w.Store.AuthorizeImagePublicAccess(ctx, authority)
	if err != nil {
		return true, err
	}
	execCtx, finish := startTaskExecutionLease(ctx, task, w.Tasks, w.WorkerID, lease, w.Clock)
	result, execErr := w.Gateway.ExecuteImagePublicAccess(execCtx, approved, authority)
	if err := finish(); err != nil {
		return true, err
	}
	if execErr != nil {
		if errors.Is(execErr, appcontracts.ErrLeaseLost) {
			return true, execErr
		}
		if errors.Is(execErr, appcontracts.ErrOutcomeUnknown) || contracts.IsProviderOutcomeUnknown(execErr) || errors.Is(execErr, context.Canceled) || errors.Is(execErr, context.DeadlineExceeded) {
			return true, w.Store.RecordImagePublicAccessUnknown(ctx, authority, execErr.Error())
		}
		return true, w.Store.FailImagePublicAccess(ctx, authority, execErr.Error())
	}
	if !result.RouteApplied {
		return true, w.Store.RecordImagePublicAccessUnknown(ctx, authority, "Gateway returned no verified route observation")
	}
	if err := w.Store.CommitImagePublicAccess(ctx, authority, result); err != nil {
		return true, fmt.Errorf("commit public route observation: %w", err)
	}
	return true, nil
}

func (w *ImagePublicAccessWorker) Start(ctx context.Context) <-chan struct{} {
	w.once.Do(func() {
		w.done = make(chan struct{})
		go func() {
			defer close(w.done)
			interval := w.PollInterval
			if interval <= 0 {
				interval = 500 * time.Millisecond
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if _, err := w.PollOnce(ctx); err != nil && ctx.Err() == nil {
						log.Printf("image public access worker: %v", err)
					}
				}
			}
		}()
	})
	return w.done
}
