package apiserver

import (
	"context"
	"net/http"

	"github.com/acornfox/acornfox/internal/state"
)

// appOperationLocker serializes destructive API actions with reconciliation.
// The concrete reconciler implements it; simple test kickers need not.
type appOperationLocker interface {
	WithApp(context.Context, string, func() error) error
}

func (s *server) withApp(ctx context.Context, app string, fn func() error) error {
	if locker, ok := s.kicker.(appOperationLocker); ok {
		return locker.WithApp(ctx, app, fn)
	}
	return fn()
}

type lifecycleError struct {
	status  int
	code    string
	message string
}

func (e *lifecycleError) Error() string { return e.message }

// redeployLive recreates the current image while retaining request-key dedup.
// An app that has never gone live has nothing to recreate.
func (s *server) redeployLive(ctx context.Context, app, key string) (string, error) {
	a, err := s.store.GetApp(ctx, app)
	if err != nil {
		return "", err
	}
	if a.CurrentDeployment == "" {
		return "", nil
	}
	live, err := s.store.GetDeployment(ctx, a.CurrentDeployment)
	if err != nil {
		return "", err
	}
	if live.ImageID == "" {
		return "", &lifecycleError{http.StatusConflict, "no_image", "当前版本没有可重新部署的镜像"}
	}
	dep, _, err := s.store.CreateDeployment(ctx, state.NewDeployment{
		App: app, SourceKind: state.SourceImage, SourceRef: live.ImageID,
		SourceDigest: live.ImageID, BypassDedup: true, RequestKey: key,
	})
	if err != nil {
		return "", err
	}
	s.kicker.Kick(app)
	return dep.ID, nil
}
