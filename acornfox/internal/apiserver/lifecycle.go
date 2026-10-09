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

// originKind is the source a deployment's image originally came from: its own
// source kind, or the inherited origin when it already re-used an image.
func originKind(d state.Deployment) string {
	if d.OriginKind != "" {
		return d.OriginKind
	}
	return d.SourceKind
}

// redeployLive recreates the current image while retaining request-key dedup.
// An app that has never gone live has nothing to recreate. reason is a
// state.Reason* value recorded for display.
func (s *server) redeployLive(ctx context.Context, app, key, reason string) (string, error) {
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
		BasedOnSeq: live.Seq, OriginKind: originKind(live), Reason: reason,
	})
	if err != nil {
		return "", err
	}
	s.kicker.Kick(app)
	return dep.ID, nil
}
