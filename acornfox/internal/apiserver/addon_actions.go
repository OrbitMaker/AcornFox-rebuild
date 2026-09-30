package apiserver

import (
	"net/http"

	"github.com/acornfox/acornfox/internal/state"
)

func (s *server) addonAction(w http.ResponseWriter, r *http.Request, fn http.HandlerFunc) {
	app := r.PathValue("app")
	if !state.ValidAppName(app) {
		writeError(w, http.StatusBadRequest, "invalid_app", "应用名不合法")
		return
	}
	if err := s.withApp(r.Context(), app, func() error {
		fn(w, r)
		return nil
	}); err != nil {
		writeError(w, http.StatusServiceUnavailable, "operation_cancelled", "操作尚未执行，请稍后重试")
	}
}

func (s *server) addAddon(w http.ResponseWriter, r *http.Request) {
	s.addonAction(w, r, s.addAddonLocked)
}

func (s *server) removeAddon(w http.ResponseWriter, r *http.Request) {
	s.addonAction(w, r, s.removeAddonLocked)
}
