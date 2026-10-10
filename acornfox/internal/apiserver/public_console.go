package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/acornfox/acornfox/internal/publicconsole"
)

// PublicConsole is what the trusted API needs from the public console
// (ADR-0016); *publicconsole.Manager implements it.
type PublicConsole interface {
	Status(ctx context.Context) (publicconsole.Status, error)
	StartVerify(ctx context.Context, domain string) (publicconsole.VerifyInfo, error)
	Enable(ctx context.Context, domain, verifyID string, resetPassword bool) (publicconsole.EnableResult, error)
	Disable(ctx context.Context) (bool, error)
}

func (s *server) publicConsoleUnavailable(w http.ResponseWriter) bool {
	if s.publicConsole == nil {
		writeError(w, http.StatusNotFound, "not_found", "该服务端不支持公网控制台")
		return true
	}
	return false
}

func (s *server) writePublicConsoleError(w http.ResponseWriter, err error) {
	var pe *publicconsole.Error
	if errors.As(err, &pe) {
		writeError(w, pe.Status, pe.Code, pe.Message)
		return
	}
	s.log.Error("public console", "err", err)
	writeError(w, http.StatusInternalServerError, "internal", "内部错误")
}

// publicConsoleStatus implements GET /v1/public-console.
func (s *server) publicConsoleStatus(w http.ResponseWriter, r *http.Request) {
	if s.publicConsoleUnavailable(w) {
		return
	}
	st, err := s.publicConsole.Status(r.Context())
	if err != nil {
		s.writePublicConsoleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// publicConsoleVerify implements POST /v1/public-console/verify {"domain"}.
func (s *server) publicConsoleVerify(w http.ResponseWriter, r *http.Request) {
	if s.publicConsoleUnavailable(w) {
		return
	}
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法的 JSON")
		return
	}
	info, err := s.publicConsole.StartVerify(r.Context(), req.Domain)
	if err != nil {
		s.writePublicConsoleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// publicConsoleEnable implements POST /v1/public-console/enable
// {"domain","verify_id","reset_password"}. The reply carries the password
// once; it is never stored in clear or returned again.
func (s *server) publicConsoleEnable(w http.ResponseWriter, r *http.Request) {
	if s.publicConsoleUnavailable(w) {
		return
	}
	var req struct {
		Domain        string `json:"domain"`
		VerifyID      string `json:"verify_id"`
		ResetPassword bool   `json:"reset_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法的 JSON")
		return
	}
	res, err := s.publicConsole.Enable(r.Context(), req.Domain, req.VerifyID, req.ResetPassword)
	if err != nil {
		s.writePublicConsoleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// publicConsoleDisable implements DELETE /v1/public-console.
func (s *server) publicConsoleDisable(w http.ResponseWriter, r *http.Request) {
	if s.publicConsoleUnavailable(w) {
		return
	}
	was, err := s.publicConsole.Disable(r.Context())
	if err != nil {
		s.writePublicConsoleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"disabled": true, "was_enabled": was})
}

// publicConsoleDomain returns the domain the public console uses, or "".
func (s *server) publicConsoleDomain(ctx context.Context) string {
	if s.publicConsole == nil {
		return ""
	}
	st, err := s.publicConsole.Status(ctx)
	if err != nil || !st.Enabled {
		return ""
	}
	return st.Domain
}
