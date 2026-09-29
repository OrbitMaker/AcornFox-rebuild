package runner

import (
	"encoding/json"
	"io"
	"net/http"
	"path"
	"strings"
)

// serverMaxBody bounds a single request body read on the runner side. Requests
// are small typed JSON; anything larger is rejected.
const serverMaxBody = 1 << 20

// Server exposes an API implementation over the runner's HTTP+JSON contract.
// It is meant to be served on a peer Unix socket by acornfox runner.
type Server struct {
	api       API
	uploadDir string // absolute clean directory; every BuildRequest.ContextPath must live under it
	mux       *http.ServeMux
}

// NewServer wraps an API as an http.Handler. uploadDir bounds the files a build
// request may reference; it must be an absolute clean path.
func NewServer(api API, uploadDir string) *Server {
	s := &Server{
		api:       api,
		uploadDir: path.Clean(uploadDir),
		mux:       http.NewServeMux(),
	}
	s.routes()
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("POST "+PathPing, s.handlePing)
	s.mux.HandleFunc("GET "+PathPing, s.handlePing)
	s.mux.HandleFunc("POST "+PathBuild, s.handleBuild)
	s.mux.HandleFunc("POST "+PathImageInspect, s.handleImageInspect)
	s.mux.HandleFunc("POST "+PathImageList, s.handleImageList)
	s.mux.HandleFunc("POST "+PathImageRemove, s.handleImageRemove)
	s.mux.HandleFunc("POST "+PathContainerEnsure, s.handleContainerEnsure)
	s.mux.HandleFunc("POST "+PathContainerList, s.handleContainerList)
	s.mux.HandleFunc("POST "+PathContainerStop, s.handleContainerStop)
	s.mux.HandleFunc("POST "+PathContainerStart, s.handleContainerStart)
	s.mux.HandleFunc("POST "+PathContainerRemove, s.handleContainerRemove)
	s.mux.HandleFunc("POST "+PathContainerLogs, s.handleContainerLogs)
	s.mux.HandleFunc("POST "+PathContainerDiff, s.handleContainerDiff)
	s.mux.HandleFunc("POST "+PathVolumeEnsure, s.handleVolumeEnsure)
	s.mux.HandleFunc("POST "+PathVolumeList, s.handleVolumeList)
}

// ---- response helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, ErrorResponse{Code: code, Message: msg})
}

// writeAPIError maps an API error to the correct HTTP status and error code.
func writeAPIError(w http.ResponseWriter, err error) {
	if err == ErrNotFound {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	writeError(w, http.StatusInternalServerError, "docker_error", err.Error())
}

// decode reads and unmarshals a bounded JSON request body.
func decode(r *http.Request, dst any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, serverMaxBody))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, dst)
}

// ---- validation helpers ----

// validAppName rejects requests with a malformed app identifier.
func validAppName(w http.ResponseWriter, app string) bool {
	if !ValidApp(app) {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid app name")
		return false
	}
	return true
}

// validContainerName ensures the name is well-formed and prefixed for the app.
func validContainerName(w http.ResponseWriter, app, name string) bool {
	if !validAppName(w, app) {
		return false
	}
	prefix := "af-" + app + "-"
	if !strings.HasPrefix(name, prefix) {
		writeError(w, http.StatusBadRequest, "invalid_request", "container name must start with "+prefix)
		return false
	}
	id := strings.TrimPrefix(name, prefix)
	if !ValidDeploymentID(id) {
		writeError(w, http.StatusBadRequest, "invalid_request", "container name must end with a 12-hex deployment id")
		return false
	}
	return true
}

// validVolumeName ensures the volume name is prefixed for the app.
func validVolumeName(w http.ResponseWriter, app, name string) bool {
	if !validAppName(w, app) {
		return false
	}
	if !strings.HasPrefix(name, VolumePrefix(app)) {
		writeError(w, http.StatusBadRequest, "invalid_request", "volume name must start with "+VolumePrefix(app))
		return false
	}
	return true
}

// isAbsClean reports whether p is an absolute, cleaned path.
func isAbsClean(p string) bool {
	return path.IsAbs(p) && path.Clean(p) == p
}

// underUploadDir reports whether p resolves under the configured upload dir.
func (s *Server) underUploadDir(p string) bool {
	clean := path.Clean(p)
	return clean == s.uploadDir || strings.HasPrefix(clean, s.uploadDir+"/")
}

// ---- handlers ----

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	resp, err := s.api.Ping(r.Context())
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleBuild(w http.ResponseWriter, r *http.Request) {
	var req BuildRequest
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	if !validAppName(w, req.App) {
		return
	}
	if !ValidDeploymentID(req.DeploymentID) {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid deployment id")
		return
	}
	if !isAbsClean(req.ContextPath) {
		writeError(w, http.StatusBadRequest, "invalid_request", "context_path must be absolute and clean")
		return
	}
	if !s.underUploadDir(req.ContextPath) {
		writeError(w, http.StatusBadRequest, "refused", "context_path must be under the upload directory")
		return
	}
	resp, err := s.api.Build(r.Context(), req)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleImageInspect(w http.ResponseWriter, r *http.Request) {
	var ref ImageRef
	if err := decode(r, &ref); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	if !validAppName(w, ref.App) {
		return
	}
	if ref.Ref == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "ref is required")
		return
	}
	info, err := s.api.ImageInspect(r.Context(), ref.App, ref.Ref)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleImageList(w http.ResponseWriter, r *http.Request) {
	var ref AppRef
	if err := decode(r, &ref); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	if ref.App != "" && !validAppName(w, ref.App) {
		return
	}
	images, err := s.api.ListImages(r.Context(), ref.App)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ImageListResponse{Images: images})
}

func (s *Server) handleImageRemove(w http.ResponseWriter, r *http.Request) {
	var ref ImageRef
	if err := decode(r, &ref); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	if !validAppName(w, ref.App) {
		return
	}
	if ref.Ref == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "ref is required")
		return
	}
	if err := s.api.RemoveImage(r.Context(), ref.App, ref.Ref); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, OK{OK: true})
}

func (s *Server) handleContainerEnsure(w http.ResponseWriter, r *http.Request) {
	var req EnsureContainerRequest
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	if !validAppName(w, req.App) {
		return
	}
	if !ValidDeploymentID(req.DeploymentID) {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid deployment id")
		return
	}
	if req.Image == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "image is required")
		return
	}
	if req.Port < 1 || req.Port > 65535 {
		writeError(w, http.StatusBadRequest, "invalid_request", "port must be in 1..65535")
		return
	}
	if req.MemoryMB < 64 {
		writeError(w, http.StatusBadRequest, "invalid_request", "memory_mb must be >= 64")
		return
	}
	if req.CPUMilli < 100 {
		writeError(w, http.StatusBadRequest, "invalid_request", "cpu_milli must be >= 100")
		return
	}
	prefix := VolumePrefix(req.App)
	for _, m := range req.Mounts {
		if !strings.HasPrefix(m.Volume, prefix) {
			writeError(w, http.StatusBadRequest, "refused", "mount volume must start with "+prefix)
			return
		}
		if !isAbsClean(m.Path) {
			writeError(w, http.StatusBadRequest, "invalid_request", "mount path must be absolute and clean")
			return
		}
	}
	info, err := s.api.EnsureContainer(r.Context(), req)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleContainerList(w http.ResponseWriter, r *http.Request) {
	var ref AppRef
	if err := decode(r, &ref); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	if ref.App != "" && !validAppName(w, ref.App) {
		return
	}
	list, err := s.api.ListContainers(r.Context(), ref.App)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ContainerListResponse{Containers: list})
}

func (s *Server) handleContainerStop(w http.ResponseWriter, r *http.Request) {
	var ref ContainerRef
	if err := decode(r, &ref); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	if !validContainerName(w, ref.App, ref.Name) {
		return
	}
	if err := s.api.StopContainer(r.Context(), ref.App, ref.Name); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, OK{OK: true})
}

func (s *Server) handleContainerStart(w http.ResponseWriter, r *http.Request) {
	var ref ContainerRef
	if err := decode(r, &ref); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	if !validContainerName(w, ref.App, ref.Name) {
		return
	}
	info, err := s.api.StartContainer(r.Context(), ref.App, ref.Name)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleContainerRemove(w http.ResponseWriter, r *http.Request) {
	var ref ContainerRef
	if err := decode(r, &ref); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	if !validContainerName(w, ref.App, ref.Name) {
		return
	}
	if err := s.api.RemoveContainer(r.Context(), ref.App, ref.Name); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, OK{OK: true})
}

func (s *Server) handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	var req LogsRequest
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	if !validContainerName(w, req.App, req.Name) {
		return
	}
	lines, err := s.api.Logs(r.Context(), req.App, req.Name, req.Tail)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, LogsResponse{Lines: lines})
}

func (s *Server) handleContainerDiff(w http.ResponseWriter, r *http.Request) {
	var ref ContainerRef
	if err := decode(r, &ref); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	if !validContainerName(w, ref.App, ref.Name) {
		return
	}
	files, err := s.api.Diff(r.Context(), ref.App, ref.Name)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, DiffResponse{DatabaseFiles: files})
}

func (s *Server) handleVolumeEnsure(w http.ResponseWriter, r *http.Request) {
	var ref VolumeRef
	if err := decode(r, &ref); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	if !validVolumeName(w, ref.App, ref.Name) {
		return
	}
	if err := s.api.EnsureVolume(r.Context(), ref.App, ref.Name); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, OK{OK: true})
}

func (s *Server) handleVolumeList(w http.ResponseWriter, r *http.Request) {
	var ref AppRef
	if err := decode(r, &ref); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	if ref.App != "" && !validAppName(w, ref.App) {
		return
	}
	vols, err := s.api.ListVolumes(r.Context(), ref.App)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, VolumeListResponse{Volumes: vols})
}

// ensure Server satisfies http.Handler at compile time.
var _ http.Handler = (*Server)(nil)
