package apiserver

import (
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
)

// errorBody is the wire form of every error response: {"error":{"code","message"}}.
type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// writeError writes a JSON error body with the given HTTP status.
func writeError(w http.ResponseWriter, status int, code, message string) {
	var body errorBody
	body.Error.Code = code
	body.Error.Message = message
	writeJSON(w, status, body)
}

// writeJSON marshals v and writes it with the given status. Marshalling errors
// are logged by falling back to a plain 500 body; they should not happen for
// the value types used here.
func writeJSON(w http.ResponseWriter, status int, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"internal","message":"响应编码失败"}}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf)
}

// ValidateListen reports whether addr is a listen address permitted in N1.
// Only loopback TCP addresses (127.0.0.1, ::1, localhost) and absolute unix
// socket paths are allowed; anything else is rejected so the unauthenticated
// N1 API is never exposed beyond the local host.
//
// Accepted forms:
//   - "127.0.0.1:18800", "localhost:18800", "[::1]:18800"
//   - "unix:/absolute/path.sock" or a bare absolute path "/absolute/path.sock"
func ValidateListen(addr string) error {
	if addr == "" {
		return &listenError{"监听地址为空"}
	}

	// Unix socket forms.
	if p, ok := strings.CutPrefix(addr, "unix:"); ok {
		return validateUnixPath(p)
	}
	if strings.HasPrefix(addr, "/") {
		return validateUnixPath(addr)
	}

	// TCP host:port form.
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return &listenError{"监听地址格式不合法，应为 host:port 或绝对路径 unix socket"}
	}
	if port == "" {
		return &listenError{"监听地址缺少端口"}
	}
	if !isLoopbackHost(host) {
		return &listenError{"N1 只允许监听 127.0.0.1、::1、localhost 或 unix socket"}
	}
	return nil
}

func validateUnixPath(p string) error {
	if p == "" || !filepath.IsAbs(p) {
		return &listenError{"unix socket 路径必须是绝对路径"}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

type listenError struct{ msg string }

func (e *listenError) Error() string { return e.msg }
