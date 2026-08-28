// open-card-static-server is the fixed, platform-owned runtime embedded in M1
// static-site images. It has no shell, template, proxy, upload, or execution
// surface; the immutable binary digest is bound into every static BuildPlan.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	root := flag.String("root", "/www", "read-only static document root")
	listen := flag.String("listen", ":8080", "listen address")
	startupDelay := flag.Duration("startup-delay", 0, "bounded startup delay for recovery tests")
	healthcheck := flag.Bool("healthcheck", false, "probe the fixed local health endpoint and exit")
	stateFile := flag.String("state-file", "", "optional absolute service-state fixture path")
	stateContent := flag.String("state-content", "", "bounded content written to the service-state fixture")
	flag.Parse()
	if flag.NArg() != 0 || *listen != ":8080" || *startupDelay < 0 || *startupDelay > 9*time.Second || len(*stateContent) > 4096 {
		log.Fatal("invalid static server configuration")
	}
	if *healthcheck {
		if *startupDelay != 0 || *stateFile != "" || *stateContent != "" {
			log.Fatal("healthcheck cannot use startup delay")
		}
		client := &http.Client{Timeout: time.Second}
		response, err := client.Get("http://127.0.0.1:8080/healthz")
		if err != nil {
			log.Fatal("healthcheck failed")
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			log.Fatal("healthcheck failed")
		}
		return
	}
	if !filepath.IsAbs(*root) {
		log.Fatal("invalid static server configuration")
	}
	if (*stateFile == "") != (*stateContent == "") {
		log.Fatal("state file and content must be supplied together")
	}
	if *stateFile != "" {
		clean := filepath.Clean(*stateFile)
		if !filepath.IsAbs(clean) || !strings.HasPrefix(clean, "/var/lib/opencard/data/") || clean == "/var/lib/opencard/data" {
			log.Fatal("state file must be below the fixed service data root")
		}
		if err := os.MkdirAll(filepath.Dir(clean), 0o750); err != nil {
			log.Fatal("state directory is unavailable")
		}
		temporary, err := os.CreateTemp(filepath.Dir(clean), ".open-card-state-*")
		if err != nil {
			log.Fatal("state file is unavailable")
		}
		temporaryPath := temporary.Name()
		if err := temporary.Chmod(0o600); err == nil {
			_, err = temporary.WriteString(*stateContent)
		}
		if err == nil {
			err = temporary.Sync()
		}
		if closeErr := temporary.Close(); err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(temporaryPath, clean)
		}
		if err != nil {
			_ = os.Remove(temporaryPath)
			log.Fatal("state file could not be committed")
		}
	}
	info, err := os.Stat(*root)
	if err != nil || !info.IsDir() {
		log.Fatal("static document root is unavailable")
	}
	if *startupDelay > 0 {
		time.Sleep(*startupDelay)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok\n"))
	})
	mux.Handle("/", http.FileServer(http.Dir(*root)))
	server := &http.Server{Addr: *listen, Handler: accessLogHandler(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

type accessLogResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *accessLogResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *accessLogResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

// accessLogHandler emits a bounded structured line without paths, query
// strings, headers, cookies, or bodies. The Agent performs the same redaction
// again before persistence, but the fixed shape keeps sensitive request input
// out of the container log at its origin.
func accessLogHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder := &accessLogResponseWriter{ResponseWriter: writer}
		next.ServeHTTP(recorder, request)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		log.Printf("level=info event=http_request method=%s status=%d", safeHTTPMethod(request.Method), status)
	})
}

func safeHTTPMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return method
	default:
		return "OTHER"
	}
}
