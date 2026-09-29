package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type staticCoreHandler struct {
	webRoot string
	root    *os.Root
}

func newStaticCoreHandler(webRoot, dataDir string) (*staticCoreHandler, error) {
	if webRoot == "" {
		return nil, nil
	}
	cleanWeb := filepath.Clean(webRoot)
	if !filepath.IsAbs(cleanWeb) {
		return nil, errors.New("web root must be an absolute path")
	}
	if cleanWeb == "/" {
		return nil, errors.New("web root must not be the filesystem root")
	}

	info, err := os.Lstat(cleanWeb)
	if err != nil {
		return nil, fmt.Errorf("inspect web root %s: %w", cleanWeb, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("web root %s is not a directory", cleanWeb)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("web root %s must not be a symlink", cleanWeb)
	}

	realWeb, err := filepath.EvalSymlinks(cleanWeb)
	if err != nil {
		return nil, fmt.Errorf("eval symlinks on web root %s: %w", cleanWeb, err)
	}
	if realWeb == "/" {
		return nil, errors.New("resolved web root must not be the filesystem root")
	}

	cleanData := filepath.Clean(dataDir)
	realData, err := filepath.EvalSymlinks(cleanData)
	if err != nil {
		realData = cleanData
	}

	isContainedOrEqual := func(base, target string) bool {
		if base == target {
			return true
		}
		rel, err := filepath.Rel(base, target)
		return err == nil && !strings.HasPrefix(rel, "..") && rel != "."
	}

	// Validate containment against both lexical and resolved real paths
	if isContainedOrEqual(cleanWeb, cleanData) || isContainedOrEqual(realWeb, realData) {
		return nil, errors.New("web root must not contain the data directory")
	}
	if isContainedOrEqual(cleanData, cleanWeb) || isContainedOrEqual(realData, realWeb) {
		return nil, errors.New("web root must not reside inside the data directory")
	}

	root, err := os.OpenRoot(cleanWeb)
	if err != nil {
		return nil, fmt.Errorf("open web root %s: %w", cleanWeb, err)
	}

	return &staticCoreHandler{
		webRoot: cleanWeb,
		root:    root,
	}, nil
}

func (h *staticCoreHandler) Close() error {
	if h != nil && h.root != nil {
		return h.root.Close()
	}
	return nil
}

func (h *staticCoreHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Never serve static content for API or healthcheck routes
	if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
		http.NotFound(w, r)
		return
	}

	cleanPath := path.Clean(r.URL.Path)

	// Reject any path containing dot-segments (dotfiles)
	segments := strings.Split(strings.Trim(cleanPath, "/"), "/")
	for _, seg := range segments {
		if strings.HasPrefix(seg, ".") {
			http.NotFound(w, r)
			return
		}
	}

	// 1. Root and explicit core entry
	if cleanPath == "/" || cleanPath == "/core.html" {
		h.serveCoreEntry(w, r)
		return
	}

	// 2. Static asset subtree: strictly files inside /assets/
	if strings.HasPrefix(cleanPath, "/assets/") {
		ext := strings.ToLower(filepath.Ext(cleanPath))
		if ext == ".db" || ext == ".lock" || ext == ".log" || ext == ".token" || ext == ".key" || ext == ".sql" || ext == ".env" {
			http.NotFound(w, r)
			return
		}

		relPath := strings.TrimPrefix(cleanPath, "/")
		info, err := h.root.Lstat(relPath)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			http.NotFound(w, r)
			return
		}

		f, err := h.root.Open(relPath)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()

		openedInfo, err := f.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			http.NotFound(w, r)
			return
		}

		http.ServeContent(w, r, filepath.Base(relPath), openedInfo.ModTime(), f)
		return
	}

	// 3. SPA client-side routes (paths without extension and not /assets/ or /api/)
	if filepath.Ext(cleanPath) == "" {
		h.serveCoreEntry(w, r)
		return
	}

	// All other files (arbitrary files, index.html, non-asset files) are denied
	http.NotFound(w, r)
}

func (h *staticCoreHandler) serveCoreEntry(w http.ResponseWriter, r *http.Request) {
	const coreFile = "core.html"
	info, err := h.root.Lstat(coreFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		http.NotFound(w, r)
		return
	}

	f, err := h.root.Open(coreFile)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	openedInfo, err := f.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		http.NotFound(w, r)
		return
	}

	http.ServeContent(w, r, "core.html", openedInfo.ModTime(), f)
}
