package apiserver

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/acornfox/acornfox/internal/state"
)

// deployJSONRequest is the JSON body of a source-based deploy: exactly one of
// Image or Git is set.
type deployJSONRequest struct {
	Image string `json:"image,omitempty"`
	Git   string `json:"git,omitempty"`
	Ref   string `json:"ref,omitempty"`
}

// isJSONDeploy reports whether the request carries a JSON deploy body.
func isJSONDeploy(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/json")
}

// createDeploymentJSON handles a JSON deploy body for image or git sources. It
// mirrors the tar.gz path's idempotency (Idempotency-Key and content digest)
// without touching the upload directory.
func (s *server) createDeploymentJSON(w http.ResponseWriter, r *http.Request, app string) {
	ctx := r.Context()

	var body deployJSONRequest
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "请求体不是合法 JSON")
		return
	}
	body.Image = strings.TrimSpace(body.Image)
	body.Git = strings.TrimSpace(body.Git)
	body.Ref = strings.TrimSpace(body.Ref)

	if (body.Image == "") == (body.Git == "") {
		writeError(w, http.StatusBadRequest, "invalid_source", "请恰好提供 image 或 git 之一")
		return
	}

	var (
		kind, ref, digest string
	)
	switch {
	case body.Image != "":
		if verr := validateImageRef(body.Image); verr != nil {
			writeError(w, http.StatusBadRequest, "invalid_image", verr.Error())
			return
		}
		kind = state.SourceImage
		ref = body.Image
		digest = hexDigest(body.Image)
	default:
		if verr := validateGitURL(body.Git); verr != nil {
			writeError(w, http.StatusBadRequest, "invalid_git", verr.Error())
			return
		}
		kind = state.SourceGit
		ref = body.Git + "#" + body.Ref
		digest = hexDigest(body.Git + "#" + body.Ref)
	}

	if _, _, err := s.store.EnsureApp(ctx, app); err != nil {
		s.mapStoreError(w, err)
		return
	}

	dep, created, err := s.store.CreateDeployment(ctx, state.NewDeployment{
		App:          app,
		SourceKind:   kind,
		SourceRef:    ref,
		SourceDigest: digest,
		RequestKey:   r.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		s.mapStoreError(w, err)
		return
	}
	if !created {
		writeJSON(w, http.StatusOK, deploymentView(dep))
		return
	}
	s.kicker.Kick(app)
	writeJSON(w, http.StatusAccepted, deploymentView(dep))
}

// hexDigest returns the sha256 hex of s (the deploy content digest).
func hexDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// validateImageRef checks an external image reference. It rejects a digest
// pin combined with a tag ambiguity and obviously malformed refs; it does not
// require a tag (Docker defaults to :latest).
func validateImageRef(ref string) error {
	if ref == "" {
		return errors.New("镜像引用不能为空")
	}
	if strings.ContainsAny(ref, " \t\n") {
		return errors.New("镜像引用不能包含空白字符")
	}
	// A reference may carry at most one digest and, when digested, the digest
	// must be a sha256 hex of the right length.
	if at := strings.Index(ref, "@"); at >= 0 {
		digest := ref[at+1:]
		if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
			return errors.New("镜像 digest 必须是 sha256:<64位十六进制>")
		}
		if !isHex(digest[len("sha256:"):]) {
			return errors.New("镜像 digest 必须是 sha256:<64位十六进制>")
		}
		if strings.Contains(ref[at+1:], "@") {
			return errors.New("镜像引用只能包含一个 digest")
		}
	}
	return nil
}

// validateGitURL enforces the contract: https only, no userinfo (no embedded
// credentials).
func validateGitURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("Git 地址不是合法 URL")
	}
	if u.Scheme != "https" {
		return errors.New("只允许 https:// 的 Git 地址")
	}
	if u.User != nil {
		return errors.New("Git 地址不能包含用户名或密码")
	}
	if u.Host == "" {
		return errors.New("Git 地址缺少主机名")
	}
	return nil
}

// isHex reports whether s is all lowercase/uppercase hex digits.
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
