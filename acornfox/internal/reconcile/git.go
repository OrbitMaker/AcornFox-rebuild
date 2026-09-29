package reconcile

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/acornfox/acornfox/internal/state"
)

// gitCloneTimeout bounds a server-side git clone (contract: 5 minutes).
const gitCloneTimeout = 5 * time.Minute

// gitMaxTarBytes caps the tar.gz produced from a clone so a hostile or huge
// repository cannot exhaust the disk. It matches the upload cap (200 MB).
const gitMaxTarBytes = 200 << 20

// commitHashPattern matches a full 40-hex commit hash. Such refs cannot be
// passed to `git clone --branch`, so they are checked out after a shallow
// clone of the default branch (contract).
var commitHashPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Git runs the git operations the reconciler needs. It is injectable so tests
// can supply a fake without the git binary. Clone must place a working tree at
// dst; Checkout switches an existing clone to ref (used for commit hashes).
type Git interface {
	// Clone performs a shallow clone of url into dst. When ref is non-empty and
	// not a commit hash it is passed as --branch. GIT_TERMINAL_PROMPT=0 must be
	// set so authentication never blocks. combinedOutput carries stderr/stdout
	// for diagnosis.
	Clone(ctx context.Context, url, ref, dst string) (combinedOutput string, err error)
	// Checkout switches the clone at dir to ref (a commit hash). It is only
	// called after a successful Clone with an empty branch.
	Checkout(ctx context.Context, dir, ref string) (combinedOutput string, err error)
}

// binaryGit is the default Git backed by the system git binary.
type binaryGit struct{}

// DefaultGit returns a Git that shells out to the git binary.
func DefaultGit() Git { return binaryGit{} }

func (binaryGit) Clone(ctx context.Context, url, ref, dst string) (string, error) {
	args := []string{"clone", "--depth", "1"}
	if ref != "" && !commitHashPattern.MatchString(ref) {
		args = append(args, "--branch", ref)
	}
	args = append(args, "--", url, dst)
	return runGit(ctx, "", args...)
}

func (binaryGit) Checkout(ctx context.Context, dir, ref string) (string, error) {
	// A shallow clone may not contain the target commit; fetch it first.
	if out, err := runGit(ctx, dir, "fetch", "--depth", "1", "origin", ref); err != nil {
		return out, err
	}
	return runGit(ctx, dir, "checkout", "--detach", ref)
}

// runGit executes git in dir (or the current dir when empty) with terminal
// prompts disabled and returns the combined output.
func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "GCM_INTERACTIVE=never")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// gitBinaryMissing reports whether err indicates the git binary is absent.
func gitBinaryMissing(err error) bool {
	return errors.Is(err, exec.ErrNotFound)
}

// Classification patterns for clone/checkout failures.
var (
	// The remote asked for credentials: the repository is private, or the
	// platform refuses anonymous HTTPS clone (observed on Gitee in 2026-09).
	gitAuthRequiredPattern = regexp.MustCompile(`(?i)(could not read username|terminal prompts disabled|authentication required)`)
	gitRepoNotFoundPattern = regexp.MustCompile(`(?i)(repository not found|could not read from remote repository|does not exist|authentication failed|invalid credentials|access denied|403|remote: not found)`)
	gitRefNotFoundPattern  = regexp.MustCompile(`(?i)(remote branch .* not found|couldn't find remote ref|reference is not a tree|pathspec .* did not match|unknown revision|did not match any)`)
	gitTimeoutPattern      = regexp.MustCompile(`(?i)(timed out|timeout|connection timed out|operation too slow|failed to connect|could not resolve host)`)
)

// buildGitTarball clones the git source of d into <UploadDir>/<id>-src, packs
// it as <UploadDir>/<id>.tar.gz, removes the source tree, and returns the
// tarball path. On a user-visible failure it returns a stage=source diagnosis
// (diag non-nil); on a transient/internal problem it returns a plain error.
func (r *Reconciler) buildGitTarball(ctx context.Context, d *state.Deployment) (tarball string, diag *state.Diagnosis, err error) {
	url, ref := splitGitRef(d.SourceRef)
	if url == "" {
		return "", &state.Diagnosis{
			Stage: "source", Code: "clone_failed",
			Message: "Git 地址为空",
			Hint:    "请提供有效的 https Git 仓库地址",
		}, nil
	}

	git := r.cfg.Git
	if git == nil {
		git = DefaultGit()
	}

	srcDir := filepath.Join(r.cfg.UploadDir, d.ID+"-src")
	_ = os.RemoveAll(srcDir)
	defer os.RemoveAll(srcDir)

	cctx, cancel := context.WithTimeout(ctx, gitCloneTimeout)
	defer cancel()

	out, cerr := git.Clone(cctx, url, ref, srcDir)
	if cerr != nil {
		return "", classifyGitClone(cctx, cerr, out), nil
	}
	// A full commit hash needs an explicit checkout after the shallow clone.
	if ref != "" && commitHashPattern.MatchString(ref) {
		co, coerr := git.Checkout(cctx, srcDir, ref)
		if coerr != nil {
			return "", classifyGitCheckout(cctx, coerr, co), nil
		}
	}

	tarPath := filepath.Join(r.cfg.UploadDir, d.ID+".tar.gz")
	if perr := packDirToTarGz(srcDir, tarPath); perr != nil {
		_ = os.Remove(tarPath)
		if errors.Is(perr, errTarTooLarge) {
			return "", &state.Diagnosis{
				Stage: "source", Code: "clone_failed",
				Message: "仓库内容超过 200 MB 上限",
				Hint:    "请精简仓库或改用 acornfox deploy 上传本地目录",
			}, nil
		}
		return "", nil, fmt.Errorf("pack git clone: %w", perr)
	}
	return tarPath, nil, nil
}

// classifyGitClone maps a clone error and its output to a stage=source diagnosis.
func classifyGitClone(ctx context.Context, err error, output string) *state.Diagnosis {
	if gitBinaryMissing(err) {
		return &state.Diagnosis{
			Stage: "source", Code: "git_missing",
			Message: "服务器上未安装 git",
			Hint:    "请在服务器上安装 git 后重试",
		}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || gitTimeoutPattern.MatchString(output) {
		return &state.Diagnosis{
			Stage: "source", Code: "clone_timeout",
			Message: "克隆仓库超时",
			Hint:    "国内服务器访问 GitHub 常超时，可改用 CNB 等国内平台上的仓库，或在本地项目目录直接执行 acornfox deploy 上传",
		}
	}
	if gitRefNotFoundPattern.MatchString(output) {
		return &state.Diagnosis{
			Stage: "source", Code: "ref_not_found",
			Message: "找不到指定的分支或提交：\n" + trimGitOutput(output),
			Hint:    "检查 --ref 指定的分支名或提交哈希是否存在",
		}
	}
	if gitAuthRequiredPattern.MatchString(output) {
		return &state.Diagnosis{
			Stage: "source", Code: "auth_required",
			Message: "该仓库要求登录才能克隆（私有仓库，或平台不允许匿名克隆，例如 Gitee）",
			Hint:    "把代码下载到本地后在项目目录执行 acornfox deploy 上传；私有仓库支持计划在首发之后提供",
		}
	}
	if gitRepoNotFoundPattern.MatchString(output) {
		return &state.Diagnosis{
			Stage: "source", Code: "repo_not_found",
			Message: "找不到仓库或无权访问：\n" + trimGitOutput(output),
			Hint:    "检查仓库地址是否正确，且仓库是公开的",
		}
	}
	return &state.Diagnosis{
		Stage: "source", Code: "clone_failed",
		Message: "克隆仓库失败：\n" + trimGitOutput(output),
		Hint:    "检查 Git 地址与网络后重试",
	}
}

// classifyGitCheckout maps a checkout error (commit hash case) to a diagnosis.
func classifyGitCheckout(ctx context.Context, err error, output string) *state.Diagnosis {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || gitTimeoutPattern.MatchString(output) {
		return &state.Diagnosis{
			Stage: "source", Code: "clone_timeout",
			Message: "拉取指定提交超时",
			Hint:    "国内服务器访问 GitHub 常超时，可改用 Gitee/CNB 镜像，或直接 acornfox deploy 上传本地目录",
		}
	}
	return &state.Diagnosis{
		Stage: "source", Code: "ref_not_found",
		Message: "找不到指定的提交：\n" + trimGitOutput(output),
		Hint:    "检查 --ref 指定的提交哈希是否存在",
	}
}

// trimGitOutput keeps the tail of git output for a diagnosis message.
func trimGitOutput(s string) string {
	s = strings.TrimSpace(s)
	lines := strings.Split(s, "\n")
	const maxLines = 12
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.Join(lines, "\n")
}

// splitGitRef splits "<url>#<ref>" into its parts; ref may be empty.
func splitGitRef(sourceRef string) (url, ref string) {
	if i := strings.LastIndex(sourceRef, "#"); i >= 0 {
		return sourceRef[:i], sourceRef[i+1:]
	}
	return sourceRef, ""
}

// errTarTooLarge signals the packed clone exceeded the size cap.
var errTarTooLarge = errors.New("reconcile: git clone tarball exceeds size cap")

// packDirToTarGz writes a gzip-compressed tar of root (excluding .git/) to
// dst. Regular files, directories and symlinks are stored; the output is
// capped at gitMaxTarBytes.
func packDirToTarGz(root, dst string) error {
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer out.Close()

	counter := &countingWriter{w: out, limit: gitMaxTarBytes}
	gz := gzip.NewWriter(counter)
	tw := tar.NewWriter(gz)

	root = filepath.Clean(root)
	sep := string(os.PathSeparator)
	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		// Always exclude the .git directory and its contents.
		if info.IsDir() && rel == ".git" {
			return filepath.SkipDir
		}
		if rel == ".git" || strings.HasPrefix(rel, ".git"+sep) {
			return nil
		}

		name := filepath.ToSlash(rel)
		var link string
		if info.Mode()&os.ModeSymlink != 0 {
			link, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}
		hdr, herr := tar.FileInfoHeader(info, link)
		if herr != nil {
			return herr
		}
		hdr.Name = name
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			f, oerr := os.Open(path)
			if oerr != nil {
				return oerr
			}
			_, cerr := io.Copy(tw, f)
			f.Close()
			if cerr != nil {
				return cerr
			}
		}
		return nil
	})
	if walkErr != nil {
		_ = tw.Close()
		_ = gz.Close()
		return walkErr
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if counter.overflow {
		return errTarTooLarge
	}
	return nil
}

// countingWriter enforces a byte cap on the compressed output.
type countingWriter struct {
	w        io.Writer
	limit    int64
	written  int64
	overflow bool
}

func (c *countingWriter) Write(p []byte) (int, error) {
	if c.overflow {
		return 0, errTarTooLarge
	}
	c.written += int64(len(p))
	if c.written > c.limit {
		c.overflow = true
		return 0, errTarTooLarge
	}
	return c.w.Write(p)
}
