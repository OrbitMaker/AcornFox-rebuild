package desktopupdate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	MinFreeDiskSpaceBytes  = 1 << 30 // 1 GiB safety margin
	DefaultDownloadTimeout = 10 * time.Minute
	MaxRedirects           = 10
	StagePayloadFileName   = "payload.bin"
	StageTempFileName      = "download.tmp"
)

var (
	ErrInsufficientDiskSpace = errors.New("desktopupdate: insufficient disk space")
	ErrInvalidParentDir      = errors.New("desktopupdate: invalid staging parent directory")
	ErrDownloadFailed        = errors.New("desktopupdate: download failed")
	ErrDigestMismatch        = errors.New("desktopupdate: artifact sha256 mismatch")
	ErrSizeMismatch          = errors.New("desktopupdate: artifact size mismatch")
	ErrTargetConflict        = errors.New("desktopupdate: staging target already exists")
)

// StagedReceipt represents the verified staged payload and its index metadata.
type StagedReceipt struct {
	Channel        string    `json:"channel"`
	Sequence       uint64    `json:"sequence"`
	Version        string    `json:"version"`
	ArtifactPath   string    `json:"artifact_path"`
	SHA256         string    `json:"sha256"`
	Size           int64     `json:"size"`
	BackendBinding string    `json:"backend_binding,omitempty"`
	StagedAt       time.Time `json:"staged_at"`
}

// DownloadStagingOptions controls execution of StageVerifiedUpdate.
type DownloadStagingOptions struct {
	hostStageName     string
	hostStageIdentity string
	IndexOptions      CheckUpdateOptions
	ParentDir         string
	HTTPClient        *http.Client // Optional: only its Transport is used; opts.Timeout manages requests, Jar is forced nil, env proxy is preserved
	Timeout           time.Duration
	// Test hook overrides
	DiskSpaceCheck func(path string) (uint64, error)
	SyncHook       func(dirPath string) error
}

// StageVerifiedUpdate executes verification, disk space probe, HTTPS stream download, and atomic staging.
func StageVerifiedUpdate(ctx context.Context, envelopeBytes []byte, opts DownloadStagingOptions) (*StagedReceipt, *CandidateResult, error) {
	if ctx == nil {
		return nil, nil, fmt.Errorf("%w: nil context", ErrDownloadFailed)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if opts.Timeout < 0 {
		return nil, nil, fmt.Errorf("%w: timeout cannot be negative", ErrInvalidOptions)
	}

	// 1. Verify index before touching disk or network
	res, err := VerifyAndSelectUpdate(envelopeBytes, opts.IndexOptions)
	if err != nil {
		return nil, res, err
	}
	if res == nil || res.Artifact == nil {
		return nil, res, ErrNoUpdate
	}

	if err := ctx.Err(); err != nil {
		return nil, res, err
	}

	art := res.Artifact

	// 2. Validate ParentDir (must exist, must be directory, refuse symlink, prove SameFile)
	if opts.ParentDir == "" {
		return nil, res, fmt.Errorf("%w: empty parent directory", ErrInvalidParentDir)
	}
	parentAbs, err := filepath.Abs(opts.ParentDir)
	if err != nil {
		return nil, res, fmt.Errorf("%w: invalid path: %v", ErrInvalidParentDir, err)
	}
	pInfo, err := os.Lstat(parentAbs)
	if err != nil {
		return nil, res, fmt.Errorf("%w: cannot stat parent: %v", ErrInvalidParentDir, err)
	}
	if !pInfo.IsDir() || pInfo.Mode()&os.ModeSymlink != 0 {
		return nil, res, fmt.Errorf("%w: parent must be a real directory, not symlink", ErrInvalidParentDir)
	}
	if err := checkParentDirectoryPermissions(ctx, pInfo, parentAbs); err != nil {
		return nil, res, err
	}

	root, err := os.OpenRoot(parentAbs)
	if err != nil {
		return nil, res, fmt.Errorf("%w: cannot open parent root: %v", ErrInvalidParentDir, err)
	}
	defer root.Close()

	rootStat, err := root.Stat(".")
	if err != nil || !os.SameFile(pInfo, rootStat) {
		return nil, res, fmt.Errorf("%w: parent directory changed during open", ErrInvalidParentDir)
	}

	// 3. Disk space check: required = MinFreeDiskSpaceBytes + art.Size (with overflow check)
	diskChecker := opts.DiskSpaceCheck
	if diskChecker == nil {
		diskChecker = getFreeDiskSpace
	}
	if uint64(art.Size) > math.MaxUint64-MinFreeDiskSpaceBytes {
		return nil, res, fmt.Errorf("%w: artifact size calculation overflow", ErrInsufficientDiskSpace)
	}
	requiredBytes := uint64(art.Size) + MinFreeDiskSpaceBytes
	freeBytes, err := diskChecker(parentAbs)
	if err != nil {
		return nil, res, fmt.Errorf("%w: probe failed: %v", ErrInsufficientDiskSpace, err)
	}
	if freeBytes < requiredBytes {
		return nil, res, fmt.Errorf("%w: free %d < required %d bytes", ErrInsufficientDiskSpace, freeBytes, requiredBytes)
	}

	// 4. Create isolated 0700 staging directory under ParentDir
	var randBuf [16]byte
	if _, err := io.ReadFull(rand.Reader, randBuf[:]); err != nil {
		return nil, res, fmt.Errorf("desktopupdate: entropy failure: %v", err)
	}
	stageDirName := fmt.Sprintf("stage-%s-%d-%s", res.Version, res.Sequence, hex.EncodeToString(randBuf[:]))
	if opts.hostStageName != "" {
		if !hostValidStageName(opts.hostStageName) {
			return nil, res, ErrInvalidParentDir
		}
		stageDirName = opts.hostStageName
	}
	stageDirPath := filepath.Join(parentAbs, stageDirName)

	if opts.hostStageName != "" {
		key, e := hostDirectoryKey(stageDirPath)
		if e != nil || key != opts.hostStageIdentity {
			return nil, res, ErrInvalidParentDir
		}
		entries, e := os.ReadDir(stageDirPath)
		if e != nil || len(entries) != 0 {
			return nil, res, ErrInvalidParentDir
		}
	} else if err := root.Mkdir(stageDirName, 0700); err != nil {
		return nil, res, err
	}
	if err := secureNewStageDirectory(ctx, stageDirPath); err != nil {
		_ = root.Remove(stageDirName)
		return nil, res, fmt.Errorf("desktopupdate: secure stage dir: %v", err)
	}

	stageRoot, err := root.OpenRoot(stageDirName)
	if err != nil {
		_ = root.Remove(stageDirName)
		return nil, res, fmt.Errorf("desktopupdate: cannot open stage root: %v", err)
	}
	defer stageRoot.Close()

	// Capture open descriptor identity of stage directory
	stageOpenedStat, err := stageRoot.Stat(".")
	if err != nil {
		_ = root.Remove(stageDirName)
		return nil, res, fmt.Errorf("desktopupdate: stat opened stage dir: %v", err)
	}

	// Cleanup tracker:
	// Only delete the files we created and confirmed identical.
	// Never delete unknown or substituted files.
	var tmpCreated, payloadCreated bool
	var expectedTmpInfo os.FileInfo
	var completedSuccess bool

	defer func() {
		if !completedSuccess {
			if tmpCreated {
				curTmp, err := stageRoot.Stat(StageTempFileName)
				if err == nil && expectedTmpInfo != nil && os.SameFile(expectedTmpInfo, curTmp) {
					_ = stageRoot.Remove(StageTempFileName)
				}
			}
			if payloadCreated {
				curPay, err := stageRoot.Stat(StagePayloadFileName)
				if err == nil && expectedTmpInfo != nil && os.SameFile(expectedTmpInfo, curPay) {
					_ = stageRoot.Remove(StagePayloadFileName)
				}
			}
			// Attempt to remove stage directory only if empty and unmodified
			curStage, err := root.Stat(stageDirName)
			if err == nil && os.SameFile(stageOpenedStat, curStage) {
				_ = root.Remove(stageDirName)
			}
		}
	}()

	// 5. Create exclusive temporary file 0600 under stageRoot
	tmpFile, err := stageRoot.OpenFile(StageTempFileName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, res, fmt.Errorf("desktopupdate: cannot create temporary file: %v", err)
	}
	tmpCreated = true

	expectedTmpInfo, err = tmpFile.Stat()
	if err != nil {
		_ = tmpFile.Close()
		return nil, res, fmt.Errorf("desktopupdate: stat temporary file fd: %v", err)
	}

	// 6. Execute streaming HTTPS download
	dlErr := downloadArtifactStream(ctx, art.URL, opts.IndexOptions.AllowedHosts, tmpFile, art.Size, art.SHA256, opts)
	if dlErr != nil {
		_ = tmpFile.Close()
		return nil, res, dlErr
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return nil, res, fmt.Errorf("%w: sync failed: %v", ErrDownloadFailed, err)
	}
	if err := tmpFile.Close(); err != nil {
		return nil, res, fmt.Errorf("%w: close failed: %v", ErrDownloadFailed, err)
	}

	// Verify stage and tmp file identity before linking (using Lstat without following symlinks)
	preLinkStage, err := stageRoot.Lstat(".")
	if err != nil || !os.SameFile(stageOpenedStat, preLinkStage) || preLinkStage.Mode()&os.ModeSymlink != 0 {
		return nil, res, fmt.Errorf("%w: stage directory replaced before publish", ErrDownloadFailed)
	}
	preLinkTmp, err := stageRoot.Lstat(StageTempFileName)
	if err != nil || !os.SameFile(expectedTmpInfo, preLinkTmp) || !preLinkTmp.Mode().IsRegular() || preLinkTmp.Mode()&os.ModeSymlink != 0 {
		return nil, res, fmt.Errorf("%w: temporary file replaced before publish", ErrDownloadFailed)
	}

	// Check cancellation before publish
	if err := ctx.Err(); err != nil {
		return nil, res, err
	}

	// 7. Atomic publication using stageRoot.Link without overwriting existing files
	linkErr := stageRoot.Link(StageTempFileName, StagePayloadFileName)
	if linkErr != nil {
		if errors.Is(linkErr, os.ErrExist) {
			return nil, res, ErrTargetConflict
		}
		return nil, res, fmt.Errorf("%w: link failed: %v", ErrDownloadFailed, linkErr)
	}
	payloadCreated = true

	// Remove temporary hard link name; on failure keep tmpCreated=true for cleanup
	if err := stageRoot.Remove(StageTempFileName); err != nil {
		return nil, res, fmt.Errorf("%w: failed to remove temporary hard link: %v", ErrDownloadFailed, err)
	}
	tmpCreated = false

	// Sync stage directory to ensure link directory entry is durable
	syncFn := syncDirectory
	if opts.SyncHook != nil {
		syncFn = opts.SyncHook
	}
	if err := syncFn(stageDirPath); err != nil {
		return nil, res, fmt.Errorf("%w: sync stage directory failed: %v", ErrDownloadFailed, err)
	}

	// 8. Security verification and identity confirmation of payload
	finalPayloadPath := filepath.Join(stageDirPath, StagePayloadFileName)
	if err := verifyStagedFileSecurity(ctx, stageDirPath, finalPayloadPath); err != nil {
		return nil, res, err
	}

	// Final verification: ensure payload on disk is identical to download FD, a regular file, and not a symlink
	finalPayStat, err := stageRoot.Lstat(StagePayloadFileName)
	if err != nil || !os.SameFile(expectedTmpInfo, finalPayStat) || !finalPayStat.Mode().IsRegular() || finalPayStat.Mode()&os.ModeSymlink != 0 {
		return nil, res, fmt.Errorf("%w: final payload identity mismatch or not regular file", ErrDownloadFailed)
	}

	// Confirm temp file is definitively gone
	if _, err := stageRoot.Lstat(StageTempFileName); !errors.Is(err, os.ErrNotExist) {
		return nil, res, fmt.Errorf("%w: temporary file remains present after publication", ErrDownloadFailed)
	}

	// Recheck parent still matches opened root
	currentPInfo, err := os.Lstat(parentAbs)
	if err != nil || !os.SameFile(pInfo, currentPInfo) {
		return nil, res, fmt.Errorf("%w: parent directory modified during staging", ErrInvalidParentDir)
	}

	completedSuccess = true

	receipt := &StagedReceipt{
		Channel:        res.Channel,
		Sequence:       res.Sequence,
		Version:        res.Version,
		ArtifactPath:   finalPayloadPath,
		SHA256:         art.SHA256,
		Size:           art.Size,
		BackendBinding: art.BackendBinding,
		StagedAt:       time.Now().UTC(),
	}

	return receipt, res, nil
}

func downloadArtifactStream(ctx context.Context, initialURL string, allowedHosts []string, out io.Writer, expectedSize int64, expectedSHA256 string, opts DownloadStagingOptions) error {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultDownloadTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var transport http.RoundTripper
	if opts.HTTPClient != nil && opts.HTTPClient.Transport != nil {
		transport = opts.HTTPClient.Transport
	} else {
		// Production secure transport: timeout bounds, max response header limits, proxy from env preserved
		transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			DisableCompression:    true,
		}
	}

	customClient := http.Client{
		Transport: transport,
		Jar:       nil,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= MaxRedirects {
				return fmt.Errorf("%w: too many redirects", ErrURLNotAllowed)
			}
			if err := validateRedirectURL(req.URL, allowedHosts); err != nil {
				return err
			}
			req.Header.Del("Cookie")
			req.Header.Del("Authorization")
			return nil
		},
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, initialURL, nil)
	if err != nil {
		return fmt.Errorf("%w: failed to create request", ErrDownloadFailed)
	}

	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Del("Cookie")
	req.Header.Del("Authorization")

	resp, err := customClient.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		if errors.Is(err, ErrURLNotAllowed) {
			return ErrURLNotAllowed
		}
		return fmt.Errorf("%w: request failed", ErrDownloadFailed)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: unexpected HTTP status %d", ErrDownloadFailed, resp.StatusCode)
	}

	hasher := sha256.New()
	multi := io.MultiWriter(out, hasher)

	limitReader := io.LimitReader(resp.Body, expectedSize+1)
	n, err := io.Copy(multi, limitReader)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return fmt.Errorf("%w: stream read error", ErrDownloadFailed)
	}

	if n > expectedSize {
		return fmt.Errorf("%w: downloaded bytes exceeded expected size %d", ErrSizeMismatch, expectedSize)
	}
	if n < expectedSize {
		return fmt.Errorf("%w: downloaded bytes %d less than expected size %d", ErrSizeMismatch, n, expectedSize)
	}

	actualSHA256 := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(actualSHA256, expectedSHA256) {
		return fmt.Errorf("%w: got %s, want %s", ErrDigestMismatch, actualSHA256, expectedSHA256)
	}

	return nil
}

func validateRedirectURL(u *url.URL, allowedHosts []string) error {
	if u.Scheme != "https" {
		return fmt.Errorf("%w: redirect scheme must be https", ErrURLNotAllowed)
	}
	if u.User != nil {
		return fmt.Errorf("%w: redirect userinfo not permitted", ErrURLNotAllowed)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%w: redirect fragment not permitted", ErrURLNotAllowed)
	}
	port := u.Port()
	if port != "" && port != "443" {
		return fmt.Errorf("%w: redirect non-standard port %q", ErrURLNotAllowed, port)
	}
	hostname := strings.ToLower(u.Hostname())
	matched := false
	for _, host := range allowedHosts {
		if hostname == host {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("%w: redirect host not in allowed hosts", ErrURLNotAllowed)
	}
	return nil
}
