package packmanager

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	contracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/artifactio"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/packprotocol"
)

var (
	ErrPackTrustMaterialRequired = errors.New("pack trust material required: intent planned without raw envelope")
	ErrPackAuthorizationRequired = errors.New("pack authorization required: catalog authority expired")
	ErrStagedArtifactTampered    = errors.New("staged artifact tampered or corrupt on disk")
	ErrForeignFilesPresent       = errors.New("foreign or unknown files present in staging directory")
	ErrArchiveInvalid            = errors.New("pack archive is invalid or corrupt")
	ErrInventoryMismatch         = errors.New("pack archive inventory does not match manifest")
)

type ArtifactStagingConfig struct {
	StagingRootDir   string
	Policy           packprotocol.VerificationPolicy
	HTTPClient       *http.Client
	DownloadTimeout  time.Duration
	OwnerUID         int
	OwnerGID         int
	MaxUnpackedBytes int64
	Clock            func() time.Time
}

type StageArtifactRequest struct {
	OperationID      string
	TaskID           string
	CoreGeneration   int64
	LeaseGeneration  int64
	OwnerID          string
	RenewedAuthority *packprotocol.VerifiedPackSelection
	Audit            contracts.AuditContext
}

type ArtifactStager struct {
	store         contracts.PackRepository
	config        ArtifactStagingConfig
	preCommitHook func(stageDir string) error
}

func (s *ArtifactStager) setPreCommitHookForTest(hook func(stageDir string) error) {
	s.preCommitHook = hook
}

func NewArtifactStager(store contracts.PackRepository, cfg ArtifactStagingConfig) (*ArtifactStager, error) {
	if store == nil {
		return nil, errors.New("nil pack repository")
	}
	if !filepath.IsAbs(cfg.StagingRootDir) || cfg.StagingRootDir != filepath.Clean(cfg.StagingRootDir) {
		return nil, fmt.Errorf("staging root directory must be absolute clean path: %q", cfg.StagingRootDir)
	}
	if cfg.OwnerUID < 0 || cfg.OwnerGID < 0 {
		return nil, errors.New("owner uid and gid must be non-negative")
	}
	if cfg.DownloadTimeout <= 0 {
		cfg.DownloadTimeout = artifactio.DefaultDownloadTimeout
	}
	if cfg.MaxUnpackedBytes <= 0 {
		cfg.MaxUnpackedBytes = 1024 * 1024 * 1024 // 1 GiB safety margin
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &ArtifactStager{
		store:  store,
		config: cfg,
	}, nil
}

func (s *ArtifactStager) clockNow() time.Time {
	if s.config.Clock != nil {
		return s.config.Clock().UTC()
	}
	return time.Now().UTC()
}

func (s *ArtifactStager) StageArtifact(ctx context.Context, req StageArtifactRequest) (*contracts.PackArtifactReceipt, error) {
	if ctx == nil {
		return nil, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.OperationID == "" || req.TaskID == "" || req.CoreGeneration <= 0 || req.LeaseGeneration <= 0 || req.OwnerID == "" {
		return nil, errors.New("positive caller tokens, task id and owner are required")
	}
	if artifactio.CleanRelative(req.OperationID) != nil || strings.Contains(filepath.ToSlash(req.OperationID), "/") {
		return nil, errors.New("invalid operation id for staging path")
	}

	now := s.clockNow()

	// 1. Read planned intent and pack records
	intent, err := s.store.GetPackIntent(ctx, req.OperationID)
	if err != nil {
		return nil, fmt.Errorf("get planned intent: %w", err)
	}
	packRec, err := s.store.GetPack(ctx, intent.PackID)
	if err != nil {
		return nil, fmt.Errorf("get pack record: %w", err)
	}

	// 2. Read trust material
	trustMat, err := s.store.GetPackTrustMaterial(ctx, req.OperationID)
	if err != nil {
		if errors.Is(err, sqlErrNotFound) || strings.Contains(err.Error(), "not found") {
			return nil, ErrPackTrustMaterialRequired
		}
		return nil, fmt.Errorf("get pack trust material: %w", err)
	}

	// 3. Handle renewed authority resupply if provided
	if req.RenewedAuthority != nil {
		if resupplyErr := s.store.ResupplyPackTrustMaterial(ctx, req.OperationID, *req.RenewedAuthority, "renewed_catalog"); resupplyErr != nil {
			return nil, fmt.Errorf("resupply renewed authority: %w", resupplyErr)
		}
		trustMat, err = s.store.GetPackTrustMaterial(ctx, req.OperationID)
		if err != nil {
			return nil, fmt.Errorf("get updated trust material: %w", err)
		}
	}

	// 4. Verify selection from raw trust material using policy with active clock
	policy := s.config.Policy
	policy.Now = now
	verifiedSel, err := packprotocol.VerifySelection(trustMat.CatalogEnvelope, trustMat.ManifestBytes, policy)
	if err != nil {
		if errors.Is(err, errors.New("catalog_expired")) || err.Error() == "catalog_expired" {
			recErr := s.store.RecordAuthorizationRequired(ctx, contracts.AuthorizationRequiredRecord{
				OperationID:     req.OperationID,
				TaskID:          req.TaskID,
				CoreGeneration:  req.CoreGeneration,
				LeaseGeneration: req.LeaseGeneration,
				OwnerID:         req.OwnerID,
				Reason:          "catalog expired, renewed authority required",
				Audit:           req.Audit,
			})
			if recErr != nil {
				return nil, fmt.Errorf("record authorization required: %w", recErr)
			}
			return nil, ErrPackAuthorizationRequired
		}
		recErr := s.store.RecordLifecycleFailure(ctx, contracts.LifecycleFailureRecord{
			OperationID:     req.OperationID,
			TaskID:          req.TaskID,
			CoreGeneration:  req.CoreGeneration,
			LeaseGeneration: req.LeaseGeneration,
			OwnerID:         req.OwnerID,
			Reason:          err.Error(),
			Audit:           req.Audit,
		})
		if recErr != nil {
			return nil, fmt.Errorf("record lifecycle failure: %w", recErr)
		}
		return nil, fmt.Errorf("re-verify trust material: %w", err)
	}

	snap, manifestBytes, ok := verifiedSel.Snapshot()
	if !ok {
		return nil, errors.New("invalid verified selection snapshot")
	}

	if snap.PackID != intent.PackID || snap.Version != intent.Version ||
		snap.ManifestSHA256 != packRec.ManifestSHA256 || snap.ArtifactSHA256 != packRec.ArtifactSHA256 {
		return nil, errors.New("verified selection does not match planned operation identity")
	}

	relStagePath := "staging/" + req.OperationID

	// 5. Preflight Stage Intent in SQLite BEFORE touching disk or network
	journalRev, err := s.store.RecordStageIntent(ctx, contracts.StageArtifactIntent{
		OperationID:            req.OperationID,
		TaskID:                 req.TaskID,
		PackID:                 snap.PackID,
		Version:                snap.Version,
		PlanSHA256:             intent.PlanSHA256,
		CoreGeneration:         req.CoreGeneration,
		LeaseGeneration:        req.LeaseGeneration,
		OwnerID:                req.OwnerID,
		StageDirectory:         relStagePath,
		AuthorityCatalogSHA256: snap.CatalogSHA256,
		AuthoritySequence:      trustMat.AuthoritySequence,
		AuthorityExpiresAt:     snap.ExpiresAt,
		Audit:                  req.Audit,
	})
	if err != nil {
		return nil, fmt.Errorf("record stage intent preflight: %w", err)
	}

	// 6. Descriptor-based Durable Directory Setup
	// Pin staging root directory descriptor
	rootWriter, err := artifactio.TaskDurableWriter(s.config.StagingRootDir, s.config.OwnerUID, s.config.OwnerGID)
	if err != nil {
		return nil, fmt.Errorf("open staging root descriptor: %w", err)
	}
	defer rootWriter.Close()

	if _, err := rootWriter.CreateChildDirectory("staging", 0700); err != nil {
		return nil, fmt.Errorf("create staging child directory: %w", err)
	}
	stagingWriter, err := rootWriter.OpenChildWriter("staging", 0700)
	if err != nil {
		return nil, fmt.Errorf("open staging directory descriptor: %w", err)
	}
	defer stagingWriter.Close()

	if _, err := stagingWriter.CreateChildDirectory(req.OperationID, 0700); err != nil {
		return nil, fmt.Errorf("create operation stage directory: %w", err)
	}
	opWriter, err := stagingWriter.OpenChildWriter(req.OperationID, 0700)
	if err != nil {
		return nil, fmt.Errorf("open operation stage directory descriptor: %w", err)
	}
	defer opWriter.Close()

	// Capture immutable physical identity (device + inode) of stage directory
	stageStat := opWriter.RootInfo()
	stageIdentity := s.computeStageIdentity(stageStat)

	// Acquire exclusive advisory lock for this operation stage directory
	stageLock, err := opWriter.AcquireMetadataLock("stage.lock")
	if err != nil {
		return nil, fmt.Errorf("operation stage is locked by an active writer: %w", err)
	}
	defer func() { _ = stageLock.Release() }()

	// Check existing contents for foreign sentinels or crash artifacts
	children, err := opWriter.ReadDirectChildren()
	if err != nil {
		return nil, fmt.Errorf("read stage directory: %w", err)
	}

	var hasPartFile, hasFullArchive, hasPackDir bool
	for _, child := range children {
		switch child.Name {
		case "artifact.tar.gz.part":
			hasPartFile = true
		case "artifact.tar.gz":
			hasFullArchive = true
		case "pack":
			hasPackDir = true
		case "stage.lock":
			// operation concurrency lock
		default:
			return nil, fmt.Errorf("%w: %q", ErrForeignFilesPresent, child.Name)
		}
	}

	if hasPackDir && !hasFullArchive {
		return nil, fmt.Errorf("%w: unexpected pack directory in stage root", ErrForeignFilesPresent)
	}

	// Check existing receipt for idempotent replay with full inventory verification
	existingRcpt, err := s.store.GetArtifactReceipt(ctx, req.OperationID)
	if err == nil {
		if stageIdentity != existingRcpt.StageIdentity {
			return nil, fmt.Errorf("%w: stage directory identity mismatch (expected %s, got %s)", ErrStagedArtifactTampered, existingRcpt.StageIdentity, stageIdentity)
		}
		if _, fullErr := s.verifyCompleteStagedInventory(opWriter, req.OperationID, snap, intent.PlanSHA256, manifestBytes, stageIdentity); fullErr == nil {
			return &existingRcpt, nil
		} else {
			return nil, fmt.Errorf("%w: %v", ErrStagedArtifactTampered, fullErr)
		}
	}

	// Crash recovery: if artifact.tar.gz and pack are fully present
	if hasFullArchive && hasPackDir && !hasPartFile {
		adoptedRcpt, err := s.verifyCompleteStagedInventory(opWriter, req.OperationID, snap, intent.PlanSHA256, manifestBytes, stageIdentity)
		if err == nil {
			// Intact staged payload matches plan completely: adopt and commit
			commitRecord := contracts.CommitArtifactReceiptRecord{
				TaskID:                  req.TaskID,
				Receipt:                 *adoptedRcpt,
				CoreGeneration:          req.CoreGeneration,
				LeaseGeneration:         req.LeaseGeneration,
				OwnerID:                 req.OwnerID,
				ExpectedJournalRevision: journalRev,
				Audit:                   req.Audit,
			}
			if err := s.store.CommitArtifactReceipt(ctx, commitRecord); err != nil {
				return nil, fmt.Errorf("commit adopted artifact receipt: %w", err)
			}
			return adoptedRcpt, nil
		}
		// If verification failed, return error without wiping foreign or tampered files
		return nil, fmt.Errorf("%w: existing files failed inventory verification: %v", ErrStagedArtifactTampered, err)
	}

	// Only clean up a .part file if confirmed regular file owned by us
	if hasPartFile {
		partInfo, statErr := opWriter.Ops().Lstat("artifact.tar.gz.part")
		if statErr == nil && partInfo.Mode().IsRegular() && artifactio.CheckFileOwner(partInfo, s.config.OwnerUID, s.config.OwnerGID) == nil {
			_ = opWriter.Ops().Remove("artifact.tar.gz.part")
		} else {
			return nil, fmt.Errorf("%w: unsafe existing .part file", ErrForeignFilesPresent)
		}
	}

	// Check cancellation before download
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 7. Streaming HTTPS Download through descriptor
	partFile, err := opWriter.Ops().OpenFile("artifact.tar.gz.part", os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("create temporary download file: %w", err)
	}
	partClosed := false
	defer func() {
		if !partClosed {
			_ = opWriter.Ops().CloseFile(partFile)
			_ = opWriter.Ops().Remove("artifact.tar.gz.part")
		}
	}()

	var transport http.RoundTripper
	if s.config.HTTPClient != nil {
		transport = s.config.HTTPClient.Transport
	}
	downloadOpts := artifactio.DownloadOptions{
		URL:            snap.ArtifactURL,
		AllowedHosts:   s.config.Policy.AllowedHosts,
		Out:            partFile,
		ExpectedSize:   snap.ArtifactSize,
		ExpectedSHA256: snap.ArtifactSHA256,
		Timeout:        s.config.DownloadTimeout,
		Transport:      transport,
	}
	if dlErr := artifactio.DownloadArtifactStream(ctx, downloadOpts); dlErr != nil {
		return nil, dlErr
	}
	if err := opWriter.Ops().Sync(partFile); err != nil {
		return nil, fmt.Errorf("sync downloaded file: %w", err)
	}
	if _, err := partFile.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek downloaded file: %w", err)
	}

	// Check cancellation after download before unpack
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 8. Safe Unpack & Inventory Verification using pinned descriptors
	if _, err := opWriter.CreateChildDirectory("pack", 0755); err != nil {
		return nil, fmt.Errorf("create pack directory: %w", err)
	}
	packWriter, err := opWriter.OpenChildWriter("pack", 0755)
	if err != nil {
		return nil, fmt.Errorf("open pack directory: %w", err)
	}
	defer packWriter.Close()

	unpackInfo, err := s.unpackAndVerifyArchiveDescriptor(ctx, partFile, snap.ArtifactSize, snap.ArtifactSHA256, manifestBytes, packWriter)
	if err != nil {
		return nil, err
	}

	if err := opWriter.Ops().CloseFile(partFile); err != nil {
		return nil, fmt.Errorf("close downloaded file: %w", err)
	}
	partClosed = true

	// Atomic publication of archive file inside opWriter descriptor
	if err := opWriter.Ops().Rename("artifact.tar.gz.part", "artifact.tar.gz"); err != nil {
		_ = opWriter.Ops().Remove("artifact.tar.gz.part")
		return nil, fmt.Errorf("publish archive file: %w", err)
	}
	if err := opWriter.SyncRoot(); err != nil {
		return nil, fmt.Errorf("%w: sync stage dir: %v", artifactio.ErrDurableCommitUnknown, err)
	}

	// 9. Full readback verification of staged inventory
	receipt, err := s.verifyCompleteStagedInventory(opWriter, req.OperationID, snap, intent.PlanSHA256, manifestBytes, stageIdentity)
	if err != nil {
		return nil, fmt.Errorf("%w: readback verification failed: %v", ErrStagedArtifactTampered, err)
	}
	receipt.MemberCount = unpackInfo.memberCount
	receipt.UnpackedTotalBytes = unpackInfo.totalUnpackedBytes

	// Check cancellation before SQLite commit
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Pre-commit test seam hook for controlled crash simulation
	if s.preCommitHook != nil {
		if err := s.preCommitHook(opWriter.RootPath()); err != nil {
			return nil, err
		}
	}

	// 10. Commit Receipt in SQLite
	commitRecord := contracts.CommitArtifactReceiptRecord{
		TaskID:                  req.TaskID,
		Receipt:                 *receipt,
		CoreGeneration:          req.CoreGeneration,
		LeaseGeneration:         req.LeaseGeneration,
		OwnerID:                 req.OwnerID,
		ExpectedJournalRevision: journalRev,
		Audit:                   req.Audit,
	}
	if err := s.store.CommitArtifactReceipt(ctx, commitRecord); err != nil {
		return nil, fmt.Errorf("commit artifact receipt: %w", err)
	}

	return receipt, nil
}

func (s *ArtifactStager) computeStageIdentity(info os.FileInfo) string {
	return ComputeStageIdentity(info)
}

func ComputeStageIdentity(info os.FileInfo) string {
	if info != nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			return fmt.Sprintf("dev:%d:ino:%d", stat.Dev, stat.Ino)
		}
	}
	return "dev:0:ino:0"
}

type unpackDescriptorResult struct {
	adapterPath        string
	adapterSHA         string
	memberCount        int
	totalUnpackedBytes int64
}

func (s *ArtifactStager) unpackAndVerifyArchiveDescriptor(ctx context.Context, reader io.Reader, size int64, expectedSHA string, rawManifest []byte, packWriter *artifactio.DurableWriter) (*unpackDescriptorResult, error) {
	exactStream, err := artifactio.NewExactArchiveReader(reader, size, size)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrArchiveInvalid, err)
	}
	gzipReader, err := gzip.NewReader(exactStream)
	if err != nil {
		return nil, fmt.Errorf("%w: open gzip: %v", ErrArchiveInvalid, err)
	}
	gzipReader.Multistream(false)
	defer gzipReader.Close()

	manifestObj, err := packprotocol.ParseManifest(rawManifest)
	if err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	var adapterPath, adapterSHA string
	for _, entry := range manifestObj.Entries {
		if entry.Role == "adapter" {
			adapterPath = entry.Path
			break
		}
	}
	if adapterPath == "" {
		return nil, errors.New("manifest has no adapter entry")
	}

	expectedFiles := make(map[string]packprotocol.File, len(manifestObj.Files))
	for _, f := range manifestObj.Files {
		expectedFiles["pack/"+f.Path] = f
		if f.Path == adapterPath {
			adapterSHA = f.SHA256
		}
	}
	if adapterSHA == "" {
		return nil, errors.New("manifest adapter entry file not declared in files")
	}

	tarReader := tar.NewReader(gzipReader)
	seen := make(map[string]bool, len(expectedFiles)+1)
	var memberCount int
	var totalUnpackedBytes int64

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: read tar: %v", ErrArchiveInvalid, err)
		}

		if valErr := artifactio.ValidateUSTARRegularHeader(header); valErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrArchiveInvalid, valErr)
		}
		if header.Size < 0 || header.Size > 128<<20 {
			return nil, fmt.Errorf("%w: member size invalid", ErrArchiveInvalid)
		}

		if seen[header.Name] {
			return nil, fmt.Errorf("%w: duplicate member %q", ErrArchiveInvalid, header.Name)
		}
		seen[header.Name] = true
		memberCount++
		totalUnpackedBytes += header.Size
		if totalUnpackedBytes > s.config.MaxUnpackedBytes {
			return nil, fmt.Errorf("%w: unpacked total bytes exceeded bound", ErrArchiveInvalid)
		}

		if artifactio.CleanRelative(header.Name) != nil || strings.HasPrefix(header.Name, "/") {
			return nil, fmt.Errorf("%w: path escape %q", ErrInventoryMismatch, header.Name)
		}

		relInPack := strings.TrimPrefix(header.Name, "pack/")
		if relInPack == header.Name {
			return nil, fmt.Errorf("%w: member %q outside pack/ prefix", ErrInventoryMismatch, header.Name)
		}

		sess, err := s.openParentWriterForPath(packWriter, relInPack, true)
		if err != nil {
			return nil, err
		}

		if header.Name == "pack/manifest.json" {
			if header.Mode != 0644 || header.Size != int64(len(rawManifest)) {
				_ = sess.SyncAndClose()
				return nil, fmt.Errorf("%w: manifest.json size or mode mismatch", ErrInventoryMismatch)
			}
			f, err := sess.TargetWriter.Ops().OpenFile(sess.FileName, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
			if err != nil {
				_ = sess.SyncAndClose()
				return nil, fmt.Errorf("create manifest member: %w", err)
			}
			sink := &stageMemberWriter{
				ops:      sess.TargetWriter.Ops(),
				file:     f,
				mode:     0644,
				ownerUID: s.config.OwnerUID,
				ownerGID: s.config.OwnerGID,
			}
			if err := artifactio.VerifyArchiveMember(tarReader, header.Size, rawManifest, "", memberSinkWrapper{writer: sink}, header.Name, 0644); err != nil {
				_ = sess.TargetWriter.Ops().CloseFile(f)
				_ = sess.SyncAndClose()
				return nil, fmt.Errorf("%w: verify manifest member: %v", ErrInventoryMismatch, err)
			}
			if err := sess.SyncAndClose(); err != nil {
				return nil, fmt.Errorf("%w: %v", artifactio.ErrDurableCommitUnknown, err)
			}
			continue
		}

		expectedFile, ok := expectedFiles[header.Name]
		if !ok {
			_ = sess.SyncAndClose()
			return nil, fmt.Errorf("%w: unlisted member %q", ErrInventoryMismatch, header.Name)
		}
		if int64(header.Mode) != int64(expectedFile.Mode) {
			_ = sess.SyncAndClose()
			return nil, fmt.Errorf("%w: member %q mode mismatch: got %o want %o", ErrInventoryMismatch, header.Name, header.Mode, expectedFile.Mode)
		}
		if header.Size != expectedFile.Size {
			_ = sess.SyncAndClose()
			return nil, fmt.Errorf("%w: member %q size mismatch: got %d want %d", ErrInventoryMismatch, header.Name, header.Size, expectedFile.Size)
		}

		f, err := sess.TargetWriter.Ops().OpenFile(sess.FileName, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			_ = sess.SyncAndClose()
			return nil, fmt.Errorf("create member file %q: %w", relInPack, err)
		}
		sink := &stageMemberWriter{
			ops:      sess.TargetWriter.Ops(),
			file:     f,
			mode:     os.FileMode(expectedFile.Mode),
			ownerUID: s.config.OwnerUID,
			ownerGID: s.config.OwnerGID,
		}
		if err := artifactio.VerifyArchiveMember(tarReader, header.Size, nil, expectedFile.SHA256, memberSinkWrapper{writer: sink}, header.Name, uint32(expectedFile.Mode)); err != nil {
			_ = sess.TargetWriter.Ops().CloseFile(f)
			_ = sess.SyncAndClose()
			return nil, fmt.Errorf("%w: verify member content: %v", ErrInventoryMismatch, err)
		}
		if err := sess.SyncAndClose(); err != nil {
			return nil, fmt.Errorf("%w: %v", artifactio.ErrDurableCommitUnknown, err)
		}
	}

	if !seen["pack/manifest.json"] {
		return nil, fmt.Errorf("%w: missing pack/manifest.json", ErrInventoryMismatch)
	}
	for path := range expectedFiles {
		if !seen[path] {
			return nil, fmt.Errorf("%w: missing declared file %q", ErrInventoryMismatch, path)
		}
	}

	if _, err := io.Copy(io.Discard, gzipReader); err != nil {
		return nil, fmt.Errorf("%w: trailing gzip read: %v", ErrArchiveInvalid, err)
	}
	if err := exactStream.Finish(expectedSHA); err != nil {
		return nil, fmt.Errorf("%w: finish archive stream: %v", ErrArchiveInvalid, err)
	}

	// Sync pack directory
	if err := packWriter.SyncRoot(); err != nil {
		return nil, fmt.Errorf("%w: sync pack root: %v", artifactio.ErrDurableCommitUnknown, err)
	}

	return &unpackDescriptorResult{
		adapterPath:        adapterPath,
		adapterSHA:         adapterSHA,
		memberCount:        memberCount,
		totalUnpackedBytes: totalUnpackedBytes,
	}, nil
}

type stageMemberWriter struct {
	ops      artifactio.DurableOps
	file     *os.File
	mode     os.FileMode
	ownerUID int
	ownerGID int
	closed   bool
}

func (w *stageMemberWriter) Write(p []byte) (int, error) {
	return w.ops.Write(w.file, p)
}

func (w *stageMemberWriter) Sync() error {
	return w.ops.Sync(w.file)
}

func (w *stageMemberWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true

	// 1. Sync data bytes
	if err := w.ops.Sync(w.file); err != nil {
		_ = w.ops.CloseFile(w.file)
		return fmt.Errorf("sync member data: %w", err)
	}

	// 2. Chmod exact declared mode overriding umask
	if err := w.ops.Chmod(w.file, w.mode); err != nil {
		_ = w.ops.CloseFile(w.file)
		return fmt.Errorf("chmod member exact mode %o: %w", w.mode, err)
	}

	// 3. Chown exact owner
	if err := w.ops.Chown(w.file, w.ownerUID, w.ownerGID); err != nil {
		_ = w.ops.CloseFile(w.file)
		return fmt.Errorf("chown member exact owner %d:%d: %w", w.ownerUID, w.ownerGID, err)
	}

	// 4. Stat descriptor and verify attributes
	info, err := w.ops.Stat(w.file)
	if err != nil {
		_ = w.ops.CloseFile(w.file)
		return fmt.Errorf("stat member descriptor: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != w.mode.Perm() ||
		artifactio.CheckFileOwner(info, w.ownerUID, w.ownerGID) != nil {
		_ = w.ops.CloseFile(w.file)
		return errors.New("member descriptor attributes or owner mismatch after chmod/chown")
	}

	// 5. Final metadata sync
	if err := w.ops.Sync(w.file); err != nil {
		_ = w.ops.CloseFile(w.file)
		return fmt.Errorf("sync member metadata: %w", err)
	}

	// 6. Close descriptor
	return w.ops.CloseFile(w.file)
}

type memberSinkWrapper struct {
	writer *stageMemberWriter
}

func (m memberSinkWrapper) OpenMember(name string, mode uint32) (artifactio.ArchiveMember, error) {
	return m.writer, nil
}

type nestedWriterSession = artifactio.NestedWriterSession

func (s *ArtifactStager) openParentWriterForPath(packWriter *artifactio.DurableWriter, relPathInPack string, allowCreate bool) (*nestedWriterSession, error) {
	return openParentWriterForPathStatic(packWriter, relPathInPack, allowCreate)
}

func openParentWriterForPathStatic(packWriter *artifactio.DurableWriter, relPathInPack string, allowCreate bool) (*nestedWriterSession, error) {
	return artifactio.OpenParentWriterForPath(packWriter, relPathInPack, allowCreate)
}

func (s *ArtifactStager) verifyCompleteStagedInventory(opWriter *artifactio.DurableWriter, opID string, snap packprotocol.Selection, planSHA string, rawManifest []byte, expectedStageIdentity string) (*contracts.PackArtifactReceipt, error) {
	return VerifyCompleteStagedInventory(opWriter, opID, snap, planSHA, rawManifest, expectedStageIdentity, s.config.OwnerUID, s.config.OwnerGID, s.clockNow())
}

// ReadAndVerifyStagedInventory opens an existing stage directory and verifies the complete inventory without mutation.
func ReadAndVerifyStagedInventory(stagePath string, opID string, snap packprotocol.Selection, planSHA string, rawManifest []byte, expectedStageIdentity string, ownerUID int, ownerGID int) (*contracts.PackArtifactReceipt, error) {
	writer, err := artifactio.NewDurableWriter(stagePath, ownerUID, ownerGID)
	if err != nil {
		return nil, err
	}
	defer writer.Close()
	return VerifyCompleteStagedInventory(writer, opID, snap, planSHA, rawManifest, expectedStageIdentity, ownerUID, ownerGID, time.Now().UTC())
}

// VerifyCompleteStagedInventory verifies the staged files against the selection and manifest.
func VerifyCompleteStagedInventory(opWriter *artifactio.DurableWriter, opID string, snap packprotocol.Selection, planSHA string, rawManifest []byte, expectedStageIdentity string, ownerUID int, ownerGID int, verifiedAt time.Time) (*contracts.PackArtifactReceipt, error) {
	if err := opWriter.VerifyLiveRoot(); err != nil {
		return nil, err
	}

	actualPhysicalIdentity := ComputeStageIdentity(opWriter.RootInfo())
	if expectedStageIdentity != "" && actualPhysicalIdentity != expectedStageIdentity {
		return nil, fmt.Errorf("%w: physical stage directory identity changed (expected %s, got %s)", ErrStagedArtifactTampered, expectedStageIdentity, actualPhysicalIdentity)
	}

	// 1. Verify archive file
	archiveFile, err := opWriter.Ops().OpenFile("artifact.tar.gz", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open archive file: %w", err)
	}
	defer opWriter.Ops().CloseFile(archiveFile)

	archInfo, err := opWriter.Ops().Stat(archiveFile)
	if err != nil || !archInfo.Mode().IsRegular() || archInfo.Size() != snap.ArtifactSize ||
		artifactio.CheckFileOwner(archInfo, ownerUID, ownerGID) != nil {
		return nil, errors.New("archive file attributes or owner mismatch")
	}
	archHasher := sha256.New()
	if _, err := io.Copy(archHasher, archiveFile); err != nil {
		return nil, err
	}
	if hex.EncodeToString(archHasher.Sum(nil)) != snap.ArtifactSHA256 {
		return nil, errors.New("archive file sha256 mismatch")
	}

	// 2. Open pack child writer and verify manifest.json
	packWriter, err := opWriter.OpenChildWriter("pack", 0755)
	if err != nil {
		return nil, fmt.Errorf("open pack child writer: %w", err)
	}
	defer packWriter.Close()

	manifestFile, err := packWriter.Ops().OpenFile("manifest.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open manifest.json: %w", err)
	}
	defer packWriter.Ops().CloseFile(manifestFile)

	manInfo, err := packWriter.Ops().Stat(manifestFile)
	if err != nil || !manInfo.Mode().IsRegular() || manInfo.Size() != int64(len(rawManifest)) ||
		manInfo.Mode().Perm() != 0644 || artifactio.CheckFileOwner(manInfo, ownerUID, ownerGID) != nil {
		return nil, errors.New("manifest.json attributes or owner mismatch")
	}
	manDiskBytes, err := io.ReadAll(manifestFile)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(manDiskBytes, rawManifest) {
		return nil, errors.New("manifest.json content mismatch")
	}

	manifestObj, err := packprotocol.ParseManifest(rawManifest)
	if err != nil {
		return nil, fmt.Errorf("parse raw manifest: %w", err)
	}

	var adapterPath, adapterSHA string
	for _, entry := range manifestObj.Entries {
		if entry.Role == "adapter" {
			adapterPath = entry.Path
			break
		}
	}
	if adapterPath == "" {
		return nil, errors.New("manifest missing adapter entry")
	}

	expectedFiles := make(map[string]packprotocol.File, len(manifestObj.Files))
	for _, f := range manifestObj.Files {
		expectedFiles[filepath.ToSlash(f.Path)] = f
		if f.Path == adapterPath {
			adapterSHA = f.SHA256
		}
	}
	if adapterSHA == "" {
		return nil, errors.New("manifest missing adapter file declaration")
	}

	// 3. Verify each declared file on disk
	var totalUnpackedBytes int64 = int64(len(rawManifest))
	for path, expected := range expectedFiles {
		sess, err := openParentWriterForPathStatic(packWriter, path, false)
		if err != nil {
			return nil, fmt.Errorf("open parent writer for %q: %w", path, err)
		}
		f, err := sess.TargetWriter.Ops().OpenFile(sess.FileName, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			_ = sess.SyncAndClose()
			return nil, fmt.Errorf("open declared file %q: %w", path, err)
		}
		info, err := sess.TargetWriter.Ops().Stat(f)
		if err != nil || !info.Mode().IsRegular() || info.Size() != expected.Size ||
			info.Mode().Perm() != os.FileMode(expected.Mode) ||
			artifactio.CheckFileOwner(info, ownerUID, ownerGID) != nil {
			_ = sess.TargetWriter.Ops().CloseFile(f)
			_ = sess.SyncAndClose()
			return nil, fmt.Errorf("declared file %q attributes or owner mismatch", path)
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			_ = sess.TargetWriter.Ops().CloseFile(f)
			_ = sess.SyncAndClose()
			return nil, err
		}
		_ = sess.TargetWriter.Ops().CloseFile(f)
		if err := sess.SyncAndClose(); err != nil {
			return nil, err
		}
		if hex.EncodeToString(h.Sum(nil)) != expected.SHA256 {
			return nil, fmt.Errorf("declared file %q checksum mismatch", path)
		}
		totalUnpackedBytes += expected.Size
	}

	// 4. Verify no extra or foreign files in pack/ directory tree
	discoveredFiles := make(map[string]bool)
	if err := collectPackFiles(packWriter, "", discoveredFiles); err != nil {
		return nil, err
	}
	// discoveredFiles contains manifest.json + declared files
	if !discoveredFiles["manifest.json"] {
		return nil, errors.New("manifest.json not discovered in pack tree")
	}
	delete(discoveredFiles, "manifest.json")

	if len(discoveredFiles) != len(expectedFiles) {
		return nil, fmt.Errorf("%w: pack file count mismatch", ErrInventoryMismatch)
	}
	for f := range discoveredFiles {
		if _, ok := expectedFiles[f]; !ok {
			return nil, fmt.Errorf("%w: foreign file %q discovered in pack", ErrForeignFilesPresent, f)
		}
	}

	// 5. Verify no extra files in stage directory root
	stageChildren, err := opWriter.ReadDirectChildren()
	if err != nil {
		return nil, err
	}
	for _, child := range stageChildren {
		if child.Name != "artifact.tar.gz" && child.Name != "pack" && child.Name != "stage.lock" {
			return nil, fmt.Errorf("%w: unexpected child %q in stage root", ErrForeignFilesPresent, child.Name)
		}
	}

	rcptID, err := domain.NewID("rcpt")
	if err != nil {
		return nil, err
	}

	return &contracts.PackArtifactReceipt{
		ReceiptID:          rcptID.String(),
		OperationID:        opID,
		PackID:             snap.PackID,
		Version:            snap.Version,
		PlanSHA256:         planSHA,
		ArchiveSHA256:      snap.ArtifactSHA256,
		ManifestSHA256:     snap.ManifestSHA256,
		ExecutableSHA256:   adapterSHA,
		ExecutablePath:     adapterPath,
		CatalogSHA256:      snap.CatalogSHA256,
		CatalogSequence:    snap.CatalogSequence,
		ArchiveSize:        snap.ArtifactSize,
		UnpackedTotalBytes: totalUnpackedBytes,
		RelativeStagePath:  "staging/" + opID,
		StageIdentity:      actualPhysicalIdentity,
		MemberCount:        len(expectedFiles) + 1,
		VerifiedAt:         verifiedAt,
	}, nil
}

func (s *ArtifactStager) collectPackFiles(writer *artifactio.DurableWriter, prefix string, out map[string]bool) error {
	return collectPackFiles(writer, prefix, out)
}

func collectPackFiles(writer *artifactio.DurableWriter, prefix string, out map[string]bool) error {
	children, err := writer.ReadDirectChildren()
	if err != nil {
		return err
	}
	for _, child := range children {
		childPath := child.Name
		if prefix != "" {
			childPath = prefix + "/" + child.Name
		}
		if child.Mode.IsDir() {
			subWriter, err := writer.OpenChildWriter(child.Name, child.Mode.Perm())
			if err != nil {
				return fmt.Errorf("open child dir %q: %w", childPath, err)
			}
			err = collectPackFiles(subWriter, childPath, out)
			_ = subWriter.Close()
			if err != nil {
				return err
			}
		} else if child.Mode.IsRegular() {
			out[childPath] = true
		} else {
			return fmt.Errorf("%w: non-regular file %q in pack tree", ErrInventoryMismatch, childPath)
		}
	}
	return nil
}

var sqlErrNotFound = errors.New("sql: no rows in result set")
