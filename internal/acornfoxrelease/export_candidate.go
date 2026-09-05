package acornfoxrelease

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/open-card/open-card/internal/install"
)

var ErrCandidateExport = errors.New("candidate output cannot be created safely")
var ErrCandidateExportUnknown = errors.New("candidate output exists but its final verification or durability is unconfirmed")

// ExportVerifiedCandidateV1 copies only the installer's six-file candidate set
// to local disk. The caller retains cleanup ownership of the original stage;
// closing that stage can never delete the exported files. Nothing is published.
func ExportVerifiedCandidateV1(stage *VerifiedCandidateStageV1, output string) (VerifiedCandidateReceiptV1, error) {
	receipt, err := stage.Receipt()
	if err != nil || receipt.Synthetic || !filepath.IsAbs(output) || filepath.Clean(output) != output || !githubPart.MatchString(filepath.Base(output)) {
		return VerifiedCandidateReceiptV1{}, ErrCandidateExport
	}
	parent := filepath.Dir(output)
	clean, err := cleanExistingDirectory(parent)
	if err != nil || clean != parent {
		return VerifiedCandidateReceiptV1{}, ErrCandidateExport
	}
	parentPin, err := pinDirectory(parent)
	if err != nil {
		return VerifiedCandidateReceiptV1{}, ErrCandidateExport
	}
	defer parentPin.close()
	info, err := parentPin.file.Stat()
	if err != nil || info.Mode().Perm() != 0700 {
		return VerifiedCandidateReceiptV1{}, ErrCandidateExport
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Getuid() {
		return VerifiedCandidateReceiptV1{}, ErrCandidateExport
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return VerifiedCandidateReceiptV1{}, ErrCandidateExport
	}
	temporary, err := os.MkdirTemp(parent, ".acornfox-export-")
	if err != nil {
		return VerifiedCandidateReceiptV1{}, ErrCandidateExport
	}
	tempPin, err := pinDirectory(temporary)
	if err != nil {
		return VerifiedCandidateReceiptV1{}, ErrCandidateExport
	}
	transferred := false
	defer func() {
		if !transferred && parentPin.validAt(parent) && tempPin.validAt(temporary) {
			_ = os.RemoveAll(temporary)
		}
		tempPin.close()
	}()
	anchor, err := os.OpenRoot(temporary)
	if err != nil {
		return VerifiedCandidateReceiptV1{}, ErrCandidateExport
	}
	defer anchor.Close()
	for _, entry := range receipt.Artifact.Files {
		if err := copyCandidateFile(stage.stage.root, entry.Path, anchor, entry.Path, entry, entry.Mode, 512<<20); err != nil {
			return VerifiedCandidateReceiptV1{}, ErrCandidateExport
		}
		file, err := anchor.OpenFile(entry.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return VerifiedCandidateReceiptV1{}, ErrCandidateExport
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if syncErr != nil || closeErr != nil {
			return VerifiedCandidateReceiptV1{}, ErrCandidateExport
		}
	}
	if verifyFlatCandidateRoot(temporary, receipt.Artifact) != nil || tempPin.file.Sync() != nil || !parentPin.validAt(parent) || !tempPin.validAt(temporary) {
		return VerifiedCandidateReceiptV1{}, ErrCandidateExport
	}
	if err := renameDirectoryNoReplace(parentPin.file, filepath.Base(temporary), parentPin.file, filepath.Base(output)); err != nil {
		return VerifiedCandidateReceiptV1{}, ErrCandidateExport
	}
	transferred = true
	outputPin, err := pinDirectory(output)
	if err != nil {
		return VerifiedCandidateReceiptV1{}, ErrCandidateExportUnknown
	}
	defer outputPin.close()
	before, err := tempPin.file.Stat()
	after, afterErr := outputPin.file.Stat()
	if err != nil || afterErr != nil || !os.SameFile(before, after) || verifyFlatCandidateRoot(output, receipt.Artifact) != nil || !parentPin.validAt(parent) || parentPin.file.Sync() != nil {
		return VerifiedCandidateReceiptV1{}, ErrCandidateExportUnknown
	}
	return receipt, nil
}

func verifyFlatCandidateRoot(path string, receipt CandidateArtifactReceiptV1) error {
	if receipt.Validate() != nil {
		return ErrCandidateExport
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := install.ValidateAcornFoxCandidateSetLayoutV1(root, receipt.Version); err != nil {
		return err
	}
	controls := map[string][]byte{}
	var archive *os.File
	var archiveSize int64
	defer func() {
		if archive != nil {
			_ = archive.Close()
		}
	}()
	for _, entry := range receipt.Files {
		file, err := root.OpenFile(entry.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 || linkCount(info) != 1 || info.Size() < 0 || info.Size() > 512<<20 {
			_ = file.Close()
			return ErrCandidateExport
		}
		hash := sha256.New()
		if entry.Path == candidateArchiveName(receipt.Version) {
			archive, archiveSize = file, info.Size()
			if _, err := io.Copy(hash, io.LimitReader(file, (512<<20)+1)); err != nil {
				return err
			}
		} else {
			if info.Size() > 2<<20 {
				_ = file.Close()
				return ErrCandidateExport
			}
			raw, readErr := io.ReadAll(io.LimitReader(file, (2<<20)+1))
			closeErr := file.Close()
			if readErr != nil || closeErr != nil || len(raw) > 2<<20 {
				return ErrCandidateExport
			}
			_, _ = hash.Write(raw)
			controls[entry.Path] = raw
		}
		if hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
			return ErrCandidateExport
		}
	}
	if archive == nil || !bytes.Equal(controls["candidate-binding.sha256"], []byte(receipt.BindingSHA256+"\n")) {
		return ErrCandidateExport
	}
	_, err = install.VerifyAcornFoxCandidateArtifactsV1(install.VerifyAcornFoxCandidateArtifactsV1Input{Binding: controls["candidate-binding.json"], BindingSHA256: receipt.BindingSHA256, Manifest: controls["release-manifest.json"], BundleManifest: controls["bundle-manifest.sha256"], Archive: io.NewSectionReader(archive, 0, archiveSize), ArchiveSize: archiveSize})
	return err
}
