package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

type platformBackupCaptureFilesInput struct {
	ManifestIdentity PlatformBackupV3
	KeyVersion       string
	DumpEvidence     SnapshotEvidence
	DatabaseFacts    PlatformBackupCapturedFactsV1
	Caddyfile        []byte
	EdgeCaddyfile    []byte
	Runtime          PlatformBackupRuntimeConfigV1
	Release          PlatformBackupReleaseV1
}

type platformBackupLocalMember struct {
	leaf platformBackupLocalLeaf
	path string
}

var platformBackupLocalMembers = []platformBackupLocalMember{
	{platformBackupLocalConfigCaddyfile, "config/Caddyfile"},
	{platformBackupLocalConfigEdgeCaddyfile, "config/open-card-edge.Caddyfile"},
	{platformBackupLocalConfigRuntimeJSON, "config/runtime.json"},
	{platformBackupLocalControlPlaneDump, "database/control-plane.dump"},
	{platformBackupLocalEdgeTLSJSON, "edge/tls.json"},
	{platformBackupLocalFactsAuditJSON, "facts/audit.json"},
	{platformBackupLocalFactsKeyReferencesJSON, "facts/key-references.json"},
	{platformBackupLocalFactsReleaseJSON, "facts/release.json"},
	{platformBackupLocalFactsRoutesJSON, "facts/routes.json"},
	{platformBackupLocalFactsTasksOutboxJSON, "facts/tasks-outbox.json"},
}

func (s *platformBackupLocalStore) collectCapture(input platformBackupCaptureFilesInput) (PlatformBackupJournalCaptureV1, error) {
	if s == nil || s.transaction == nil || s.transaction.VerifyLiveRoot() != nil || len(input.ManifestIdentity.Artifacts) != 0 || !input.ManifestIdentity.validIdentity() || !backupKeyVersion.MatchString(input.KeyVersion) || !platformBackupCaptureInputValid(input) {
		return PlatformBackupJournalCaptureV1{}, ErrPlatformBackupLocal
	}
	// openAccepted fully hashes the dump before text publication; close errors
	// are treated as a failed source proof.
	dump, err := s.openAccepted(platformBackupLocalControlPlaneDump, input.DumpEvidence.Size, input.DumpEvidence.SHA256)
	if err != nil || dump.Close() != nil {
		return PlatformBackupJournalCaptureV1{}, ErrPlatformBackupLocal
	}
	text, err := platformBackupCaptureText(input)
	if err != nil {
		return PlatformBackupJournalCaptureV1{}, ErrPlatformBackupLocal
	}
	manifest := input.ManifestIdentity
	manifest.Artifacts = make([]PlatformBackupArtifactV1, 0, len(platformBackupLocalMembers))
	for _, member := range platformBackupLocalMembers {
		var evidence SnapshotEvidence
		if member.leaf == platformBackupLocalControlPlaneDump {
			evidence = input.DumpEvidence
		} else {
			body := text[member.path]
			evidence = SnapshotEvidence{SHA256: platformBackupLocalSHA(body), Size: int64(len(body))}
		}
		manifest.Artifacts = append(manifest.Artifacts, PlatformBackupArtifactV1{Path: member.path, SHA256: evidence.SHA256, Size: evidence.Size, Mode: platformBackupV3Mode})
	}
	if manifest.Validate() != nil || ValidatePlatformBackupFacts(manifest, text) != nil || !platformBackupLocalKeyReferenceMatches(text["facts/key-references.json"], input.KeyVersion) {
		return PlatformBackupJournalCaptureV1{}, ErrPlatformBackupLocal
	}
	capture := PlatformBackupJournalCaptureV1{Manifest: manifest, KeyVersion: input.KeyVersion}
	if !platformBackupCaptureValid(capture) {
		return PlatformBackupJournalCaptureV1{}, ErrPlatformBackupLocal
	}
	for _, member := range platformBackupLocalMembers {
		if member.leaf == platformBackupLocalControlPlaneDump {
			continue
		}
		if err := s.publishCaptureText(member.leaf, text[member.path]); err != nil {
			return PlatformBackupJournalCaptureV1{}, ErrPlatformBackupLocal
		}
	}
	readers, err := s.openCaptureMembers(capture)
	if err != nil || closePlatformBackupReaders(readers) != nil {
		return PlatformBackupJournalCaptureV1{}, ErrPlatformBackupLocal
	}
	return capture, nil
}

func platformBackupCaptureInputValid(input platformBackupCaptureFilesInput) bool {
	facts := input.DatabaseFacts
	if !validSHA(input.DumpEvidence.SHA256) || input.DumpEvidence.Size <= 0 || facts.DatabaseSnapshotSHA256 != input.ManifestIdentity.DatabaseSnapshotSHA256 || input.Release.Validate() != nil || input.Release.DatabaseSnapshotSHA256 != input.ManifestIdentity.DatabaseSnapshotSHA256 || input.Release.Activation.ActivationID != input.ManifestIdentity.SourceActivationID || input.Release.Activation.ActivationJSONSHA256 != input.ManifestIdentity.SourceActivationJSONSHA256 || input.Release.Release != input.ManifestIdentity.SourceRelease || input.Release.Database.DatabaseV1 != input.ManifestIdentity.SourceDatabase {
		return false
	}
	database, err := facts.ReleaseDatabase()
	if err != nil || database != input.Release.Database || database.DatabaseV1 != input.ManifestIdentity.SourceDatabase {
		return false
	}
	localKeys := 0
	for _, key := range facts.KeyReferences.References {
		if key.Provider == "local-backup-key" {
			localKeys++
			if key.Revoked || key.KeyVersion != input.KeyVersion || key.KeyID != "backup-encryption" {
				return false
			}
		}
	}
	return localKeys == 1
}

func platformBackupLocalKeyReferenceMatches(raw []byte, keyVersion string) bool {
	keys, err := ParsePlatformBackupKeyReferencesV1(raw)
	if err != nil || !backupKeyVersion.MatchString(keyVersion) {
		return false
	}
	matched := 0
	for _, ref := range keys.References {
		if ref.Provider == "local-backup-key" && !ref.Revoked {
			if ref.KeyID != "backup-encryption" || ref.KeyVersion != keyVersion {
				return false
			}
			matched++
		}
	}
	return matched == 1
}

func platformBackupCaptureText(input platformBackupCaptureFilesInput) (map[string][]byte, error) {
	caddyfile := append([]byte(nil), input.Caddyfile...)
	edgeCaddyfile := append([]byte(nil), input.EdgeCaddyfile...)
	runtime, err := MarshalPlatformBackupRuntimeConfigV1(input.Runtime)
	if err != nil {
		return nil, ErrPlatformBackupLocal
	}
	release, err := MarshalPlatformBackupReleaseV1(input.Release)
	if err != nil {
		return nil, ErrPlatformBackupLocal
	}
	facts := input.DatabaseFacts
	routes, routesErr := MarshalPlatformBackupRoutesV1(facts.Routes)
	audit, auditErr := MarshalPlatformBackupAuditV1(facts.Audit)
	keys, keysErr := MarshalPlatformBackupKeyReferencesV1(facts.KeyReferences)
	tasks, tasksErr := MarshalPlatformBackupTasksOutboxV1(facts.TasksOutbox)
	tls, tlsErr := MarshalPlatformBackupTLSV1(facts.TLS)
	if routesErr != nil || auditErr != nil || keysErr != nil || tasksErr != nil || tlsErr != nil || !validPlatformBackupText("config/Caddyfile", caddyfile) || !validPlatformBackupText("config/open-card-edge.Caddyfile", edgeCaddyfile) {
		return nil, ErrPlatformBackupLocal
	}
	return map[string][]byte{
		"config/Caddyfile":                caddyfile,
		"config/open-card-edge.Caddyfile": edgeCaddyfile,
		"config/runtime.json":             runtime,
		"edge/tls.json":                   tls,
		"facts/audit.json":                audit,
		"facts/key-references.json":       keys,
		"facts/release.json":              release,
		"facts/routes.json":               routes,
		"facts/tasks-outbox.json":         tasks,
	}, nil
}

func (s *platformBackupLocalStore) publishCaptureText(leaf platformBackupLocalLeaf, body []byte) error {
	spec, ok := platformBackupLocalSpec(leaf)
	if !ok || !spec.accepted || !spec.plaintext || len(body) == 0 || int64(len(body)) > spec.maxSize || s.transaction.VerifyLiveRoot() != nil {
		return ErrPlatformBackupLocal
	}
	err := s.transaction.CreateMetadata(spec.name, body)
	if err != nil && !errors.Is(err, os.ErrExist) && !errors.Is(err, ErrDurableCommitUnknown) {
		return ErrPlatformBackupLocal
	}
	stored, readErr := s.transaction.ReadMetadata(spec.name)
	if readErr != nil || !bytes.Equal(stored, body) {
		return ErrPlatformBackupLocal
	}
	return nil
}

func (s *platformBackupLocalStore) buildPackage(capture PlatformBackupJournalCaptureV1) (PlatformBackupJournalPackageV1, error) {
	if s == nil || s.transaction == nil || s.transaction.VerifyLiveRoot() != nil || !platformBackupCaptureValid(capture) || s.captureKeyReferenceValid(capture) != nil {
		return PlatformBackupJournalPackageV1{}, ErrPlatformBackupLocal
	}
	if _, err := s.transaction.ops.Lstat("package.tar"); err == nil {
		return s.packageEvidence(capture)
	} else if !errors.Is(err, os.ErrNotExist) {
		return PlatformBackupJournalPackageV1{}, ErrPlatformBackupLocal
	}
	if err := s.removePackagePartial(); err != nil {
		return PlatformBackupJournalPackageV1{}, ErrPlatformBackupLocal
	}
	sources, err := s.openCaptureMembers(capture)
	if err != nil {
		return PlatformBackupJournalPackageV1{}, ErrPlatformBackupLocal
	}
	return s.buildPackageFromSources(capture, sources)
}

// buildPackageFromSources is a narrow test seam around the two-pass package
// builder. It owns and closes every supplied source on all outcomes.
func (s *platformBackupLocalStore) buildPackageFromSources(capture PlatformBackupJournalCaptureV1, sources []platformBackupLocalReadSeeker) (PlatformBackupJournalPackageV1, error) {
	if s == nil || s.transaction == nil || s.transaction.VerifyLiveRoot() != nil || !platformBackupCaptureValid(capture) || s.captureKeyReferenceValid(capture) != nil || len(sources) != len(platformBackupLocalMembers) {
		_ = closePlatformBackupReaders(sources)
		return PlatformBackupJournalPackageV1{}, ErrPlatformBackupLocal
	}
	for _, source := range sources {
		if source == nil {
			_ = closePlatformBackupReaders(sources)
			return PlatformBackupJournalPackageV1{}, ErrPlatformBackupLocal
		}
	}
	candidate, err := s.beginStream(platformBackupLocalPackagePartial, platformBackupLocalPackage)
	if err != nil {
		_ = closePlatformBackupReaders(sources)
		return PlatformBackupJournalPackageV1{}, ErrPlatformBackupLocal
	}
	sink := &platformBackupLocalPackageSink{candidate: candidate, capture: capture}
	input := PlatformBackupPackageInput{Manifest: capture.Manifest, Artifacts: make([]PlatformBackupArtifactSource, len(sources))}
	for i, source := range sources {
		input.Artifacts[i] = PlatformBackupArtifactSource{Path: platformBackupLocalMembers[i].path, Source: source, Size: capture.Manifest.Artifacts[i].Size, Mode: platformBackupV3Mode}
	}
	buildErr := BuildPlatformBackupV3Package(sink, input)
	closeErr := closePlatformBackupReaders(sources)
	if buildErr != nil || closeErr != nil {
		return PlatformBackupJournalPackageV1{}, ErrPlatformBackupLocal
	}
	return s.packageEvidence(capture)
}

func (s *platformBackupLocalStore) removePackagePartial() error {
	spec, _ := platformBackupLocalSpec(platformBackupLocalPackagePartial)
	if s.transaction.VerifyLiveRoot() != nil {
		return ErrPlatformBackupLocal
	}
	_, err := s.transaction.ops.Lstat(spec.name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || s.removeUncommitted(platformBackupLocalPackagePartial) != nil {
		return ErrPlatformBackupLocal
	}
	return nil
}

type platformBackupLocalPackageSink struct {
	candidate *platformBackupLocalCandidate
	capture   PlatformBackupJournalCaptureV1
}

func (s *platformBackupLocalPackageSink) Open() (io.Writer, error) {
	if s == nil || s.candidate == nil {
		return nil, ErrPlatformBackupLocal
	}
	return s.candidate, nil
}
func (s *platformBackupLocalPackageSink) Abort() {
	if s != nil && s.candidate != nil {
		_ = s.candidate.Abort()
	}
}
func (s *platformBackupLocalPackageSink) Commit() error {
	if s == nil || s.candidate == nil {
		return ErrPlatformBackupLocal
	}
	return s.candidate.Commit(func(source io.ReadSeeker) error {
		manifest, evidence, err := platformBackupPackageReadEvidence(source)
		if err != nil || !platformBackupManifestEqual(manifest, s.capture.Manifest) || evidence.Size <= 0 || !validSHA(evidence.SHA256) {
			return ErrPlatformBackupLocal
		}
		return nil
	})
}

func (s *platformBackupLocalStore) packageEvidence(capture PlatformBackupJournalCaptureV1) (PlatformBackupJournalPackageV1, error) {
	spec, _ := platformBackupLocalSpec(platformBackupLocalPackage)
	file, err := s.openSecure(spec, os.O_RDONLY)
	if err != nil {
		return PlatformBackupJournalPackageV1{}, ErrPlatformBackupLocal
	}
	info, statErr := s.transaction.ops.Stat(file)
	manifest := PlatformBackupV3{}
	evidence := SnapshotEvidence{}
	readErr := error(nil)
	if statErr != nil || !platformBackupLocalFileValid(info, s.transaction, spec.maxSize) || info.Size() <= 0 {
		readErr = ErrPlatformBackupLocal
	} else {
		manifest, evidence, readErr = platformBackupPackageReadEvidence(file)
	}
	closeErr := s.transaction.ops.CloseFile(file)
	if readErr != nil || closeErr != nil || s.transaction.VerifyLiveRoot() != nil || !platformBackupManifestEqual(manifest, capture.Manifest) {
		return PlatformBackupJournalPackageV1{}, ErrPlatformBackupLocal
	}
	manifestRaw, err := MarshalPlatformBackupV3(capture.Manifest)
	if err != nil {
		return PlatformBackupJournalPackageV1{}, ErrPlatformBackupLocal
	}
	return PlatformBackupJournalPackageV1{ManifestSHA256: platformBackupLocalSHA(manifestRaw), PackageSHA256: evidence.SHA256, PackageSize: evidence.Size}, nil
}

func platformBackupPackageReadEvidence(source io.ReadSeeker) (PlatformBackupV3, SnapshotEvidence, error) {
	if source == nil {
		return PlatformBackupV3{}, SnapshotEvidence{}, ErrPlatformBackupLocal
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return PlatformBackupV3{}, SnapshotEvidence{}, ErrPlatformBackupLocal
	}
	hash := sha256.New()
	size, err := io.Copy(hash, source)
	if err != nil || size <= 0 || size > PlatformBackupV3MaxPackageSize {
		return PlatformBackupV3{}, SnapshotEvidence{}, ErrPlatformBackupLocal
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return PlatformBackupV3{}, SnapshotEvidence{}, ErrPlatformBackupLocal
	}
	manifest, err := VerifyPlatformBackupV3Package(source, PlatformBackupDiscardSink{})
	if err != nil {
		return PlatformBackupV3{}, SnapshotEvidence{}, ErrPlatformBackupLocal
	}
	return manifest, SnapshotEvidence{SHA256: hex.EncodeToString(hash.Sum(nil)), Size: size}, nil
}

func (s *platformBackupLocalStore) openPackage(capture PlatformBackupJournalCaptureV1, evidence PlatformBackupJournalPackageV1) (platformBackupLocalReadSeeker, error) {
	if s == nil || s.transaction == nil || s.transaction.VerifyLiveRoot() != nil || !platformBackupCaptureValid(capture) || s.captureKeyReferenceValid(capture) != nil || evidence.ManifestSHA256 == "" || evidence.PackageSize <= 0 || !validSHA(evidence.PackageSHA256) {
		return nil, ErrPlatformBackupLocal
	}
	manifestRaw, err := MarshalPlatformBackupV3(capture.Manifest)
	if err != nil || evidence.ManifestSHA256 != platformBackupLocalSHA(manifestRaw) {
		return nil, ErrPlatformBackupLocal
	}
	reader, err := s.openAccepted(platformBackupLocalPackage, evidence.PackageSize, evidence.PackageSHA256)
	if err != nil {
		return nil, ErrPlatformBackupLocal
	}
	manifest, verifyErr := VerifyPlatformBackupV3Package(reader, PlatformBackupDiscardSink{})
	if verifyErr != nil || !platformBackupManifestEqual(manifest, capture.Manifest) {
		_ = reader.Close()
		return nil, ErrPlatformBackupLocal
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		_ = reader.Close()
		return nil, ErrPlatformBackupLocal
	}
	if s.transaction.VerifyLiveRoot() != nil {
		_ = reader.Close()
		return nil, ErrPlatformBackupLocal
	}
	return reader, nil
}

func (s *platformBackupLocalStore) openCaptureMembers(capture PlatformBackupJournalCaptureV1) ([]platformBackupLocalReadSeeker, error) {
	if !platformBackupCaptureValid(capture) || len(capture.Manifest.Artifacts) != len(platformBackupLocalMembers) {
		return nil, ErrPlatformBackupLocal
	}
	readers := make([]platformBackupLocalReadSeeker, 0, len(platformBackupLocalMembers))
	for i, member := range platformBackupLocalMembers {
		artifact := capture.Manifest.Artifacts[i]
		if artifact.Path != member.path || artifact.Mode != platformBackupV3Mode {
			_ = closePlatformBackupReaders(readers)
			return nil, ErrPlatformBackupLocal
		}
		reader, err := s.openAccepted(member.leaf, artifact.Size, artifact.SHA256)
		if err != nil {
			_ = closePlatformBackupReaders(readers)
			return nil, ErrPlatformBackupLocal
		}
		readers = append(readers, reader)
	}
	return readers, nil
}

func (s *platformBackupLocalStore) captureKeyReferenceValid(capture PlatformBackupJournalCaptureV1) error {
	if s == nil || s.transaction == nil || !platformBackupCaptureValid(capture) {
		return ErrPlatformBackupLocal
	}
	for _, artifact := range capture.Manifest.Artifacts {
		if artifact.Path != "facts/key-references.json" {
			continue
		}
		reader, err := s.openAccepted(platformBackupLocalFactsKeyReferencesJSON, artifact.Size, artifact.SHA256)
		if err != nil {
			return ErrPlatformBackupLocal
		}
		raw, readErr := io.ReadAll(io.LimitReader(reader, artifact.Size+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || int64(len(raw)) != artifact.Size || !platformBackupLocalKeyReferenceMatches(raw, capture.KeyVersion) {
			return ErrPlatformBackupLocal
		}
		return nil
	}
	return ErrPlatformBackupLocal
}

func closePlatformBackupReaders(readers []platformBackupLocalReadSeeker) error {
	failed := false
	for _, reader := range readers {
		if reader != nil && reader.Close() != nil {
			failed = true
		}
	}
	if failed {
		return ErrPlatformBackupLocal
	}
	return nil
}

func platformBackupManifestEqual(left, right PlatformBackupV3) bool {
	leftRaw, leftErr := MarshalPlatformBackupV3(left)
	rightRaw, rightErr := MarshalPlatformBackupV3(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func platformBackupLocalSHA(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func platformBackupCaptureValid(c PlatformBackupJournalCaptureV1) bool {
	return c.Manifest.Validate() == nil && backupKeyVersion.MatchString(c.KeyVersion)
}
