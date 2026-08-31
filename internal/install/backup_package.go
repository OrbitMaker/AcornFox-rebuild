package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	PlatformBackupV3Schema   = "open-card.platform-backup.v3"
	PlatformBackupV3Manifest = "package.json"

	PlatformBackupV3MaxTextMemberSize int64 = 1 << 20
	// Dumps are opaque backup plaintext and are streamed, never buffered.
	PlatformBackupV3MaxDumpSize    int64 = 1 << 40
	PlatformBackupV3MaxPackageSize       = PlatformBackupV3MaxDumpSize + 10*PlatformBackupV3MaxTextMemberSize + 15*512
	platformBackupV3Mode           int64 = 0o600
	platformBackupUSTARMaxSize     int64 = (1 << 33) - 1
)

var (
	// Fixed, path- and content-neutral error for every contract failure.
	ErrPlatformBackupPackage = errors.New("platform backup package validation failed")
	platformBackupV3Members  = []string{
		"config/Caddyfile", "config/open-card-edge.Caddyfile", "config/runtime.json", "database/control-plane.dump", "edge/tls.json",
		"facts/audit.json", "facts/key-references.json", "facts/release.json", "facts/routes.json", "facts/tasks-outbox.json",
	}
	// Defense in depth only: this is not proof against encoded secret material.
	// B2 typed capture/schema validation is required before production composition.
	platformBackupObviousSecret = regexp.MustCompile(`(?i)(-----begin [a-z0-9 ]*private key-----|postgres(?:ql)?://|\b(?:password|passwd|authorization|token|credential|access[_-]?key|secret[_-]?key|private[_-]?key|api[_-]?key|aws_secret_access_key|cos[_-]?(?:secret|key))\b\s*"?\s*[:=]|\bbearer\s+\S+|\bsession(?:[_-]?(?:id|token|key))?\b\s*"?\s*[:=])`)
)

// PlatformBackupV3 package content is sensitive plaintext quarantine because
// it includes a database dump. It MUST be independently encrypted before it
// leaves root-only staging.
type PlatformBackupV3 struct {
	Schema                     string    `json:"schema"`
	BackupID                   string    `json:"backup_id"`
	CreatedAt                  time.Time `json:"created_at"`
	Reason                     string    `json:"reason"`
	SourceInstallationIDSHA256 string    `json:"source_installation_id_sha256"`
	SourceActivationID         string    `json:"source_activation_id"`
	SourceActivationJSONSHA256 string    `json:"source_activation_json_sha256"`
	// DatabaseSnapshotSHA256 is the pg_export_snapshot producer assertion. It
	// is not the dump hash; B3 must recompute row digests after restore.
	DatabaseSnapshotSHA256 string                     `json:"database_snapshot_sha256"`
	SourceRelease          ReleaseV1                  `json:"source_release"`
	SourceDatabase         DatabaseV1                 `json:"source_database"`
	Artifacts              []PlatformBackupArtifactV1 `json:"artifacts"`
}

type PlatformBackupArtifactV1 struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   int64  `json:"mode"`
}

// A source must be rewindable: the first pass validates/hashes, and the second
// pass streams directly to the archive without loading a dump into memory.
type PlatformBackupArtifactSource struct {
	Path   string
	Source io.ReadSeeker
	Size   int64
	Mode   int64
}

type PlatformBackupPackageInput struct {
	Manifest  PlatformBackupV3
	Artifacts []PlatformBackupArtifactSource
}

// A sink receives candidates in quarantine. Abort is invoked on every parser
// failure; Commit happens only after canonical EOF and all checks pass.
type PlatformBackupQuarantineSink interface {
	OpenArtifact(PlatformBackupArtifactV1) (io.Writer, error)
	Abort()
	Commit() error
}

// PlatformBackupBuildSink owns the partially written archive quarantine. Open
// returns its sole writer; Abort must remove or invalidate partial output.
// Commit is called only after the complete canonical archive terminator.
type PlatformBackupBuildSink interface {
	Open() (io.Writer, error)
	Abort()
	Commit() error
}

type PlatformBackupDiscardSink struct{}

func (PlatformBackupDiscardSink) OpenArtifact(PlatformBackupArtifactV1) (io.Writer, error) {
	return io.Discard, nil
}
func (PlatformBackupDiscardSink) Abort()        {}
func (PlatformBackupDiscardSink) Commit() error { return nil }

// Key references contain only opaque, sorted selectors—not key material.
type PlatformBackupKeyReferenceV1 struct {
	Provider   string `json:"provider"`
	KeyID      string `json:"key_id"`
	KeyVersion string `json:"key_version"`
	Revoked    bool   `json:"revoked"`
}
type PlatformBackupKeyReferencesV1 struct {
	SchemaVersion          int                            `json:"schema_version"`
	DatabaseSnapshotSHA256 string                         `json:"database_snapshot_sha256"`
	References             []PlatformBackupKeyReferenceV1 `json:"references"`
}

func (a PlatformBackupArtifactV1) valid() bool {
	return platformBackupMember(a.Path) && validSHA(a.SHA256) && a.Size > 0 && a.Size <= platformBackupMemberLimit(a.Path) && a.Mode == platformBackupV3Mode
}
func (m PlatformBackupV3) validIdentity() bool {
	return m.Schema == PlatformBackupV3Schema && validBackupID(m.BackupID) && !m.CreatedAt.IsZero() && m.CreatedAt.Location() == time.UTC && validBackupReason(m.Reason) && validSHA(m.SourceInstallationIDSHA256) && validID(m.SourceActivationID) && validSHA(m.SourceActivationJSONSHA256) && validSHA(m.DatabaseSnapshotSHA256) && m.SourceRelease.valid() && m.SourceDatabase.valid()
}
func (m PlatformBackupV3) Validate() error {
	if !m.validIdentity() || len(m.Artifacts) != len(platformBackupV3Members) {
		return ErrPlatformBackupPackage
	}
	for i, path := range platformBackupV3Members {
		if m.Artifacts[i].Path != path || !m.Artifacts[i].valid() {
			return ErrPlatformBackupPackage
		}
	}
	return nil
}
func (r PlatformBackupKeyReferenceV1) valid() bool {
	return (r.Provider == "control-plane-secret" || r.Provider == "local-backup-key") && validID(r.KeyID) && validID(r.KeyVersion)
}
func keyRefLess(left, right PlatformBackupKeyReferenceV1) bool {
	if left.Provider != right.Provider {
		return left.Provider < right.Provider
	}
	if left.KeyID != right.KeyID {
		return left.KeyID < right.KeyID
	}
	return left.KeyVersion < right.KeyVersion
}
func (r PlatformBackupKeyReferencesV1) Validate() error {
	if r.SchemaVersion != 1 || !validSHA(r.DatabaseSnapshotSHA256) || len(r.References) > 128 {
		return ErrPlatformBackupPackage
	}
	for i, ref := range r.References {
		if !ref.valid() || i > 0 && !keyRefLess(r.References[i-1], ref) {
			return ErrPlatformBackupPackage
		}
	}
	return nil
}
func MarshalPlatformBackupKeyReferencesV1(value PlatformBackupKeyReferencesV1) ([]byte, error) {
	if value.Validate() != nil {
		return nil, ErrPlatformBackupPackage
	}
	return json.Marshal(value)
}
func ParsePlatformBackupKeyReferencesV1(raw []byte) (PlatformBackupKeyReferencesV1, error) {
	var value PlatformBackupKeyReferencesV1
	if decodeStrict(raw, &value) != nil || requireStrictFields(raw, []string{"schema_version", "database_snapshot_sha256", "references"}) != nil || value.Validate() != nil || !platformBackupKeyReferenceFields(raw) {
		return PlatformBackupKeyReferencesV1{}, ErrPlatformBackupPackage
	}
	canonical, err := MarshalPlatformBackupKeyReferencesV1(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return PlatformBackupKeyReferencesV1{}, ErrPlatformBackupPackage
	}
	return value, nil
}
func platformBackupKeyReferenceFields(raw []byte) bool {
	var value struct {
		References []json.RawMessage `json:"references"`
	}
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	for _, item := range value.References {
		if requireStrictFields(item, []string{"provider", "key_id", "key_version", "revoked"}) != nil {
			return false
		}
	}
	return true
}
func MarshalPlatformBackupV3(value PlatformBackupV3) ([]byte, error) {
	if value.Validate() != nil {
		return nil, ErrPlatformBackupPackage
	}
	return json.Marshal(value)
}
func ParsePlatformBackupV3(raw []byte) (PlatformBackupV3, error) {
	var value PlatformBackupV3
	if decodeStrict(raw, &value) != nil || requireStrictFields(raw, []string{"schema", "backup_id", "created_at", "reason", "source_installation_id_sha256", "source_activation_id", "source_activation_json_sha256", "database_snapshot_sha256", "source_release", "source_database", "artifacts"}) != nil || value.Validate() != nil {
		return PlatformBackupV3{}, ErrPlatformBackupPackage
	}
	canonical, err := MarshalPlatformBackupV3(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return PlatformBackupV3{}, ErrPlatformBackupPackage
	}
	return value, nil
}

// BuildPlatformBackupV3Package is the production streaming writer API. sink
// owns partial-output cleanup; it is aborted on every failure, including a
// changed second-pass source, write failure, or commit failure.
func BuildPlatformBackupV3Package(sink PlatformBackupBuildSink, input PlatformBackupPackageInput) (err error) {
	if sink == nil {
		return ErrPlatformBackupPackage
	}
	accepted := false
	defer func() {
		if !accepted {
			sink.Abort()
			err = ErrPlatformBackupPackage
		}
	}()
	if !input.Manifest.validIdentity() || len(input.Artifacts) != len(platformBackupV3Members) {
		return ErrPlatformBackupPackage
	}
	artifacts := append([]PlatformBackupArtifactSource(nil), input.Artifacts...)
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	manifest := input.Manifest
	manifest.Artifacts = make([]PlatformBackupArtifactV1, len(artifacts))
	textMembers := make(map[string][]byte, len(artifacts))
	for i, artifact := range artifacts {
		if artifact.Path != platformBackupV3Members[i] || artifact.Source == nil || artifact.Size <= 0 || artifact.Size > platformBackupMemberLimit(artifact.Path) || artifact.Mode != platformBackupV3Mode {
			return ErrPlatformBackupPackage
		}
		digest, err := platformBackupSourcePass(artifact.Source, artifact.Size, nil, artifact.Path)
		if err != nil {
			return ErrPlatformBackupPackage
		}
		manifest.Artifacts[i] = PlatformBackupArtifactV1{Path: artifact.Path, SHA256: digest, Size: artifact.Size, Mode: artifact.Mode}
		if artifact.Path != "database/control-plane.dump" {
			text, textErr := platformBackupArtifactText(artifact.Source, artifact.Size, artifact.Path)
			if textErr != nil {
				return ErrPlatformBackupPackage
			}
			textMembers[artifact.Path] = text
		}
	}
	if manifest.Validate() != nil {
		return ErrPlatformBackupPackage
	}
	manifestRaw, err := MarshalPlatformBackupV3(manifest)
	if err != nil || !validPlatformBackupText(PlatformBackupV3Manifest, manifestRaw) || !platformBackupArchiveSizeOK(int64(len(manifestRaw)), manifest.Artifacts) {
		return ErrPlatformBackupPackage
	}
	if ValidatePlatformBackupFacts(manifest, textMembers) != nil {
		return ErrPlatformBackupPackage
	}
	destination, err := sink.Open()
	if err != nil || destination == nil {
		return ErrPlatformBackupPackage
	}
	if err := platformBackupWriteBytesMember(destination, PlatformBackupV3Manifest, manifestRaw); err != nil {
		return ErrPlatformBackupPackage
	}
	for i, artifact := range artifacts {
		if _, err := artifact.Source.Seek(0, io.SeekStart); err != nil {
			return ErrPlatformBackupPackage
		}
		if err := platformBackupWriteSourceMember(destination, artifact, manifest.Artifacts[i].SHA256); err != nil {
			return ErrPlatformBackupPackage
		}
	}
	if platformBackupWriteAll(destination, make([]byte, 1024)) != nil {
		return ErrPlatformBackupPackage
	}
	if sink.Commit() != nil {
		return ErrPlatformBackupPackage
	}
	accepted = true
	return nil
}

// VerifyPlatformBackupV3Package is the production streaming verifier API.
func VerifyPlatformBackupV3Package(source io.Reader, sink PlatformBackupQuarantineSink) (manifest PlatformBackupV3, err error) {
	if source == nil || sink == nil {
		return PlatformBackupV3{}, ErrPlatformBackupPackage
	}
	accepted := false
	defer func() {
		if !accepted {
			sink.Abort()
			manifest = PlatformBackupV3{}
			err = ErrPlatformBackupPackage
		}
	}()
	block, err := platformBackupReadBlock(source)
	if err != nil {
		return PlatformBackupV3{}, ErrPlatformBackupPackage
	}
	size, ok := platformBackupHeaderSize(block)
	if !ok || size > PlatformBackupV3MaxTextMemberSize || !platformBackupHeaderMatches(block, PlatformBackupV3Manifest, size, platformBackupV3Mode) {
		return PlatformBackupV3{}, ErrPlatformBackupPackage
	}
	manifestData, err := platformBackupReadData(source, size, nil, PlatformBackupV3Manifest)
	if err != nil || !validPlatformBackupText(PlatformBackupV3Manifest, manifestData.text) || !platformBackupReadPadding(source, size) {
		return PlatformBackupV3{}, ErrPlatformBackupPackage
	}
	manifest, err = ParsePlatformBackupV3(manifestData.text)
	if err != nil || !platformBackupArchiveSizeOK(size, manifest.Artifacts) {
		return PlatformBackupV3{}, ErrPlatformBackupPackage
	}
	textMembers := make(map[string][]byte, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		if !platformBackupReadCanonicalHeaders(source, artifact.Path, artifact.Size, artifact.Mode) {
			return PlatformBackupV3{}, ErrPlatformBackupPackage
		}
		writer, openErr := sink.OpenArtifact(artifact)
		if openErr != nil || writer == nil {
			return PlatformBackupV3{}, ErrPlatformBackupPackage
		}
		data, err := platformBackupReadData(source, artifact.Size, writer, artifact.Path)
		if err != nil || !platformBackupReadPadding(source, artifact.Size) {
			return PlatformBackupV3{}, ErrPlatformBackupPackage
		}
		if hex.EncodeToString(data.hashBytes) != artifact.SHA256 || data.text != nil && !validPlatformBackupText(artifact.Path, data.text) {
			return PlatformBackupV3{}, ErrPlatformBackupPackage
		}
		if data.text != nil {
			textMembers[artifact.Path] = data.text
		}
	}
	end, err := platformBackupReadExact(source, 1024)
	if err != nil || !bytes.Equal(end, make([]byte, 1024)) {
		return PlatformBackupV3{}, ErrPlatformBackupPackage
	}
	var trailing [1]byte
	if count, readErr := source.Read(trailing[:]); count != 0 || readErr != io.EOF {
		return PlatformBackupV3{}, ErrPlatformBackupPackage
	}
	if ValidatePlatformBackupFacts(manifest, textMembers) != nil {
		return PlatformBackupV3{}, ErrPlatformBackupPackage
	}
	if sink.Commit() != nil {
		return PlatformBackupV3{}, ErrPlatformBackupPackage
	}
	accepted = true
	return manifest, nil
}

// ParsePlatformBackupV3Package is the streaming parser spelling retained for
// callers that prefer Parse naming; it has the same quarantine lifecycle.
func ParsePlatformBackupV3Package(source io.Reader, sink PlatformBackupQuarantineSink) (PlatformBackupV3, error) {
	return VerifyPlatformBackupV3Package(source, sink)
}

func platformBackupMember(path string) bool {
	index := sort.SearchStrings(platformBackupV3Members, path)
	return index < len(platformBackupV3Members) && platformBackupV3Members[index] == path
}
func platformBackupMemberLimit(path string) int64 {
	if path == "database/control-plane.dump" {
		return PlatformBackupV3MaxDumpSize
	}
	return PlatformBackupV3MaxTextMemberSize
}
func platformBackupHeaderBlock(name string, size, mode int64) ([]byte, error) {
	if size <= 0 || size > platformBackupMemberLimit(name) || mode != platformBackupV3Mode {
		return nil, ErrPlatformBackupPackage
	}
	if size <= platformBackupUSTARMaxSize {
		return platformBackupUSTARHeader(name, size, mode, 0)
	}
	pax := platformBackupPAXSizeRecord(size)
	paxName := "PaxHeaders.0/" + strings.ReplaceAll(name, "/", ".")
	paxHeader, err := platformBackupUSTARHeader(paxName, int64(len(pax)), mode, 'x')
	if err != nil {
		return nil, ErrPlatformBackupPackage
	}
	memberHeader, err := platformBackupUSTARHeader(name, 0, mode, 0)
	if err != nil {
		return nil, ErrPlatformBackupPackage
	}
	return append(append(append(paxHeader, pax...), make([]byte, platformBackupPadding(int64(len(pax))))...), memberHeader...), nil
}
func platformBackupPAXSizeRecord(size int64) []byte {
	base := " size=" + strconv.FormatInt(size, 10) + "\n"
	for width := 1; ; width++ {
		record := strconv.Itoa(len(base)+width) + base
		if len(record) == len(base)+width {
			return []byte(record)
		}
	}
}
func platformBackupUSTARHeader(name string, size, mode int64, typeFlag byte) ([]byte, error) {
	if len(name) == 0 || len(name) > 100 || size < 0 || size > platformBackupUSTARMaxSize || mode != platformBackupV3Mode {
		return nil, ErrPlatformBackupPackage
	}
	block := make([]byte, 512)
	copy(block[:100], name)
	if !platformBackupPutOctal(block[100:108], mode, 7) || !platformBackupPutOctal(block[108:116], 0, 7) || !platformBackupPutOctal(block[116:124], 0, 7) || !platformBackupPutOctal(block[124:136], size, 11) || !platformBackupPutOctal(block[136:148], 0, 11) {
		return nil, ErrPlatformBackupPackage
	}
	for i := 148; i < 156; i++ {
		block[i] = ' '
	}
	block[156] = typeFlag
	copy(block[257:263], "ustar\x00")
	copy(block[263:265], "00")
	sum := 0
	for _, value := range block {
		sum += int(value)
	}
	if !platformBackupPutChecksum(block[148:156], sum) {
		return nil, ErrPlatformBackupPackage
	}
	return block, nil
}
func platformBackupPutOctal(field []byte, value int64, digits int) bool {
	if value < 0 || digits+1 != len(field) {
		return false
	}
	for index := digits - 1; index >= 0; index-- {
		field[index] = byte('0' + value%8)
		value /= 8
	}
	if value != 0 {
		return false
	}
	field[digits] = 0
	return true
}
func platformBackupPutChecksum(field []byte, sum int) bool {
	if len(field) != 8 || sum < 0 || sum > 0o777777 {
		return false
	}
	for index := 5; index >= 0; index-- {
		field[index] = byte('0' + sum%8)
		sum /= 8
	}
	field[6], field[7] = 0, ' '
	return sum == 0
}
func platformBackupHeaderMatches(block []byte, name string, size, mode int64) bool {
	expected, err := platformBackupHeaderBlock(name, size, mode)
	return err == nil && bytes.Equal(block, expected)
}
func platformBackupReadCanonicalHeaders(source io.Reader, name string, size, mode int64) bool {
	expected, err := platformBackupHeaderBlock(name, size, mode)
	if err != nil {
		return false
	}
	actual, err := platformBackupReadExact(source, len(expected))
	return err == nil && bytes.Equal(actual, expected)
}
func platformBackupHeaderSize(block []byte) (int64, bool) {
	if len(block) != 512 {
		return 0, false
	}
	value := int64(0)
	seen := false
	for _, char := range block[124:136] {
		if char == 0 || char == ' ' {
			continue
		}
		if char < '0' || char > '7' || value > (1<<60)/8 {
			return 0, false
		}
		seen = true
		value = value*8 + int64(char-'0')
	}
	return value, seen && value > 0
}
func platformBackupPadding(size int64) int { return int((512 - size%512) % 512) }
func platformBackupWriteAll(destination io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := destination.Write(data)
		if n < 0 || n > len(data) || n == 0 && err == nil {
			return ErrPlatformBackupPackage
		}
		data = data[n:]
		if err != nil {
			return ErrPlatformBackupPackage
		}
	}
	return nil
}
func platformBackupWriteBytesMember(destination io.Writer, path string, data []byte) error {
	header, err := platformBackupHeaderBlock(path, int64(len(data)), platformBackupV3Mode)
	if err != nil || platformBackupWriteAll(destination, header) != nil || platformBackupWriteAll(destination, data) != nil {
		return ErrPlatformBackupPackage
	}
	return platformBackupWriteAll(destination, make([]byte, platformBackupPadding(int64(len(data)))))
}
func platformBackupWriteSourceMember(destination io.Writer, artifact PlatformBackupArtifactSource, expectedSHA string) error {
	header, err := platformBackupHeaderBlock(artifact.Path, artifact.Size, artifact.Mode)
	if err != nil || platformBackupWriteAll(destination, header) != nil {
		return ErrPlatformBackupPackage
	}
	digest, err := platformBackupSourcePass(artifact.Source, artifact.Size, destination, artifact.Path)
	if err != nil || digest != expectedSHA {
		return ErrPlatformBackupPackage
	}
	return platformBackupWriteAll(destination, make([]byte, platformBackupPadding(artifact.Size)))
}
func platformBackupSourcePass(source io.ReadSeeker, size int64, destination io.Writer, path string) (string, error) {
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return "", ErrPlatformBackupPackage
	}
	hash := sha256.New()
	var text bytes.Buffer
	writers := []io.Writer{hash}
	if destination != nil {
		writers = append(writers, destination)
	}
	if path != "database/control-plane.dump" {
		writers = append(writers, &text)
	}
	if copied, err := io.CopyN(io.MultiWriter(writers...), source, size); err != nil || copied != size {
		return "", ErrPlatformBackupPackage
	}
	var extra [1]byte
	if n, err := source.Read(extra[:]); n != 0 || err != io.EOF {
		return "", ErrPlatformBackupPackage
	}
	if path != "database/control-plane.dump" && !validPlatformBackupText(path, text.Bytes()) {
		return "", ErrPlatformBackupPackage
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func validPlatformBackupText(path string, data []byte) bool {
	if len(data) == 0 || int64(len(data)) > PlatformBackupV3MaxTextMemberSize || platformBackupObviousSecret.Match(data) {
		return false
	}
	if strings.HasSuffix(path, ".json") {
		var value any
		if decodeStrict(data, &value) != nil {
			return false
		}
		if _, ok := value.(map[string]any); !ok {
			return false
		}
		return platformBackupParseTypedJSON(path, data)
	}
	return true
}

func platformBackupArtifactText(source io.ReadSeeker, size int64, path string) ([]byte, error) {
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return nil, ErrPlatformBackupPackage
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(source, data); err != nil {
		return nil, ErrPlatformBackupPackage
	}
	var extra [1]byte
	if n, err := source.Read(extra[:]); n != 0 || err != io.EOF || !validPlatformBackupText(path, data) {
		return nil, ErrPlatformBackupPackage
	}
	return data, nil
}

func platformBackupParseTypedJSON(path string, data []byte) bool {
	switch path {
	case PlatformBackupV3Manifest:
		_, err := ParsePlatformBackupV3(data)
		return err == nil
	case "config/runtime.json":
		_, err := ParsePlatformBackupRuntimeConfigV1(data)
		return err == nil
	case "edge/tls.json":
		_, err := ParsePlatformBackupTLSV1(data)
		return err == nil
	case "facts/audit.json":
		_, err := ParsePlatformBackupAuditV1(data)
		return err == nil
	case "facts/key-references.json":
		_, err := ParsePlatformBackupKeyReferencesV1(data)
		return err == nil
	case "facts/release.json":
		_, err := ParsePlatformBackupReleaseV1(data)
		return err == nil
	case "facts/routes.json":
		_, err := ParsePlatformBackupRoutesV1(data)
		return err == nil
	case "facts/tasks-outbox.json":
		_, err := ParsePlatformBackupTasksOutboxV1(data)
		return err == nil
	default:
		return false
	}
}
func platformBackupArchiveSizeOK(manifestSize int64, artifacts []PlatformBackupArtifactV1) bool {
	total := int64(1024)
	members := append([]PlatformBackupArtifactV1{{Path: PlatformBackupV3Manifest, Size: manifestSize, Mode: platformBackupV3Mode}}, artifacts...)
	for _, artifact := range members {
		member, ok := platformBackupMemberArchiveSize(artifact.Path, artifact.Size)
		if !ok || total > PlatformBackupV3MaxPackageSize-member {
			return false
		}
		total += member
	}
	return total <= PlatformBackupV3MaxPackageSize
}
func platformBackupMemberArchiveSize(path string, size int64) (int64, bool) {
	if size <= 0 || size > PlatformBackupV3MaxDumpSize || size > (1<<63-1024) {
		return 0, false
	}
	header, err := platformBackupHeaderBlock(path, size, platformBackupV3Mode)
	const maxInt64 = int64(^uint64(0) >> 1)
	padding := int64(platformBackupPadding(size))
	if err != nil || size > maxInt64-int64(len(header))-padding {
		return 0, false
	}
	return int64(len(header)) + size + padding, true
}
func platformBackupReadBlock(source io.Reader) ([]byte, error) {
	return platformBackupReadExact(source, 512)
}
func platformBackupReadExact(source io.Reader, size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := io.ReadFull(source, data)
	if err != nil {
		return nil, ErrPlatformBackupPackage
	}
	return data, nil
}
func platformBackupReadPadding(source io.Reader, size int64) bool {
	data, err := platformBackupReadExact(source, platformBackupPadding(size))
	return err == nil && bytes.Equal(data, make([]byte, len(data)))
}

type platformBackupReadResult struct {
	hashBytes []byte
	text      []byte
}

func platformBackupReadData(source io.Reader, size int64, destination io.Writer, path string) (platformBackupReadResult, error) {
	hash := sha256.New()
	var text bytes.Buffer
	writers := []io.Writer{hash}
	if destination != nil {
		writers = append(writers, destination)
	}
	if path != "database/control-plane.dump" {
		writers = append(writers, &text)
	}
	if copied, err := io.CopyN(io.MultiWriter(writers...), source, size); err != nil || copied != size {
		return platformBackupReadResult{}, ErrPlatformBackupPackage
	}
	result := platformBackupReadResult{hashBytes: hash.Sum(nil)}
	if path != "database/control-plane.dump" {
		result.text = text.Bytes()
	}
	return result, nil
}
