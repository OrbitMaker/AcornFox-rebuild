package domain

import (
	"errors"
	"strings"
	"time"
)

type SourceUploadKind string

const (
	SourceUploadArchive   SourceUploadKind = "archive"
	SourceUploadDirectory SourceUploadKind = "directory"
)

type SourceUploadStatus string

const (
	SourceUploadReady   SourceUploadStatus = "ready"
	SourceUploadClaimed SourceUploadStatus = "claimed"
	SourceUploadExpired SourceUploadStatus = "expired"
	SourceUploadFailed  SourceUploadStatus = "failed"
)

type SourceUploadFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	Digest string `json:"digest"`
}

type SourceUploadRecord struct {
	ID                   ID                 `json:"id"`
	Kind                 SourceUploadKind   `json:"kind"`
	Status               SourceUploadStatus `json:"status"`
	Digest               string             `json:"digest"`
	Bytes                int64              `json:"bytes"`
	FileCount            int                `json:"file_count"`
	StorageRef           string             `json:"-"`
	ExpiresAt            time.Time          `json:"expires_at"`
	ClaimedApplicationID ID                 `json:"claimed_application_id,omitempty"`
	ClaimedSourceID      ID                 `json:"claimed_source_revision_id,omitempty"`
	IdempotencyKey       string             `json:"-"`
	RequestDigest        string             `json:"-"`
	CreatedAt            time.Time          `json:"created_at"`
	UpdatedAt            time.Time          `json:"updated_at"`
	Files                []SourceUploadFile `json:"-"`
}

func (u SourceUploadRecord) Validate() error {
	if err := RequireID(u.ID, "source upload id"); err != nil {
		return err
	}
	if u.Kind != SourceUploadArchive && u.Kind != SourceUploadDirectory {
		return ValidationError("source upload kind is unsupported")
	}
	if u.Status != SourceUploadReady && u.Status != SourceUploadClaimed && u.Status != SourceUploadExpired && u.Status != SourceUploadFailed {
		return ValidationError("source upload status is unsupported")
	}
	if err := ValidateSourceUploadDigest(u.Digest); err != nil {
		return err
	}
	if u.Bytes < 0 || u.FileCount < 1 || len(u.Files) != u.FileCount {
		return ValidationError("source upload byte or file count is invalid")
	}
	if err := ValidateSourceUploadStorageRef(u.StorageRef, u.ID); err != nil {
		return err
	}
	if u.ExpiresAt.IsZero() || !u.ExpiresAt.After(u.CreatedAt) || u.UpdatedAt.Before(u.CreatedAt) {
		return ValidationError("source upload timestamps are invalid")
	}
	if strings.TrimSpace(u.IdempotencyKey) == "" || ValidateSourceUploadDigest(u.RequestDigest) != nil {
		return ValidationError("source upload idempotency identity is invalid")
	}
	if u.Status == SourceUploadClaimed {
		if u.ClaimedApplicationID.Empty() || u.ClaimedSourceID.Empty() {
			return ValidationError("claimed source upload requires application and source revision ids")
		}
	} else if !u.ClaimedApplicationID.Empty() || !u.ClaimedSourceID.Empty() {
		return ValidationError("unclaimed source upload cannot have claim facts")
	}
	seen := map[string]struct{}{}
	var total int64
	for _, file := range u.Files {
		if err := file.Validate(); err != nil {
			return err
		}
		if _, exists := seen[file.Path]; exists {
			return ValidationError("source upload file paths must be unique")
		}
		seen[file.Path] = struct{}{}
		total += file.Bytes
	}
	if total != u.Bytes {
		return ValidationError("source upload bytes do not match file manifest")
	}
	return nil
}

func (f SourceUploadFile) Validate() error {
	if _, err := NormalizeSourceUploadPath(f.Path); err != nil {
		return err
	}
	if f.Bytes < 0 {
		return ValidationError("source upload file bytes are invalid")
	}
	return ValidateSourceUploadDigest(f.Digest)
}

func ValidateSourceUploadDigest(value string) error {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return ValidationError("source upload digest is invalid")
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return ValidationError("source upload digest is invalid")
		}
	}
	return nil
}

func ValidateSourceUploadStorageRef(value string, id ID) error {
	if value != "upload://"+id.String() {
		return ValidationError("source upload storage reference is invalid")
	}
	return nil
}

// NormalizeSourceUploadPath intentionally accepts only ASCII, exact bytes and
// a small portable character set. It neither performs Unicode normalization
// nor case folding, so distinct client paths cannot silently alias each other.
func NormalizeSourceUploadPath(value string) (string, error) {
	if value == "" || len(value) > 512 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "\\") || strings.Contains(value, "//") || strings.ContainsRune(value, 0) {
		return "", ValidationError("source upload path is invalid")
	}
	for _, character := range value {
		if character > 0x7f {
			return "", ValidationError("source upload path must be ASCII")
		}
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && !strings.ContainsRune("._/@+ -", character) {
			return "", ValidationError("source upload path contains an unsafe character")
		}
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || strings.Contains(part, ":") {
			return "", ValidationError("source upload path contains an unsafe segment")
		}
	}
	return value, nil
}

var ErrSourceUploadClaimed = errors.New("source upload is already claimed")
