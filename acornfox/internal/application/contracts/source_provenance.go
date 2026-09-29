package contracts

import (
	"fmt"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/foundation"
	"strings"
)

// AcornFoxPublicSourceProvenance is written only by a trusted public-git
// ingest path at the time that it accepts an immutable source revision. It is
// deliberately separate from SourceRevision so historical locators cannot be
// upgraded into public URLs after the fact.
type AcornFoxPublicSourceProvenance struct {
	SourceRevisionID domain.ID
	RepositoryURL    string
}

func (p AcornFoxPublicSourceProvenance) Validate() error {
	if err := domain.RequireID(p.SourceRevisionID, "source revision id"); err != nil {
		return err
	}
	canonical, err := CanonicalAcornFoxPublicRepositoryURL(p.RepositoryURL)
	if err != nil || canonical != p.RepositoryURL {
		return fmt.Errorf("public repository URL is invalid")
	}
	return nil
}

// CanonicalAcornFoxPublicRepositoryURL is syntactic display safety only. Its
// caller must separately establish public visibility through trusted ingest
// provenance; HTTPS alone is never that proof.
func CanonicalAcornFoxPublicRepositoryURL(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("repository URL is invalid")
	}
	canonical, scheme, err := foundation.NormalizeGitLocator(value)
	if err != nil || scheme != foundation.GitHTTPS {
		return "", fmt.Errorf("repository URL is invalid")
	}
	return canonical, nil
}
