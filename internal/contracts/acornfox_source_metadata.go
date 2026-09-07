package contracts

import (
	"fmt"
	"strings"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

// AcornFoxAvailability communicates whether this narrowly-scoped façade can
// prove an answer from durable facts. It must never be inferred from a source
// locator: a syntactically valid HTTPS locator may still name a private host.
type AcornFoxAvailability string

const (
	AcornFoxAvailable   AcornFoxAvailability = "available"
	AcornFoxUnavailable AcornFoxAvailability = "unavailable"
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

// AcornFoxSourceMetadata is the dedicated source metadata response. Repository
// URL is absent unless explicit public-source provenance exists.
type AcornFoxSourceMetadata struct {
	SourceRevisionID domain.ID            `json:"source_revision_id"`
	Availability     AcornFoxAvailability `json:"availability"`
	RepositoryURL    string               `json:"repository_url,omitempty"`
}

func (m AcornFoxSourceMetadata) Validate() error {
	if err := domain.RequireID(m.SourceRevisionID, "source revision id"); err != nil {
		return err
	}
	switch m.Availability {
	case AcornFoxUnavailable:
		if m.RepositoryURL != "" {
			return fmt.Errorf("unavailable source metadata must not contain repository URL")
		}
	case AcornFoxAvailable:
		canonical, err := CanonicalAcornFoxPublicRepositoryURL(m.RepositoryURL)
		if err != nil || canonical != m.RepositoryURL {
			return fmt.Errorf("available source metadata requires canonical public repository URL")
		}
	default:
		return fmt.Errorf("source metadata availability is invalid")
	}
	return nil
}

// AcornFoxDeploymentSource is a deliberately all-or-unavailable projection.
// This prevents a historical deployment from leaking a commit or ref unless
// its exact release/build/source chain and public-source provenance agree.
type AcornFoxDeploymentSource struct {
	DeploymentID     domain.ID            `json:"deployment_id"`
	Availability     AcornFoxAvailability `json:"availability"`
	SourceRevisionID domain.ID            `json:"source_revision_id,omitempty"`
	Commit           string               `json:"commit,omitempty"`
	Ref              string               `json:"ref,omitempty"`
	RepositoryURL    string               `json:"repository_url,omitempty"`
}

func (m AcornFoxDeploymentSource) Validate() error {
	if err := domain.RequireID(m.DeploymentID, "deployment id"); err != nil {
		return err
	}
	switch m.Availability {
	case AcornFoxUnavailable:
		if !m.SourceRevisionID.Empty() || m.Commit != "" || m.Ref != "" || m.RepositoryURL != "" {
			return fmt.Errorf("unavailable deployment source must not contain source fields")
		}
	case AcornFoxAvailable:
		if err := domain.RequireID(m.SourceRevisionID, "source revision id"); err != nil {
			return err
		}
		canonical, err := CanonicalAcornFoxPublicRepositoryURL(m.RepositoryURL)
		if err != nil || canonical != m.RepositoryURL || strings.TrimSpace(m.Commit) == "" || strings.TrimSpace(m.Ref) == "" {
			return fmt.Errorf("available deployment source is incomplete")
		}
	default:
		return fmt.Errorf("deployment source availability is invalid")
	}
	return nil
}
