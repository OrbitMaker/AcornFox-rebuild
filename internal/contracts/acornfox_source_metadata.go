package contracts

import (
	"fmt"
	"strings"

	persistence "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
)

// AcornFoxAvailability communicates whether this narrowly-scoped façade can
// prove an answer from durable facts. It must never be inferred from a source
// locator: a syntactically valid HTTPS locator may still name a private host.
type AcornFoxAvailability string

const (
	AcornFoxAvailable   AcornFoxAvailability = "available"
	AcornFoxUnavailable AcornFoxAvailability = "unavailable"
)

type AcornFoxPublicSourceProvenance = persistence.AcornFoxPublicSourceProvenance

func CanonicalAcornFoxPublicRepositoryURL(raw string) (string, error) {
	return persistence.CanonicalAcornFoxPublicRepositoryURL(raw)
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
