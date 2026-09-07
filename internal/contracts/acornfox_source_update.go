package contracts

import (
	"fmt"
	"strings"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

type AcornFoxSourceUpdateStatus string

const AcornFoxSourceUpdateImported AcornFoxSourceUpdateStatus = "imported"

// AcornFoxSourceUpdateResult confirms only a new immutable source import. It
// does not create a build, release, deployment, runtime change, or route.
type AcornFoxSourceUpdateResult struct {
	SourceRevisionID domain.ID                  `json:"source_revision_id"`
	Status           AcornFoxSourceUpdateStatus `json:"status"`
}

func (r AcornFoxSourceUpdateResult) Validate() error {
	if err := domain.RequireID(r.SourceRevisionID, "source revision id"); err != nil || r.Status != AcornFoxSourceUpdateImported {
		return fmt.Errorf("source update result is invalid")
	}
	return nil
}

func NormalizeAcornFoxSourceUpdateRef(ref string) (string, error) {
	normalized, err := foundation.NormalizeGitRef(strings.TrimSpace(ref))
	if err != nil {
		return "", fmt.Errorf("source update ref is invalid")
	}
	return normalized, nil
}
