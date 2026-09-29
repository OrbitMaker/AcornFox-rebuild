//go:build !linux

package hosthelper

import (
	contracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/localpeer"
	"github.com/acornfox/acornfox/internal/packprotocol"
)

type StagedInventoryVerifier func(stagePath string, opID string, snap packprotocol.Selection, planSHA string, rawManifest []byte, expectedStageIdentity string, ownerUID int, ownerGID int) (*contracts.PackArtifactReceipt, error)

type ServerConfig struct {
	SocketPath               string
	StateDir                 string
	StageDir                 string
	PacksDir                 string
	PacksStateDir            string
	PacksRunDir              string
	ServiceTemplatePath      string
	TrustedCoreUID           uint32
	CoreGID                  uint32
	SocketGID                uint32
	TrustedCoreExecutableSHA string
	InstallationBinding      string
	Policies                 map[string]packprotocol.VerificationPolicy
	VerifyStagedInventory    StagedInventoryVerifier
	RuntimeBindingPath       string
	ReadOnlyPeerOnly         bool
}

type Server struct{}

func NewServer(cfg ServerConfig) (*Server, error) {
	return nil, localpeer.ErrUnsupportedPlatform
}

func (s *Server) Start() error {
	return localpeer.ErrUnsupportedPlatform
}

func (s *Server) Close() error {
	return nil
}
