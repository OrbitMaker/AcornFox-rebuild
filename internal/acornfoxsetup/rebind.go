package acornfoxsetup

import (
	"bytes"
	"github.com/open-card/open-card/internal/providers/acornfoxroute"
	"slices"
)

// RebindVersion preserves a validated runtime's identities and configuration,
// replacing only its version binding. The returned files and resolver list do
// not share mutable storage with the caller. No files are written.
func RebindVersion(bundle Bundle, input Inputs, nextVersion string) (Bundle, Inputs, error) {
	if err := ValidateExistingRuntime(bundle, input); err != nil {
		return Bundle{}, Inputs{}, err
	}
	nextInput := input
	nextInput.Version = nextVersion
	nextInput.ResolverEndpoints = slices.Clone(input.ResolverEndpoints)
	nextBundle := Bundle{Files: slices.Clone(bundle.Files)}
	var serial string
	for i := range nextBundle.Files {
		f := &nextBundle.Files[i]
		f.Data = bytes.Clone(f.Data)
		if f.Path == RuntimeDirectory+"/agent.crt" {
			agent, err := parseCertificate(f.Data)
			if err != nil {
				return Bundle{}, Inputs{}, errInvalid
			}
			serial = agent.SerialNumber.String()
		}
	}
	for i := range nextBundle.Files {
		f := &nextBundle.Files[i]
		switch f.Path {
		case ServerEnvironment:
			f.Data = serverEnv(nextInput, serial)
		case AgentEnvironment:
			f.Data = agentEnv(nextInput)
		}
	}
	if err := ValidateExistingRuntime(nextBundle, nextInput); err != nil {
		return Bundle{}, Inputs{}, err
	}
	return nextBundle, nextInput, nil
}

// RebindLocalVersion preserves a validated local runtime's identities and configuration,
// replacing only its version binding. The returned files and resolver list do
// not share mutable storage with the caller. No files are written.
func RebindLocalVersion(bundle Bundle, input Inputs, nextVersion string) (Bundle, Inputs, error) {
	if err := ValidateLocal(bundle, input); err != nil {
		return Bundle{}, Inputs{}, err
	}
	nextInput := input
	nextInput.Version = nextVersion
	nextInput.ResolverEndpoints = slices.Clone(input.ResolverEndpoints)
	if err := ValidateLocalInputs(nextInput); err != nil {
		return Bundle{}, Inputs{}, err
	}
	nextBundle := Bundle{Files: slices.Clone(bundle.Files)}
	var serial string
	for i := range nextBundle.Files {
		f := &nextBundle.Files[i]
		f.Data = bytes.Clone(f.Data)
		if f.Path == RuntimeDirectory+"/agent.crt" {
			agent, err := parseCertificate(f.Data)
			if err != nil {
				return Bundle{}, Inputs{}, errInvalid
			}
			serial = agent.SerialNumber.String()
		}
	}
	for i := range nextBundle.Files {
		f := &nextBundle.Files[i]
		switch f.Path {
		case ServerEnvironment:
			f.Data = serverEnvLocal(nextInput, serial)
		case AgentEnvironment:
			f.Data = agentEnv(nextInput)
		}
	}
	if err := ValidateLocal(nextBundle, nextInput); err != nil {
		return Bundle{}, Inputs{}, err
	}
	return nextBundle, nextInput, nil
}

// WithBoundedEdgeGrace upgrades only the exact initial edge profile while
// keeping identities, credentials, origin and resolvers unchanged.
// For local runtime bundles (where Origin == ExactLocalLoopbackOrigin and there is no EdgeConfiguration),
// this operation is a verified no-op.
func WithBoundedEdgeGrace(bundle Bundle, input Inputs) (Bundle, error) {
	if input.Origin == ExactLocalLoopbackOrigin {
		if err := ValidateLocal(bundle, input); err != nil {
			return Bundle{}, err
		}
		result := Bundle{Files: slices.Clone(bundle.Files)}
		for index := range result.Files {
			result.Files[index].Data = bytes.Clone(result.Files[index].Data)
		}
		return result, nil
	}
	if err := ValidateExistingRuntime(bundle, input); err != nil {
		return Bundle{}, err
	}
	edge, err := acornfoxroute.InitialConfig(input.Origin, input.ResolverEndpoints)
	if err != nil {
		return Bundle{}, err
	}
	result := Bundle{Files: slices.Clone(bundle.Files)}
	for index := range result.Files {
		result.Files[index].Data = bytes.Clone(result.Files[index].Data)
		if result.Files[index].Path == EdgeConfiguration {
			result.Files[index].Data = bytes.Clone(edge)
		}
	}
	return result, Validate(result, input)
}
