package acornfoxsetup

import (
	"bytes"
	"slices"
)

// RebindVersion preserves a validated runtime's identities and configuration,
// replacing only its version binding. The returned files and resolver list do
// not share mutable storage with the caller. No files are written.
func RebindVersion(bundle Bundle, input Inputs, nextVersion string) (Bundle, Inputs, error) {
	if err := Validate(bundle, input); err != nil {
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
	if err := Validate(nextBundle, nextInput); err != nil {
		return Bundle{}, Inputs{}, err
	}
	return nextBundle, nextInput, nil
}
