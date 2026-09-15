package application

import (
	"encoding/json"
	"fmt"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

// resolveAcornFoxRuntimeInput makes defaults explicit before identity is computed.
// Plain arguments and non-secret environment values become immutable facts.
func resolveAcornFoxRuntimeInput(input *contracts.AcornFoxRuntimeInput, port int) (*contracts.AcornFoxRuntimeConfiguration, contracts.AcornFoxRuntimeRequestedResources, string, error) {
	resources := acornFoxRuntimeResources()
	if input == nil {
		return nil, resources, "", nil
	}
	c := input.AcornFoxRuntimeConfiguration
	c.Environment = append([]contracts.RuntimeEnvironmentVariable(nil), c.Environment...)
	for i := range c.Environment {
		if c.Environment[i].Kind == "" {
			c.Environment[i].Kind = contracts.RuntimeEnvironmentLiteral
		}
	}
	if len(c.Secrets) > 0 {
		return nil, resources, "", domain.NewError(domain.ErrUnsupportedCapability, "runtime secret files are not yet supported")
	}
	if input.Resources != nil {
		resources = *input.Resources
	} else {
		var volumeBytes int64
		for _, v := range c.Volumes {
			if v.SizeBytes <= 0 || v.SizeBytes > 1<<50 || volumeBytes > (1<<50)-v.SizeBytes {
				return nil, resources, "", domain.ValidationError("runtime volume capacity is invalid")
			}
			volumeBytes += v.SizeBytes
		}
		if volumeBytes > 0 {
			resources.DiskReservationBytes += volumeBytes
		}
	}
	digest, err := contracts.CanonicalAcornFoxRuntimeConfigDigest(c, resources, port)
	if err != nil {
		return nil, resources, "", domain.ValidationError("runtime configuration is invalid")
	}
	// The durable task store redacts credential-shaped values. Reject them before
	// acceptance, rather than silently changing an immutable configuration later.
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, resources, "", err
	}
	safe, err := foundation.RedactJSON(raw, nil)
	if err != nil {
		return nil, resources, "", domain.ValidationError("runtime configuration is not persistable")
	}
	var roundtrip contracts.AcornFoxRuntimeConfiguration
	if json.Unmarshal(safe, &roundtrip) != nil {
		return nil, resources, "", domain.ValidationError("runtime configuration contains protected values")
	}
	persistedDigest, err := contracts.CanonicalAcornFoxRuntimeConfigDigest(roundtrip, resources, port)
	if err != nil || digest != persistedDigest {
		return nil, resources, "", domain.ValidationError("runtime configuration contains protected values; use secret references")
	}
	return &c, resources, digest, nil
}

func configuredAcornFoxRequestDigest(request AcornFoxDeliveryCreateRequest, original string) string {
	if request.Runtime == nil {
		return original
	}
	_, _, digest, err := resolveAcornFoxRuntimeInput(request.Runtime, request.ContainerPort)
	if err != nil {
		return "invalid-runtime-configuration"
	} // callers validate first
	return acornFoxDeliveryDigest(original, "runtime-config-v2", digest)
}

func acornFoxRuntimeDefinitionFact(configuration *contracts.AcornFoxRuntimeConfiguration, resources contracts.AcornFoxRuntimeRequestedResources, port int, digest string) domain.FieldFact {
	return domain.FieldFact{Source: domain.FactSourceUser, Confidence: 1, Status: domain.FactConfirmed, Value: struct {
		Configuration *contracts.AcornFoxRuntimeConfiguration     `json:"configuration"`
		Resources     contracts.AcornFoxRuntimeRequestedResources `json:"resources"`
		ContainerPort int                                         `json:"container_port"`
		ConfigDigest  string                                      `json:"config_digest"`
	}{configuration, resources, port, digest}}
}

func validatePersistedAcornFoxRuntimeDefinition(definition domain.ApplicationDeliveryDefinition, expected domain.FieldFact) error {
	got, ok := definition.Facts["runtime_configuration"]
	if !ok || got.Source != domain.FactSourceUser || got.Status != domain.FactConfirmed {
		return fmt.Errorf("runtime configuration was not persisted")
	}
	wantJSON, _ := json.Marshal(expected.Value)
	gotJSON, err := json.Marshal(got.Value)
	var want, actual any
	if err != nil || json.Unmarshal(wantJSON, &want) != nil || json.Unmarshal(gotJSON, &actual) != nil {
		return fmt.Errorf("runtime configuration persistence is invalid")
	}
	// Both concrete and database-decoded representations normalize to JSON maps.
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(actual)
	if string(a) != string(b) {
		return fmt.Errorf("runtime configuration persistence changed accepted values")
	}
	return nil
}
