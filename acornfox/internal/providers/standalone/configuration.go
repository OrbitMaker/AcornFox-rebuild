package standalone

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	volumeprovider "github.com/acornfox/acornfox/internal/providers/volume"
)

// ManagedVolumeProvider adds fresh readback to the existing lifecycle interface.
// Attach alone is insufficient because its idempotency cache can reuse old facts.
type ManagedVolumeProvider interface {
	contracts.VolumeProvider
	InspectFacts(context.Context, contracts.VolumeRequest) (volumeprovider.VolumeFacts, error)
}

type runtimeImageConfiguration struct {
	Entrypoint []string       `json:"Entrypoint"`
	Cmd        []string       `json:"Cmd"`
	Env        []string       `json:"Env"`
	Volumes    map[string]any `json:"Volumes"`
}

func copyRuntimeConfiguration(c *contracts.AcornFoxRuntimeConfiguration) *contracts.AcornFoxRuntimeConfiguration {
	if c == nil {
		return nil
	}
	next := *c
	next.Entrypoint = append([]string(nil), c.Entrypoint...)
	next.Command = append([]string(nil), c.Command...)
	next.Environment = append([]contracts.RuntimeEnvironmentVariable(nil), c.Environment...)
	next.Volumes = append([]contracts.AcornFoxRuntimeVolume(nil), c.Volumes...)
	next.Secrets = append([]contracts.AcornFoxRuntimeSecretBinding(nil), c.Secrets...)
	return &next
}

func (state *runtimeState) runtimeSpec() contracts.RuntimeSpec {
	return contracts.RuntimeSpec{ApplicationID: state.deployment.ApplicationID, EnvironmentID: state.deployment.EnvironmentID, ReleaseID: state.deployment.ReleaseID, ServiceName: state.service, Image: state.image, Resources: state.resources, Port: state.containerPort, Configuration: copyRuntimeConfiguration(state.configuration), ConfigDigest: state.configDigest}
}

func runtimeStateSchema(spec contracts.RuntimeSpec) string {
	if spec.Configuration != nil {
		return "2"
	}
	return "1"
}

// The schema-2 algorithm is stable across releases and is part of persisted
// configuration semantics. Hashing both IDs prevents cross-application reuse.
func runtimeVolumeName(taskPrefix string, spec contracts.RuntimeSpec, name string) string {
	return taskPrefix + "-volume-af-" + hash(spec.ApplicationID.String(), name)[:32]
}
func runtimeVolumeSpec(taskPrefix string, spec contracts.RuntimeSpec, v contracts.AcornFoxRuntimeVolume) contracts.VolumeSpec {
	return contracts.VolumeSpec{Name: runtimeVolumeName(taskPrefix, spec, v.Name), MountPath: v.MountPath, SizeBytes: v.SizeBytes}
}

func (p *Provider) validateConfiguredSpec(spec contracts.RuntimeSpec, op contracts.OperationContext) error {
	if spec.Configuration == nil && spec.ConfigDigest == "" {
		return nil
	}
	if spec.Configuration == nil {
		return p.failure(op, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrValidation, "runtime configuration is missing", contracts.RetryNever, false, nil)
	}
	resources := contracts.AcornFoxRuntimeRequestedResources{CPUMillis: spec.Resources.CPUMillis, MemoryBytes: spec.Resources.MemoryBytes, PIDs: spec.Resources.PIDs, DiskReservationBytes: spec.Resources.DiskBytes}
	digest, err := contracts.CanonicalAcornFoxRuntimeConfigDigest(*spec.Configuration, resources, spec.Port)
	if err != nil || digest != spec.ConfigDigest {
		return p.failure(op, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrValidation, "runtime configuration digest is invalid", contracts.RetryNever, false, nil)
	}
	if len(spec.Configuration.Secrets) > 0 {
		return p.failure(op, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrForbidden, "runtime secret files are not yet supported", contracts.RetryUserAction, false, nil)
	}
	if len(spec.Configuration.Volumes) > 0 && p.config.Volumes == nil {
		return p.failure(op, contracts.CapabilityRuntimeDeploy, "deploy", contracts.ErrForbidden, "named volume capability is unavailable", contracts.RetryUserAction, false, nil)
	}
	return nil
}

func (p *Provider) prepareRuntimeVolumes(ctx context.Context, spec contracts.RuntimeSpec, op contracts.OperationContext) error {
	if spec.Configuration == nil {
		return nil
	}
	for _, v := range spec.Configuration.Volumes {
		claim := runtimeVolumeClaimFor(p.config.TaskPrefix, spec, v)
		unlock := p.lockDeployment(domain.ID("volume_" + hash(claim.Volume.Name)))
		err := p.prepareRuntimeVolume(ctx, spec, claim, op)
		unlock()
		if err != nil {
			return err
		}
	}
	return nil
}
func (p *Provider) prepareRuntimeVolume(ctx context.Context, spec contracts.RuntimeSpec, claim runtimeVolumeClaim, op contracts.OperationContext) error {
	state, err := p.readRuntimeVolumeReceipt(claim)
	if err != nil {
		return err
	}
	inspectErr := p.inspectRuntimeVolume(ctx, claim.Volume, op)
	if inspectErr != nil && !isProviderCode(inspectErr, contracts.ErrNotFound) {
		return inspectErr
	}
	if state == "" {
		if inspectErr == nil {
			return fmt.Errorf("existing volume has no creation receipt")
		}
		if err := p.persistRuntimeVolumeReceipt(claim, "pending"); err != nil {
			return err
		}
		state, err = p.readRuntimeVolumeReceipt(claim)
		if err != nil {
			return err
		}
	}
	if state == "accepted" {
		return inspectErr
	}
	if state != "pending" {
		return fmt.Errorf("retained volume receipt state is invalid")
	}
	if inspectErr != nil {
		operation := op
		operation.IdempotencyKey = "runtime-volume-create-" + hash(claim.ApplicationID.String(), claim.LogicalName, spec.ConfigDigest, op.IdempotencyKey)[:40]
		got, _, err := p.config.Volumes.Create(ctx, contracts.VolumeRequest{Volume: claim.Volume, Operation: operation})
		if err != nil {
			return err
		}
		if got != claim.Volume {
			return fmt.Errorf("volume provider returned an unexpected resource")
		}
	}
	if err := p.inspectRuntimeVolume(ctx, claim.Volume, op); err != nil {
		return err
	}
	return p.persistRuntimeVolumeReceipt(claim, "accepted")
}

// Recovery only inspects existing retained volumes. It never creates a blank
// replacement when data is missing, and never destroys a volume as compensation.
func (p *Provider) verifyRuntimeVolumes(ctx context.Context, spec contracts.RuntimeSpec, op contracts.OperationContext) error {
	if spec.Configuration == nil {
		return nil
	}
	for _, v := range spec.Configuration.Volumes {
		claim := runtimeVolumeClaimFor(p.config.TaskPrefix, spec, v)
		expected := claim.Volume
		recorded, err := p.readRuntimeVolumeReceipt(claim)
		if err != nil {
			return err
		}
		if recorded != "accepted" {
			return fmt.Errorf("retained volume receipt is not accepted")
		}
		if err := p.inspectRuntimeVolume(ctx, expected, op); err != nil {
			return err
		}
	}
	return nil
}
func (p *Provider) inspectRuntimeVolume(ctx context.Context, expected contracts.VolumeSpec, op contracts.OperationContext) error {
	if p.config.Volumes == nil {
		return fmt.Errorf("named volume capability is unavailable")
	}
	operation := op
	operation.IdempotencyKey = "runtime-volume-inspect-" + hash(expected.Name, op.IdempotencyKey)[:40]
	facts, err := p.config.Volumes.InspectFacts(ctx, contracts.VolumeRequest{Volume: expected, Operation: operation})
	if err != nil {
		return err
	}
	labels := facts.Labels
	if facts.Name != expected.Name || facts.Driver != "local" || len(facts.Options) != 0 || labels["open-card.managed"] != "true" || labels["open-card.task-prefix"] != p.config.TaskPrefix || labels["open-card.volume-logical-name"] != expected.Name || labels["open-card.volume-mount-path"] != expected.MountPath || labels["open-card.volume-size-bytes"] != strconv.FormatInt(expected.SizeBytes, 10) || labels["open-card.retention"] != "retain" {
		return fmt.Errorf("retained volume ownership or configuration changed")
	}
	return nil
}
func (p *Provider) ConfiguredRuntimeSupported() bool { return p.config.Volumes != nil }

func (p *Provider) loadRuntimeImageConfiguration(ctx context.Context, image string) (runtimeImageConfiguration, error) {
	output, err := p.output(ctx, []string{"image", "inspect", "--format", "{{.Id}}|{{json .Config}}", image})
	if err != nil {
		return runtimeImageConfiguration{}, err
	}
	parts := strings.SplitN(strings.TrimSpace(output), "|", 2)
	var config runtimeImageConfiguration
	if len(parts) != 2 || parts[0] != image || !validImageID(image) || json.Unmarshal([]byte(parts[1]), &config) != nil {
		return config, fmt.Errorf("runtime image configuration is unavailable")
	}
	return config, nil
}

func runtimeDeclaredVolumesCovered(declared map[string]any, spec contracts.RuntimeSpec) bool {
	for path := range declared {
		found := false
		if spec.Configuration != nil {
			for _, v := range spec.Configuration.Volumes {
				if v.MountPath == path {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (facts inspectFacts) matchesConfiguredRuntime(config Config, spec contracts.RuntimeSpec) bool {
	c := spec.Configuration
	if c == nil {
		return len(facts.Config.Volumes) == 0 && len(facts.Mounts) == 0
	}
	if !facts.imageConfigurationVerified || facts.Config.Labels["open-card.config-digest"] != spec.ConfigDigest || !runtimeDeclaredVolumesCovered(facts.Config.Volumes, spec) {
		return false
	}
	entrypoint := facts.imageConfiguration.Entrypoint
	command := facts.imageConfiguration.Cmd
	if len(c.Entrypoint) > 0 {
		entrypoint = []string{c.Entrypoint[0]}
		command = append(append([]string(nil), c.Entrypoint[1:]...), c.Command...)
	} else if len(c.Command) > 0 {
		command = c.Command
	}
	if !slices.Equal(facts.Config.Entrypoint, entrypoint) || !slices.Equal(facts.Config.Cmd, command) {
		return false
	}
	environment := map[string]string{}
	for _, entry := range facts.Config.Env {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			return false
		}
		if _, exists := environment[name]; exists {
			return false
		}
		environment[name] = value
	}
	for _, v := range c.Environment {
		if value, ok := environment[v.Name]; !ok || value != v.Value {
			return false
		}
	}
	if len(facts.Mounts) != len(c.Volumes) {
		return false
	}
	seen := map[string]bool{}
	for _, mount := range facts.Mounts {
		if mount.Type != "volume" || seen[mount.Destination] {
			return false
		}
		seen[mount.Destination] = true
		found := false
		for _, v := range c.Volumes {
			if mount.Destination == v.MountPath && mount.Name == runtimeVolumeName(config.TaskPrefix, spec, v.Name) && mount.RW != v.ReadOnly {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
