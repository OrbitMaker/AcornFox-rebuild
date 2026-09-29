package engine

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/volume"
	"github.com/opencontainers/go-digest"
)

var (
	hexPattern         = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	canonicalIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	safeNamePattern    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	volumePattern      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,255}$`)

	allowedOwnershipLabels = map[string]bool{
		"open-card.managed":     true,
		"open-card.task-prefix": true,
	}

	maxSafeQuota = int64((1 << 62) / 1000)
)

// filterAllowlistedLabels projects only explicitly permitted ownership labels.
// All arbitrary or unknown labels are dropped to prevent secret leakage.
func filterAllowlistedLabels(raw map[string]string) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	res := make(map[string]string)
	for k, v := range raw {
		if allowedOwnershipLabels[k] {
			res[k] = v
		}
	}
	if len(res) == 0 {
		return nil
	}
	return res
}

// validateEntityIdentifier validates container and network identifiers.
// Accepts full 64-hex IDs or hex prefixes with explicit minimum 12 chars, or exact legal object names.
// Rejects arbitrary name prefixes, path traversal, slashes, and control characters.
func validateEntityIdentifier(idOrName string) (isHex bool, err error) {
	s := strings.TrimSpace(idOrName)
	if s == "" || strings.Contains(s, "..") || strings.Contains(s, "/") || strings.Contains(s, "\\") || strings.ContainsAny(s, " \r\n\t") {
		return false, ErrInvalidIdentifier
	}

	if hexPattern.MatchString(s) {
		if len(s) < 12 || len(s) > 64 {
			return false, ErrInvalidIdentifier
		}
		return true, nil
	}

	if !safeNamePattern.MatchString(s) {
		return false, ErrInvalidIdentifier
	}
	return false, nil
}

// ValidateContainerIdentifier validates container identifiers.
func ValidateContainerIdentifier(idOrName string) (bool, error) {
	return validateEntityIdentifier(idOrName)
}

// MatchContainerIdentity verifies that the inspected container matches the requested identifier.
// The returned container ID must be a valid full 64-hex ID for both ID and name queries.
// Hex queries require prefix match against canonical 64-char ID. Name queries require exact match against canonical name.
func MatchContainerIdentity(requested string, isHex bool, resp *container.InspectResponse) error {
	if resp == nil || !canonicalIDPattern.MatchString(resp.ID) {
		return ErrIdentityMismatch
	}

	if isHex {
		if !strings.HasPrefix(strings.ToLower(resp.ID), strings.ToLower(requested)) {
			return ErrIdentityMismatch
		}
		return nil
	}

	canonicalName := strings.TrimPrefix(resp.Name, "/")
	if canonicalName != requested {
		return ErrIdentityMismatch
	}
	return nil
}

// parsedImageIdentity represents a validated image identifier.
type parsedImageIdentity struct {
	isDigest       bool
	configDigest   digest.Digest
	canonicalNamed reference.Canonical
	taggedNamed    reference.NamedTagged
}

// ParseImageReference validates and normalizes an image reference using official reference/digest parsers.
func ParseImageReference(ref string) (parsedImageIdentity, error) {
	s := strings.TrimSpace(ref)
	if s == "" || strings.Contains(s, "..") || strings.ContainsAny(s, " \r\n\t") {
		return parsedImageIdentity{}, ErrInvalidIdentifier
	}

	// 1. Explicit bare sha256: digest syntax
	if strings.HasPrefix(s, "sha256:") {
		d, err := digest.Parse(s)
		if err != nil || d.Validate() != nil {
			// Failed digest validation must return ErrInvalidIdentifier immediately.
			// Never fall through to ParseNormalizedNamed to reinterpret as a repo tag.
			return parsedImageIdentity{}, ErrInvalidIdentifier
		}
		return parsedImageIdentity{
			isDigest:     true,
			configDigest: d,
		}, nil
	}

	// 2. Named reference with repository (e.g. "redis", "redis:alpine", "myrepo@sha256:...")
	named, err := reference.ParseNormalizedNamed(s)
	if err != nil {
		// Invalid repository syntax or invalid prefix before @ -> ErrInvalidIdentifier
		return parsedImageIdentity{}, ErrInvalidIdentifier
	}

	// Canonical named digest (repo@digest)
	if canonical, ok := named.(reference.Canonical); ok {
		return parsedImageIdentity{
			isDigest:       true,
			canonicalNamed: canonical,
		}, nil
	}

	// Tagged reference or bare name: canonicalize default tag (:latest if none)
	tagged := reference.TagNameOnly(named)
	if namedTagged, ok := tagged.(reference.NamedTagged); ok {
		return parsedImageIdentity{
			isDigest:    false,
			taggedNamed: namedTagged,
		}, nil
	}

	return parsedImageIdentity{}, ErrInvalidIdentifier
}

// MatchImageIdentity verifies image identity against exact config ID or exact normalized RepoDigest/RepoTag.
// Bare ID matches response ID exactly.
// Named canonical digest matches full normalized RepoDigest including repository, not only digest suffix and not image config ID.
func MatchImageIdentity(requested string, parsed parsedImageIdentity, resp *image.InspectResponse) error {
	if resp == nil || strings.TrimSpace(resp.ID) == "" {
		return ErrIdentityMismatch
	}

	respDigest, err := digest.Parse(resp.ID)
	if err != nil || respDigest.Validate() != nil {
		return ErrIdentityMismatch
	}

	if parsed.isDigest {
		if parsed.configDigest != "" {
			// Bare config ID query: must match response ID exactly
			if parsed.configDigest != respDigest {
				return ErrIdentityMismatch
			}
			return nil
		}

		// Named canonical query (repo@manifestDigest):
		reqCanonicalStr := parsed.canonicalNamed.String()
		for _, rd := range resp.RepoDigests {
			if rdNamed, err := reference.ParseNormalizedNamed(rd); err == nil {
				if rdCanonical, ok := rdNamed.(reference.Canonical); ok {
					if rdCanonical.String() == reqCanonicalStr {
						return nil
					}
				}
			}
		}
		return ErrIdentityMismatch
	}

	// Tagged reference query (repo:tag)
	reqTaggedStr := parsed.taggedNamed.String()
	for _, rt := range resp.RepoTags {
		if rtNamed, err := reference.ParseNormalizedNamed(rt); err == nil {
			rtTagged := reference.TagNameOnly(rtNamed)
			if rtTagged.String() == reqTaggedStr {
				return nil
			}
		}
	}

	return ErrIdentityMismatch
}

// ValidateNetworkIdentifier validates network identifiers.
func ValidateNetworkIdentifier(idOrName string) (bool, error) {
	return validateEntityIdentifier(idOrName)
}

// MatchNetworkIdentity checks network match against hex ID prefix or exact name.
// The returned network ID must be a valid full 64-hex ID for both ID and name queries.
func MatchNetworkIdentity(requested string, isHex bool, resp *network.Inspect) error {
	if resp == nil || !canonicalIDPattern.MatchString(resp.ID) {
		return ErrIdentityMismatch
	}
	if isHex {
		if !strings.HasPrefix(strings.ToLower(resp.ID), strings.ToLower(requested)) {
			return ErrIdentityMismatch
		}
		return nil
	}
	if resp.Name != requested {
		return ErrIdentityMismatch
	}
	return nil
}

// ValidateVolumeName validates volume names.
func ValidateVolumeName(name string) error {
	s := strings.TrimSpace(name)
	if s == "" || strings.Contains(s, "..") || strings.Contains(s, "/") || strings.Contains(s, "\\") {
		return ErrInvalidIdentifier
	}
	if !volumePattern.MatchString(s) {
		return ErrInvalidIdentifier
	}
	return nil
}

// MatchVolumeIdentity checks volume match against exact name.
func MatchVolumeIdentity(requested string, resp *volume.Volume) error {
	if resp == nil || resp.Name == "" {
		return ErrIdentityMismatch
	}
	if resp.Name != requested {
		return ErrIdentityMismatch
	}
	return nil
}

// calculateCPULimits computes CPU limits from NanoCPUs and CFS quota/period.
// Protects against overflow, negative values, and contradictory configurations.
// Default zero CFS values represent an unset representation, not conflicting unlimited.
func calculateCPULimits(nanoCPUs, cpuQuota, cpuPeriod int64) (millis int64, known bool, unlimited bool) {
	if nanoCPUs < 0 || cpuPeriod < 0 || cpuQuota < -1 || cpuQuota > maxSafeQuota {
		return 0, false, false
	}

	hasNano := nanoCPUs > 0
	hasCFS := cpuPeriod > 0 && cpuQuota > 0

	// When both representations are explicitly set, verify consistency
	if hasNano && hasCFS {
		nanoMillis := nanoCPUs / 1_000_000
		cfsMillis := (cpuQuota * 1000) / cpuPeriod
		if nanoMillis <= 0 || cfsMillis <= 0 {
			return 0, false, false
		}
		diff := nanoMillis - cfsMillis
		if diff < -1 || diff > 1 {
			// Actually contradictory limits
			return 0, false, false
		}
		return nanoMillis, true, false
	}

	// Contradictory: explicit -1 unlimited CFS quota while NanoCPUs > 0
	if hasNano && cpuQuota == -1 {
		return 0, false, false
	}

	// NanoCPUs configured (CFS unset or default zero)
	if hasNano {
		nanoMillis := nanoCPUs / 1_000_000
		if nanoMillis <= 0 {
			return 0, false, false
		}
		return nanoMillis, true, false
	}

	// CFS quota and period configured (NanoCPUs unset)
	if hasCFS {
		cfsMillis := (cpuQuota * 1000) / cpuPeriod
		if cfsMillis <= 0 {
			return 0, false, false
		}
		return cfsMillis, true, false
	}

	// Unlimited: both unset (all zero) or CFS explicitly unlimited (quota 0 or -1 with period >= 0)
	if (cpuQuota == 0 || cpuQuota == -1) && nanoCPUs == 0 {
		return 0, true, true
	}

	return 0, false, false
}

// calculateMemoryLimits computes memory limit and distinguishes unlimited from constrained.
func calculateMemoryLimits(memBytes int64) (bytes int64, known bool, unlimited bool) {
	if memBytes < 0 {
		return 0, false, false
	}
	if memBytes > 0 {
		return memBytes, true, false
	}
	if memBytes == 0 {
		return 0, true, true
	}
	return 0, false, false
}

// projectNetworks preserves network associations with deterministic alphabetical sorting.
func projectNetworks(raw map[string]*network.EndpointSettings) []ContainerNetworkFact {
	if len(raw) == 0 {
		return nil
	}
	res := make([]ContainerNetworkFact, 0, len(raw))
	for name, ep := range raw {
		fact := ContainerNetworkFact{
			NetworkName: name,
		}
		if ep != nil {
			fact.NetworkID = ep.NetworkID
			if ep.IPAddress.IsValid() {
				fact.IPAddress = ep.IPAddress.String()
			}
			if ep.Gateway.IsValid() {
				fact.Gateway = ep.Gateway.String()
			}
			if len(ep.MacAddress) > 0 {
				fact.MacAddress = ep.MacAddress.String()
			}
		}
		res = append(res, fact)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].NetworkName < res[j].NetworkName
	})
	return res
}

// projectContainerFacts extracts only allowlisted container facts from SDK response.
func projectContainerFacts(resp *container.InspectResponse) ContainerFacts {
	now := time.Now().UTC()
	facts := ContainerFacts{
		ID:         resp.ID,
		Name:       strings.TrimPrefix(resp.Name, "/"),
		ImageID:    resp.Image,
		ObservedAt: now,
	}

	if resp.Config != nil {
		facts.ImageRef = resp.Config.Image
		facts.Labels = filterAllowlistedLabels(resp.Config.Labels)
	}

	if resp.State != nil {
		facts.Status = string(resp.State.Status)
		facts.Running = resp.State.Running
		facts.Paused = resp.State.Paused
		facts.Restarting = resp.State.Restarting
		facts.ExitCode = resp.State.ExitCode
		if resp.State.StartedAt != "" {
			facts.StartedAt, _ = time.Parse(time.RFC3339Nano, resp.State.StartedAt)
		}
		if resp.State.FinishedAt != "" {
			facts.FinishedAt, _ = time.Parse(time.RFC3339Nano, resp.State.FinishedAt)
		}
		if resp.State.Health != nil {
			facts.HealthStatus = string(resp.State.Health.Status)
			facts.Healthy = (resp.State.Health.Status == "healthy")
		}
	}
	facts.RestartCount = uint64(resp.RestartCount)

	if resp.HostConfig != nil {
		facts.CPUMillis, facts.CPULimitKnown, facts.CPUUnlimited = calculateCPULimits(
			resp.HostConfig.NanoCPUs,
			resp.HostConfig.CPUQuota,
			resp.HostConfig.CPUPeriod,
		)
		facts.MemoryLimitBytes, facts.MemoryLimitKnown, facts.MemoryUnlimited = calculateMemoryLimits(resp.HostConfig.Memory)

		if resp.HostConfig.PidsLimit != nil {
			facts.PIDsLimit = *resp.HostConfig.PidsLimit
		}

		if resp.HostConfig.PortBindings != nil {
			for portProto, bindings := range resp.HostConfig.PortBindings {
				cPort := int(portProto.Num())
				proto := string(portProto.Proto())
				if proto == "" {
					proto = "tcp"
				}
				for _, b := range bindings {
					hPort, _ := strconv.Atoi(b.HostPort)
					hostIP := ""
					if b.HostIP.IsValid() {
						hostIP = b.HostIP.String()
					}
					facts.PortBindings = append(facts.PortBindings, PortBinding{
						HostIP:        hostIP,
						HostPort:      hPort,
						ContainerPort: cPort,
						Protocol:      proto,
					})
				}
			}
		}
	}

	for _, m := range resp.Mounts {
		// Strictly omit m.Source to avoid host path leakage
		facts.Mounts = append(facts.Mounts, MountFact{
			Type:        string(m.Type),
			Name:        m.Name,
			Destination: m.Destination,
			ReadOnly:    !m.RW,
		})
	}

	if resp.NetworkSettings != nil {
		facts.Networks = projectNetworks(resp.NetworkSettings.Networks)
	}

	return facts
}

// projectImageFacts extracts safe image facts without build environment or history.
func projectImageFacts(resp *image.InspectResponse) ImageFacts {
	now := time.Now().UTC()
	facts := ImageFacts{
		ID:           resp.ID,
		RepoTags:     resp.RepoTags,
		RepoDigests:  resp.RepoDigests,
		SizeBytes:    resp.Size,
		Architecture: resp.Architecture,
		OS:           resp.Os,
		ObservedAt:   now,
	}

	if resp.Created != "" {
		facts.CreatedAt, _ = time.Parse(time.RFC3339Nano, resp.Created)
	}

	if resp.Config != nil && resp.Config.ExposedPorts != nil {
		for p := range resp.Config.ExposedPorts {
			facts.ExposedPorts = append(facts.ExposedPorts, string(p))
		}
		sort.Strings(facts.ExposedPorts)
	}

	return facts
}

// projectNetworkFacts extracts safe network facts and filters labels.
func projectNetworkFacts(resp *network.Inspect) NetworkFacts {
	now := time.Now().UTC()
	facts := NetworkFacts{
		ID:         resp.ID,
		Name:       resp.Name,
		Driver:     resp.Driver,
		Scope:      resp.Scope,
		Internal:   resp.Internal,
		Labels:     filterAllowlistedLabels(resp.Labels),
		ObservedAt: now,
	}

	if len(resp.IPAM.Config) > 0 {
		if resp.IPAM.Config[0].Subnet.IsValid() {
			facts.Subnet = resp.IPAM.Config[0].Subnet.String()
		}
		if resp.IPAM.Config[0].Gateway.IsValid() {
			facts.Gateway = resp.IPAM.Config[0].Gateway.String()
		}
	}

	return facts
}

// projectVolumeFacts extracts safe volume facts without host mountpoint.
func projectVolumeFacts(resp *volume.Volume) VolumeFacts {
	now := time.Now().UTC()
	facts := VolumeFacts{
		Name:       resp.Name,
		Driver:     resp.Driver,
		Labels:     filterAllowlistedLabels(resp.Labels),
		ObservedAt: now,
	}

	if resp.CreatedAt != "" {
		facts.CreatedAt, _ = time.Parse(time.RFC3339Nano, resp.CreatedAt)
	}

	return facts
}
