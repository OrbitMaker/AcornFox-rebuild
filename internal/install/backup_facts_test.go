package install

import (
	"bytes"
	"sort"
	"testing"
	"time"
)

func platformBackupFactFixture(t *testing.T) (PlatformBackupV3, map[string][]byte) {
	t.Helper()
	input := platformBackupInput(t)
	members := make(map[string][]byte, len(input.Artifacts))
	for _, artifact := range input.Artifacts {
		if artifact.Path == "database/control-plane.dump" {
			continue
		}
		data, err := platformBackupArtifactText(artifact.Source, artifact.Size, artifact.Path)
		if err != nil {
			t.Fatal(err)
		}
		members[artifact.Path] = data
	}
	artifacts := append([]PlatformBackupArtifactSource(nil), input.Artifacts...)
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	for i, artifact := range artifacts {
		members[artifact.Path] = members[artifact.Path]
		input.Manifest.Artifacts = append(input.Manifest.Artifacts, PlatformBackupArtifactV1{Path: artifact.Path, SHA256: platformBackupDigest(string(members[artifact.Path])), Size: artifact.Size, Mode: artifact.Mode})
		if artifact.Path == "database/control-plane.dump" {
			input.Manifest.Artifacts[i].SHA256 = platformBackupDigest("PGDMP\x01opaque dump")
		}
	}
	return input.Manifest, members
}

func TestPlatformBackupRuntimeFactBoundaries(t *testing.T) {
	_, members := platformBackupFactFixture(t)
	base, err := ParsePlatformBackupRuntimeConfigV1(members["config/runtime.json"])
	if err != nil {
		t.Fatal(err)
	}
	if !validCanonicalIDsJSON(`[{"certificate_id":"cert-a","instance_id":"instance-platform","node_id":"node-platform"}]`) || validCanonicalIDsJSON(`[{"instance_id":"instance-platform","certificate_id":"cert-a","node_id":"node-platform"}]`) {
		t.Fatal("identity JSON canonicalization")
	}
	for name, mutate := range map[string]func(*PlatformBackupRuntimeConfigV1){
		"unsorted":      func(v *PlatformBackupRuntimeConfigV1) { v.Server[0], v.Server[1] = v.Server[1], v.Server[0] },
		"forbidden":     func(v *PlatformBackupRuntimeConfigV1) { v.Server[4].Value = "postgresql://secret" },
		"missing-cross": func(v *PlatformBackupRuntimeConfigV1) { v.Agent = v.Agent[1:] },
		"unknown": func(v *PlatformBackupRuntimeConfigV1) {
			v.Server = append(v.Server, PlatformBackupRuntimeSettingV1{Key: "OPEN_CARD_UNKNOWN", Value: "true"})
		},
		"hierarchy": func(v *PlatformBackupRuntimeConfigV1) {
			v.Server = append(v.Server, PlatformBackupRuntimeSettingV1{Key: "OPEN_CARD_M1_ENABLED", Value: "false"}, PlatformBackupRuntimeSettingV1{Key: "OPEN_CARD_M3_ENABLED", Value: "true"})
			sort.Slice(v.Server, func(i, j int) bool { return v.Server[i].Key < v.Server[j].Key })
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			value.Server = append([]PlatformBackupRuntimeSettingV1(nil), base.Server...)
			value.Agent = append([]PlatformBackupRuntimeSettingV1(nil), base.Agent...)
			mutate(&value)
			if value.Validate() == nil {
				t.Fatal("invalid runtime accepted")
			}
		})
	}
	if !validLoopbackURL("http://127.0.0.1:5000", "http") || !validResolverList("1.1.1.1:53,8.8.8.8:53") || !validResolverList("1.1.1.1:53,[2606:4700:4700::1111]:53") || validResolverList("[::ffff:1.1.1.1]:53,8.8.8.8:53") || validResolverList("8.8.8.8:53,1.1.1.1:53") || validResolverList("198.51.100.1:53,8.8.8.8:53") || !runtimeValueValid("OPEN_CARD_BUILDKIT_ADDRESS", "unix:///run/open-card-buildkit/buildkitd.sock", true) {
		t.Fatal("documented runtime grammar")
	}
}

func TestPlatformBackupFactTableAndAuditInvariants(t *testing.T) {
	_, members := platformBackupFactFixture(t)
	routes, _ := ParsePlatformBackupRoutesV1(members["facts/routes.json"])
	routes.Tables[0], routes.Tables[1] = routes.Tables[1], routes.Tables[0]
	if routes.Validate() == nil {
		t.Fatal("route order accepted")
	}
	audit, _ := ParsePlatformBackupAuditV1(members["facts/audit.json"])
	first, last := int64(3), int64(9)
	head := "sha256:" + platformBackupDigest("head")
	audit.Table.RowCount, audit.FirstSequence, audit.LastSequence, audit.ChainHead, audit.Sequence.LastValue, audit.Sequence.IsCalled = 2, &first, &last, &head, 12, true
	if audit.Validate() != nil {
		t.Fatal("gapped audit rejected")
	}
	for name, mutate := range map[string]func(*PlatformBackupAuditV1){"link": func(v *PlatformBackupAuditV1) { v.LinkContinuity = false }, "head": func(v *PlatformBackupAuditV1) { bad := "bad"; v.ChainHead = &bad }, "bounds": func(v *PlatformBackupAuditV1) { zero := int64(0); v.FirstSequence = &zero }} {
		t.Run(name, func(t *testing.T) {
			value := audit
			mutate(&value)
			if value.Validate() == nil {
				t.Fatal("invalid audit accepted")
			}
		})
	}
}

func TestPlatformBackupFactTLSAndTasksInvariants(t *testing.T) {
	_, members := platformBackupFactFixture(t)
	tls, _ := ParsePlatformBackupTLSV1(members["edge/tls.json"])
	before, after, due := time.Unix(1, 0).UTC(), time.Unix(3, 0).UTC(), time.Unix(2, 0).UTC()
	tls.References = []PlatformBackupTLSReferenceV1{{CertificateReferenceID: "cert-a", OwnerKind: "platform_domain", OwnerID: "owner-a", SecretReferenceID: nil, SubjectHostname: "console.example.test", Issuer: "issuer-a", Status: "ready", NotBefore: &before, NotAfter: &after, RenewalDueAt: &due}}
	if tls.Validate() != nil {
		t.Fatal("external TLS reference rejected")
	}
	tls.MaterialIncluded = true
	if tls.Validate() == nil {
		t.Fatal("TLS material accepted")
	}
	tls.MaterialIncluded = false
	tls.References[0].Status = "unknown"
	if tls.Validate() == nil {
		t.Fatal("TLS status accepted")
	}
	empty := ""
	tls.References[0].Status, tls.References[0].SecretReferenceID = "ready", &empty
	if tls.Validate() == nil {
		t.Fatal("empty TLS secret reference accepted")
	}
	tasks, _ := ParsePlatformBackupTasksOutboxV1(members["facts/tasks-outbox.json"])
	first, last := int64(5), int64(9)
	tasks.Tables[0].RowCount, tasks.Tables[2].RowCount, tasks.OutboxSequence.LastValue, tasks.OutboxSequence.IsCalled = 2, 2, 9, true
	tasks.PendingOutbox.RowCount, tasks.PendingOutbox.FirstStreamSequence, tasks.PendingOutbox.LastStreamSequence = 2, &first, &last
	created, ended := time.Unix(1, 0).UTC(), time.Unix(2, 0).UTC()
	tasks.RecoverableTasks.RowCount, tasks.RecoverableTasks.FirstCreatedAt, tasks.RecoverableTasks.LastCreatedAt = 2, &created, &ended
	if tasks.Validate() != nil {
		t.Fatal("nonempty task facts rejected")
	}
	zero := int64(0)
	tasks.PendingOutbox.FirstStreamSequence = &zero
	if tasks.Validate() == nil {
		t.Fatal("bad task bounds accepted")
	}
}

func TestPlatformBackupFactKeyAndReleaseCrossBindings(t *testing.T) {
	manifest, members := platformBackupFactFixture(t)
	if ValidatePlatformBackupFacts(manifest, members) != nil {
		t.Fatal("fixture")
	}
	keys, _ := ParsePlatformBackupKeyReferencesV1(members["facts/key-references.json"])
	keys.References[0], keys.References[1] = keys.References[1], keys.References[0]
	if keys.Validate() == nil {
		t.Fatal("key order accepted")
	}
	keys, _ = ParsePlatformBackupKeyReferencesV1(members["facts/key-references.json"])
	keys.References = keys.References[:1]
	rawKeys, err := MarshalPlatformBackupKeyReferencesV1(keys)
	if err != nil {
		t.Fatal(err)
	}
	members["facts/key-references.json"] = rawKeys
	if ValidatePlatformBackupFacts(manifest, members) == nil {
		t.Fatal("missing local backup key accepted")
	}
	_, members = platformBackupFactFixture(t)
	release, _ := ParsePlatformBackupReleaseV1(members["facts/release.json"])
	release.Pointers.CurrentTarget = "active/wrong"
	if release.Validate() == nil {
		t.Fatal("bad relative pointer accepted")
	}
	release, _ = ParsePlatformBackupReleaseV1(members["facts/release.json"])
	release.Activation.ActivationID = "activation-other"
	release.Pointers.ActiveTarget = "activations/activation-other"
	raw, err := MarshalPlatformBackupReleaseV1(release)
	if err != nil {
		t.Fatal(err)
	}
	members["facts/release.json"] = raw
	if ValidatePlatformBackupFacts(manifest, members) == nil {
		t.Fatal("release/package mismatch accepted")
	}
}

func TestPlatformBackupFactsCanonicalJSON(t *testing.T) {
	_, members := platformBackupFactFixture(t)
	for path, raw := range members {
		if path == "config/Caddyfile" || path == "config/open-card-edge.Caddyfile" || path == "database/control-plane.dump" {
			continue
		}
		if !platformBackupParseTypedJSON(path, raw) {
			t.Fatalf("typed parse %s", path)
		}
		if !bytes.Equal(raw, mustCanonicalFact(t, path, raw)) {
			t.Fatalf("noncanonical %s", path)
		}
		if platformBackupParseTypedJSON(path, append(append([]byte(nil), raw...), ' ')) {
			t.Fatalf("whitespace accepted %s", path)
		}
	}
}

func mustCanonicalFact(t *testing.T, path string, raw []byte) []byte {
	t.Helper()
	switch path {
	case "config/runtime.json":
		v, e := ParsePlatformBackupRuntimeConfigV1(raw)
		if e != nil {
			t.Fatal(e)
		}
		out, _ := MarshalPlatformBackupRuntimeConfigV1(v)
		return out
	case "edge/tls.json":
		v, e := ParsePlatformBackupTLSV1(raw)
		if e != nil {
			t.Fatal(e)
		}
		out, _ := MarshalPlatformBackupTLSV1(v)
		return out
	case "facts/audit.json":
		v, e := ParsePlatformBackupAuditV1(raw)
		if e != nil {
			t.Fatal(e)
		}
		out, _ := MarshalPlatformBackupAuditV1(v)
		return out
	case "facts/key-references.json":
		v, e := ParsePlatformBackupKeyReferencesV1(raw)
		if e != nil {
			t.Fatal(e)
		}
		out, _ := MarshalPlatformBackupKeyReferencesV1(v)
		return out
	case "facts/release.json":
		v, e := ParsePlatformBackupReleaseV1(raw)
		if e != nil {
			t.Fatal(e)
		}
		out, _ := MarshalPlatformBackupReleaseV1(v)
		return out
	case "facts/routes.json":
		v, e := ParsePlatformBackupRoutesV1(raw)
		if e != nil {
			t.Fatal(e)
		}
		out, _ := MarshalPlatformBackupRoutesV1(v)
		return out
	case "facts/tasks-outbox.json":
		v, e := ParsePlatformBackupTasksOutboxV1(raw)
		if e != nil {
			t.Fatal(e)
		}
		out, _ := MarshalPlatformBackupTasksOutboxV1(v)
		return out
	default:
		t.Fatalf("unexpected %s", path)
		return nil
	}
}

func TestPlatformBackupFactsRejectCrossSnapshotAndTLSMaterial(t *testing.T) {
	manifest, members := platformBackupFactFixture(t)
	if ValidatePlatformBackupFacts(manifest, members) != nil {
		t.Fatal("fixture")
	}
	tls, err := ParsePlatformBackupTLSV1(members["edge/tls.json"])
	if err != nil {
		t.Fatal(err)
	}
	tls.MaterialIncluded = true
	if tls.Validate() == nil {
		t.Fatal("TLS material accepted")
	}
	routes, err := ParsePlatformBackupRoutesV1(members["facts/routes.json"])
	if err != nil {
		t.Fatal(err)
	}
	routes.DatabaseSnapshotSHA256 = platformBackupDigest("other")
	raw, _ := MarshalPlatformBackupRoutesV1(routes)
	if raw != nil {
		members["facts/routes.json"] = raw
	}
	if ValidatePlatformBackupFacts(manifest, members) == nil {
		t.Fatal("snapshot mismatch accepted")
	}
}
