package install

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func rc0ReleaseFixture() ReleaseV1 {
	return ReleaseV1{
		ID:             "release-0.8.0-rc.0",
		Version:        ProductionNMinusOneVersion,
		SourceCommit:   RC0SourceCommit,
		Architecture:   "amd64",
		ManifestSHA256: RC0ReleaseManifestSHA256,
	}
}

func assertJSONKeys(t *testing.T, raw []byte, expected ...string) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != len(expected) {
		t.Fatalf("JSON fields=%v, want %v", fields, expected)
	}
	for _, name := range expected {
		if fields[name] == nil {
			t.Fatalf("missing JSON field %q", name)
		}
	}
	return fields
}

func legacyPlanFixture() LegacyProjectionPlan {
	env := []byte("OPEN_CARD_DATABASE_URL=postgresql://user:pass@localhost:5432/open_card?sslmode=disable\n")
	release := rc0ReleaseFixture()
	target := []byte("console.example.test {\n\trespond \"ok\"\n}\n")
	edgeEvidence := edgeTransitionFixture("txn-1", release.ID, "release-0.8.0-rc.1")
	edgeEvidence.InstalledAfterSHA256 = bytesSHA256(target)
	return LegacyProjectionPlan{
		TransactionID:          "txn-1",
		ActivationID:           "activation-old",
		Release:                release,
		CurrentTarget:          legacyReleaseTarget(release),
		ExpectedMigration:      "0023",
		ExpectedRowsSHA256:     sha("a"),
		DatabaseEnv:            env,
		DatabaseEnvSHA256:      databaseEnvSHA256(env),
		ServerEnvBeforeSHA256:  sha("b"),
		ServerEnvAfterSHA256:   sha("c"),
		ServerUnitBeforeSHA256: sha("d"),
		ServerUnitAfterSHA256:  sha("e"),
		ServerUnitReleaseID:    "release-0.8.0-rc.1",
		EdgeConfigTransition:   &EdgeConfigTransitionPlan{Evidence: edgeEvidence, Target: target},
		Previous: ActivationPointerIdentity{
			ID:         "activation-previous",
			JSONSHA256: sha("f"),
		},
	}
}

func legacyActivationFixture() ActivationV1 {
	plan := legacyPlanFixture()
	return ActivationV1{
		SchemaVersion:          ActivationSchemaVersion,
		ActivationID:           plan.ActivationID,
		Origin:                 "rc0_compat_projection",
		Release:                plan.Release,
		Database:               DatabaseV1{Name: "open_card", Migration: "0023", SchemaMigrationsSHA256: plan.ExpectedRowsSHA256},
		DatabaseEnvSHA256:      plan.DatabaseEnvSHA256,
		CreatedAt:              time.Unix(1, 0).UTC(),
		CreatedByTransactionID: plan.TransactionID,
		LegacyProjection: &LegacyProjectionV1{
			Target:                 plan.CurrentTarget,
			ServerEnvBeforeSHA256:  plan.ServerEnvBeforeSHA256,
			ServerEnvAfterSHA256:   plan.ServerEnvAfterSHA256,
			ServerUnitBeforeSHA256: plan.ServerUnitBeforeSHA256,
			ServerUnitAfterSHA256:  plan.ServerUnitAfterSHA256,
			ServerUnitReleaseID:    plan.ServerUnitReleaseID,
		},
	}
}

func TestActivationPointerIdentityPairs(t *testing.T) {
	for _, pointer := range []ActivationPointerIdentity{
		{}, {ID: "activation-1", JSONSHA256: sha("a")},
	} {
		if err := pointer.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, pointer := range []ActivationPointerIdentity{
		{ID: "activation-1"}, {JSONSHA256: sha("a")}, {ID: "!", JSONSHA256: sha("a")}, {ID: "activation-1", JSONSHA256: "bad"},
	} {
		if err := pointer.Validate(); err == nil {
			t.Fatal("invalid pointer pair accepted")
		}
	}
}

func TestLegacyProjectionPlanValidationAndSecretBoundary(t *testing.T) {
	plan := legacyPlanFixture()
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "postgresql://") || strings.Contains(string(raw), "database_env\"") {
		t.Fatal("legacy plan serialized database environment")
	}
	fields := assertJSONKeys(t, raw,
		"transaction_id", "activation_id", "release", "current_target", "expected_migration", "expected_rows_sha256",
		"database_env_sha256", "server_env_before_sha256", "server_env_after_sha256", "server_unit_before_sha256", "server_unit_after_sha256", "server_unit_release_id", "edge_config_transition", "previous",
	)
	if _, exists := fields["database_env"]; exists || fields["database_env_sha256"] == nil || fields["previous"] == nil || strings.Contains(string(raw), "console.example.test {") || strings.Contains(string(raw), `respond \\"ok\\"`) {
		t.Fatal("legacy plan JSON shape is unsafe")
	}
	assertJSONKeys(t, fields["edge_config_transition"], "evidence")
	if strings.Contains(string(fields["edge_config_transition"]), "open-card-edge.Caddyfile") || strings.Contains(string(fields["edge_config_transition"]), "target") {
		t.Fatal("legacy plan serialized raw edge configuration")
	}

	for _, edit := range []func(*LegacyProjectionPlan){
		func(p *LegacyProjectionPlan) { p.TransactionID = "" },
		func(p *LegacyProjectionPlan) { p.ActivationID = "" },
		func(p *LegacyProjectionPlan) { p.Release.ID = "" },
		func(p *LegacyProjectionPlan) { p.Release.Version = "0.8.0-rc.1" },
		func(p *LegacyProjectionPlan) { p.Release.SourceCommit = strings.Repeat("a", 40) },
		func(p *LegacyProjectionPlan) { p.Release.Architecture = "arm64" },
		func(p *LegacyProjectionPlan) { p.Release.ManifestSHA256 = sha("0") },
		func(p *LegacyProjectionPlan) { p.CurrentTarget = "/tmp/release" },
		func(p *LegacyProjectionPlan) { p.ExpectedMigration = "0024" },
		func(p *LegacyProjectionPlan) { p.ExpectedRowsSHA256 = "bad" },
		func(p *LegacyProjectionPlan) { p.DatabaseEnv = []byte("bad\n") },
		func(p *LegacyProjectionPlan) { p.DatabaseEnvSHA256 = sha("0") },
		func(p *LegacyProjectionPlan) { p.ServerEnvBeforeSHA256 = "bad" },
		func(p *LegacyProjectionPlan) { p.ServerEnvAfterSHA256 = "bad" },
		func(p *LegacyProjectionPlan) { p.ServerUnitBeforeSHA256 = "bad" },
		func(p *LegacyProjectionPlan) { p.ServerUnitAfterSHA256 = "bad" },
		func(p *LegacyProjectionPlan) { p.ServerUnitReleaseID = "" },
		func(p *LegacyProjectionPlan) { p.EdgeConfigTransition = nil },
		func(p *LegacyProjectionPlan) { p.EdgeConfigTransition.Target = nil },
		func(p *LegacyProjectionPlan) { p.EdgeConfigTransition.Evidence.TransactionID = "txn-other" },
		func(p *LegacyProjectionPlan) { p.EdgeConfigTransition.Evidence.SourceReleaseID = "other-release" },
		func(p *LegacyProjectionPlan) { p.EdgeConfigTransition.Evidence.CandidateReleaseID = "other-release" },
		func(p *LegacyProjectionPlan) {
			p.EdgeConfigTransition.Evidence.ConsoleHostname = "Console.Example.Test"
		},
		func(p *LegacyProjectionPlan) { p.EdgeConfigTransition.Evidence.InstalledAfterSHA256 = sha("0") },
		func(p *LegacyProjectionPlan) { p.Previous.JSONSHA256 = "" },
	} {
		broken := legacyPlanFixture()
		edit(&broken)
		if err := broken.Validate(); err == nil {
			t.Fatal("invalid legacy projection plan accepted")
		}
	}
}

func TestLegacyProjectionRemainsAMD64OnlyAfterArm64RC0Freeze(t *testing.T) {
	release := rc0ReleaseFixture()
	release.Architecture = "arm64"
	release.ManifestSHA256 = ARM64RC0ReleaseManifestSHA256
	if validRC0Release(release) {
		t.Fatal("legacy runtime upgrade accepted frozen arm64 RC0")
	}
	plan := legacyPlanFixture()
	plan.Release = release
	plan.CurrentTarget = legacyReleaseTarget(release)
	if err := plan.Validate(); err == nil {
		t.Fatal("legacy projection accepted frozen arm64 RC0")
	}
}

func TestEdgeConfigPlanAndObservationContract(t *testing.T) {
	plan := legacyPlanFixture()
	edge := plan.EdgeConfigTransition
	if edge == nil || edge.PreparedArtifactPath() != edgeConfigPreparedArtifactPath(plan.TransactionID) || edge.PreparedArtifactPath() != artifactPath(plan.TransactionID, "open-card-edge.Caddyfile") {
		t.Fatal("prepared edge artifact path is not transaction-derived")
	}
	if err := edge.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := plan.ValidateForCandidate(ReleaseV1{ID: "release-0.8.0-rc.1", Version: "0.8.0-rc.1", SourceCommit: strings.Repeat("a", 40), Architecture: "amd64", ManifestSHA256: sha("b")}); err != nil {
		t.Fatal(err)
	}
	observation := EdgeConfigObservationV1{PreparedConfigSHA256: bytesSHA256(edge.Target), InstalledConfigSHA256: edge.Evidence.InstalledAfterSHA256, CaddySHA256: edge.Evidence.CandidateCaddySHA256}
	if err := observation.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*EdgeConfigObservationV1){
		func(o *EdgeConfigObservationV1) { o.PreparedConfigSHA256 = "bad" },
		func(o *EdgeConfigObservationV1) { o.InstalledConfigSHA256 = "bad" },
		func(o *EdgeConfigObservationV1) { o.CaddySHA256 = "bad" },
	} {
		broken := observation
		edit(&broken)
		if err := broken.Validate(); err == nil {
			t.Fatal("invalid edge configuration observation accepted")
		}
	}
}

func TestPreflightAndInspectionContracts(t *testing.T) {
	native := activationFixture()
	nativeEnv := []byte("OPEN_CARD_DATABASE_URL=postgresql://user:pass@localhost:5432/open_card?sslmode=disable\n")
	native.DatabaseEnvSHA256 = databaseEnvSHA256(nativeEnv)
	nativeDigest, err := CanonicalActivationJSONSHA256(native)
	if err != nil {
		t.Fatal(err)
	}
	existing := UpgradePreflight{Existing: &ExistingActivationPreflight{Activation: native, JSONSHA256: nativeDigest, DatabaseEnv: nativeEnv}}
	if err := existing.Validate(); err != nil {
		t.Fatal(err)
	}
	rawExisting, err := json.Marshal(existing)
	if err != nil || strings.Contains(string(rawExisting), "postgresql://") || strings.Contains(string(rawExisting), "\"database_env\"") {
		t.Fatalf("native preflight serialized database environment: %s", rawExisting)
	}
	plan := legacyPlanFixture()
	legacy := UpgradePreflight{Legacy: &plan, Previous: plan.Previous}
	if err := legacy.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, broken := range []UpgradePreflight{
		{}, {Existing: existing.Existing, Legacy: &plan}, {Existing: existing.Existing, Previous: ActivationPointerIdentity{ID: "bad"}},
		{Existing: &ExistingActivationPreflight{Activation: native, JSONSHA256: sha("0"), DatabaseEnv: nativeEnv}},
		{Legacy: &plan},
	} {
		if err := broken.Validate(); err == nil {
			t.Fatal("invalid preflight accepted")
		}
	}
	request := UpgradePreflightRequest{TransactionID: "txn-1", CandidateRelease: ReleaseV1{ID: plan.ServerUnitReleaseID, Version: "0.8.0-rc.1", SourceCommit: strings.Repeat("a", 40), Architecture: "amd64", ManifestSHA256: sha("b")}}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := legacy.ValidateForRequest(request); err != nil {
		t.Fatal(err)
	}
	request.CandidateRelease.ID = "another-release"
	if err := legacy.ValidateForRequest(request); err == nil {
		t.Fatal("legacy unit was not bound to candidate release")
	}
	request.CandidateRelease.ID = plan.ServerUnitReleaseID
	request.CandidateRelease.SourceCommit = "bad"
	if err := request.Validate(); err == nil {
		t.Fatal("invalid preflight request accepted")
	}
	inspection := ActiveDatabaseInspectionRequest{DatabaseEnv: plan.DatabaseEnv, ExpectedMigration: plan.ExpectedMigration, ExpectedRowsSHA256: plan.ExpectedRowsSHA256, ExpectedRowCount: 23}
	if err := inspection.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(inspection)
	if err != nil || strings.Contains(string(raw), "postgresql://") || strings.Contains(string(raw), "database_env") {
		t.Fatal("inspection request serialized secret")
	}
	assertJSONKeys(t, raw, "expected_migration", "expected_rows_sha256", "expected_row_count")
	openRequest := UpgradeDatabaseOpenRequest{TransactionID: "txn-1", CandidateActivationID: "activation-1", CandidateDatabaseName: "open_card_act_0123456789abcdef", ActiveDatabaseEnv: plan.DatabaseEnv}
	if raw, err := json.Marshal(openRequest); err != nil || strings.Contains(string(raw), "postgresql://") || strings.Contains(string(raw), "active_database_env") {
		t.Fatalf("database open request serialized secret: %s err=%v", raw, err)
	}
	inspection.ExpectedMigration = "0024"
	if err := inspection.Validate(); err == nil {
		t.Fatal("invalid inspection request accepted")
	}
}

func TestLegacyActivationAndObservationContracts(t *testing.T) {
	activation := legacyActivationFixture()
	if err := activation.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*ActivationV1){
		func(a *ActivationV1) { a.Origin = "native" },
		func(a *ActivationV1) { a.Release.Version = "0.8.0-rc.1" },
		func(a *ActivationV1) { a.Database.Migration = "0024" },
		func(a *ActivationV1) { a.LegacyProjection.Target = "/tmp/release" },
		func(a *ActivationV1) { a.LegacyProjection.ServerEnvBeforeSHA256 = "bad" },
		func(a *ActivationV1) { a.LegacyProjection.ServerEnvAfterSHA256 = "bad" },
		func(a *ActivationV1) { a.LegacyProjection.ServerUnitBeforeSHA256 = "bad" },
		func(a *ActivationV1) { a.LegacyProjection.ServerUnitAfterSHA256 = "bad" },
		func(a *ActivationV1) { a.LegacyProjection.ServerUnitReleaseID = "" },
	} {
		broken := legacyActivationFixture()
		edit(&broken)
		if err := broken.Validate(); err == nil {
			t.Fatal("invalid legacy activation accepted")
		}
	}
	native := activationFixture()
	native.LegacyProjection = &LegacyProjectionV1{}
	if err := native.Validate(); err == nil {
		t.Fatal("native activation accepted legacy projection")
	}
	digest, err := CanonicalActivationJSONSHA256(activation)
	if err != nil {
		t.Fatal(err)
	}
	observation := LegacyProjectionObservation{ActivationID: activation.ActivationID, ActivationJSONSHA256: digest, DatabaseEnvSHA256: activation.DatabaseEnvSHA256, Active: ActivationPointerIdentity{ID: activation.ActivationID, JSONSHA256: digest}, CurrentTarget: legacyCurrentTarget, ServerEnvSHA256: sha("a"), ServerUnitSHA256: sha("b")}
	if err := observation.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*LegacyProjectionObservation){
		func(o *LegacyProjectionObservation) { o.ActivationID = "" },
		func(o *LegacyProjectionObservation) { o.ActivationJSONSHA256 = "bad" },
		func(o *LegacyProjectionObservation) { o.DatabaseEnvSHA256 = "bad" },
		func(o *LegacyProjectionObservation) { o.Active.ID = "another" },
		func(o *LegacyProjectionObservation) { o.Previous.ID = "unpaired" },
		func(o *LegacyProjectionObservation) { o.CurrentTarget = "releases/old" },
		func(o *LegacyProjectionObservation) { o.ServerEnvSHA256 = "bad" },
		func(o *LegacyProjectionObservation) { o.ServerUnitSHA256 = "bad" },
	} {
		broken := observation
		edit(&broken)
		if err := broken.Validate(); err == nil {
			t.Fatal("invalid legacy projection observation accepted")
		}
	}
}

func TestPlannedOldActivationJournalRoundTripAndStrictJSON(t *testing.T) {
	planned := legacyActivationFixture()
	digest, err := CanonicalActivationJSONSHA256(planned)
	if err != nil {
		t.Fatal(err)
	}
	journal := journalFixture()
	journal.OldActivationID = planned.ActivationID
	journal.OldActivationJSONSHA256 = digest
	journal.PlannedOldActivation = &planned
	transition := *legacyPlanFixture().EdgeConfigTransition
	journal.EdgeConfigTransition = &transition.Evidence
	if err := journal.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalUpgradeJournalV1(journal)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "postgresql://") || strings.Contains(string(raw), "pass@") {
		t.Fatal("journal serialized database secret")
	}
	fields := assertJSONKeys(t, raw,
		"schema_version", "transaction_id", "request_kind", "revision", "state", "created_at", "updated_at", "requested_manifest_sha256",
		"upgrade_control_database_env_sha256",
		"old_activation_id", "old_activation_json_sha256", "planned_old_activation", "candidate_activation_id", "candidate_database_name", "edge_config_transition", "service_snapshot", "history",
	)
	assertJSONKeys(t, fields["planned_old_activation"],
		"schema_version", "activation_id", "origin", "release", "database", "database_env_sha256", "created_at", "created_by_transaction_id", "legacy_projection",
	)
	got, err := ParseUpgradeJournalV1(raw)
	if err != nil || got.PlannedOldActivation == nil || got.PlannedOldActivation.ActivationID != planned.ActivationID {
		t.Fatalf("planned old activation did not round-trip: %v", err)
	}
	appendTransition(&journal, JournalLegacyProjected)
	raw, err = MarshalUpgradeJournalV1(journal)
	if err != nil {
		t.Fatal(err)
	}
	if got, err = ParseUpgradeJournalV1(raw); err != nil || got.PlannedOldActivation == nil || got.PlannedOldActivation.ActivationID != planned.ActivationID {
		t.Fatalf("planned old activation was not retained: %v", err)
	}
	for _, edit := range []func(*UpgradeJournalV1){
		func(j *UpgradeJournalV1) { j.OldActivationID = "activation-other" },
		func(j *UpgradeJournalV1) { j.OldActivationJSONSHA256 = sha("0") },
		func(j *UpgradeJournalV1) { j.PlannedOldActivation.Origin = "native" },
	} {
		broken := journal
		plannedCopy := *journal.PlannedOldActivation
		broken.PlannedOldActivation = &plannedCopy
		edit(&broken)
		if err := broken.Validate(); err == nil {
			t.Fatal("invalid planned activation journal accepted")
		}
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields["planned_old_activation"] = json.RawMessage("null")
	nullPlanned, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		[]byte(`{"schema_version":1,"schema_version":1}`),
		append(raw, []byte(" {}")...),
		nullPlanned,
		[]byte(strings.Replace(string(raw), `"planned_old_activation":{`, `"planned_old_activation":{"unknown":true,`, 1)),
	} {
		if _, err := ParseUpgradeJournalV1(bad); err == nil {
			t.Fatal("unsafe planned journal JSON accepted")
		}
	}
}
