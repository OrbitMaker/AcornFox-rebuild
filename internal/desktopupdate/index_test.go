package desktopupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Helper to sign and create valid envelope JSON
func createTestEnvelope(t *testing.T, priv ed25519.PrivateKey, p IndexPayload) []byte {
	t.Helper()
	payloadBytes, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, payloadBytes)
	env := map[string]any{
		"schema_version": 1,
		"payload":        base64.StdEncoding.EncodeToString(payloadBytes),
		"signature":      base64.StdEncoding.EncodeToString(sig),
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return envBytes
}

func validTestArtifacts() []Artifact {
	dummySHA := strings.Repeat("0", 64)
	return []Artifact{
		{
			OS:     "darwin",
			Arch:   "arm64",
			URL:    "https://downloads.example.com/builds/darwin-arm64.tar.gz",
			SHA256: dummySHA,
			Size:   1048576,
		},
		{
			OS:     "windows",
			Arch:   "amd64",
			URL:    "https://downloads.example.com/builds/windows-amd64.zip",
			SHA256: dummySHA,
			Size:   2097152,
		},
		{
			OS:     "linux",
			Arch:   "amd64",
			URL:    "https://downloads.example.com/builds/linux-amd64.tar.gz",
			SHA256: dummySHA,
			Size:   1572864,
		},
	}
}

func TestVerifyAndSelectUpdate_Success(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := IndexPayload{
		Channel:   "stable",
		Sequence:  10,
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "v1.10.0",
		Artifacts: validTestArtifacts(),
	}

	envBytes := createTestEnvelope(t, priv, payload)

	opts := CheckUpdateOptions{
		PublicKey:       pub,
		TargetOS:        "darwin",
		TargetArch:      "arm64",
		AllowedChannel:  "stable",
		CurrentSequence: 5,
		CurrentVersion:  "v1.9.0",
		AllowedHosts:    []string{"downloads.example.com"},
	}

	res, err := VerifyAndSelectUpdate(envBytes, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Version != "v1.10.0" {
		t.Errorf("got version %s, want v1.10.0", res.Version)
	}
	if res.Sequence != 10 {
		t.Errorf("got sequence %d, want 10", res.Sequence)
	}
	if res.Artifact == nil {
		t.Fatal("expected non-nil artifact")
	}
	if res.Artifact.OS != "darwin" || res.Artifact.Arch != "arm64" {
		t.Errorf("got artifact platform %s/%s, want darwin/arm64", res.Artifact.OS, res.Artifact.Arch)
	}
}

func TestSemver_ParseAndCompareRules(t *testing.T) {
	// Rejection tests for Semver
	invalidSemvers := []string{
		"18446744073709551616.0.0", // overflow uint64
		"01.2.3",                   // leading zero
		"1.02.3",                   // leading zero in minor
		"1.2.03",                   // leading zero in patch
		"1.2.3-beta.01",            // leading zero in prerelease num
		"1.2.3-gamma.1",            // unsupported prerelease identifier
		"1.2.3-beta",               // missing prerelease number
		"1.2",                      // not X.Y.Z
		"",                         // empty
		" 1.2.3 ",                  // whitespaces
	}

	for _, s := range invalidSemvers {
		t.Run("invalid_"+s, func(t *testing.T) {
			_, err := ParseSemver(s)
			if err == nil {
				t.Errorf("expected error for invalid semver %q, got nil", s)
			}
		})
	}

	tests := []struct {
		a, b string
		want int // -1, 0, 1
	}{
		{"1.10.0", "1.9.0", 1},
		{"v1.9.0", "1.10.0", -1},
		{"1.2.3", "1.2.3", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.4", "1.2.3", 1},
		{"2.0.0", "1.99.99", 1},
		{"1.0.0", "1.0.0-beta.1", 1}, // normal version > prerelease
		{"1.0.0-beta.1", "1.0.0", -1},
		{"1.0.0-rc.1", "1.0.0-beta.1", 1}, // rc > beta
		{"1.0.0-beta.2", "1.0.0-beta.1", 1},
		{"1.0.0-beta.10", "1.0.0-beta.2", 1}, // numeric 10 > 2
		{"1.0.0-beta.1", "1.0.0-beta.2", -1},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s_vs_%s", tc.a, tc.b), func(t *testing.T) {
			va, err := ParseSemver(tc.a)
			if err != nil {
				t.Fatal(err)
			}
			vb, err := ParseSemver(tc.b)
			if err != nil {
				t.Fatal(err)
			}
			got := va.Compare(vb)
			if got != tc.want {
				t.Errorf("Compare(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestVerifyAndSelectUpdate_SequenceAndVersionRules(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	basePayload := IndexPayload{
		Channel:   "stable",
		Sequence:  10,
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "v1.5.0",
		Artifacts: validTestArtifacts(),
	}

	baseOpts := CheckUpdateOptions{
		PublicKey:      pub,
		TargetOS:       "linux",
		TargetArch:     "amd64",
		AllowedChannel: "stable",
		AllowedHosts:   []string{"downloads.example.com"},
	}

	// 1. Version rollback rejected (current 1.6.0, index 1.5.0)
	t.Run("version_rollback", func(t *testing.T) {
		env := createTestEnvelope(t, priv, basePayload)
		opts := baseOpts
		opts.CurrentSequence = 5
		opts.CurrentVersion = "v1.6.0"
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrVersionRollback) {
			t.Fatalf("expected ErrVersionRollback, got %v", err)
		}
	})

	// 2. Sequence rollback rejected (current sequence 15, index sequence 10)
	t.Run("sequence_rollback", func(t *testing.T) {
		env := createTestEnvelope(t, priv, basePayload)
		opts := baseOpts
		opts.CurrentSequence = 15
		opts.CurrentVersion = "v1.4.0"
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrSequenceRollback) {
			t.Fatalf("expected ErrSequenceRollback, got %v", err)
		}
	})

	// 3. Same version, same sequence -> ErrNoUpdate, nil Artifact
	t.Run("same_version_and_sequence", func(t *testing.T) {
		env := createTestEnvelope(t, priv, basePayload)
		opts := baseOpts
		opts.CurrentSequence = 10
		opts.CurrentVersion = "v1.5.0"
		res, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrNoUpdate) {
			t.Fatalf("expected ErrNoUpdate, got %v", err)
		}
		if res == nil {
			t.Fatal("expected metadata in result")
		}
		if res.Artifact != nil {
			t.Errorf("expected nil Artifact on no update, got %+v", res.Artifact)
		}
		if res.Sequence != 10 {
			t.Errorf("expected sequence 10, got %d", res.Sequence)
		}
	})

	// 4. Same version, higher sequence -> still ErrNoUpdate, nil Artifact, but returned sequence updated
	t.Run("same_version_higher_sequence", func(t *testing.T) {
		env := createTestEnvelope(t, priv, basePayload)
		opts := baseOpts
		opts.CurrentSequence = 8
		opts.CurrentVersion = "v1.5.0"
		res, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrNoUpdate) {
			t.Fatalf("expected ErrNoUpdate, got %v", err)
		}
		if res == nil {
			t.Fatal("expected metadata in result")
		}
		if res.Artifact != nil {
			t.Errorf("expected nil Artifact, got %+v", res.Artifact)
		}
		if res.Sequence != 10 {
			t.Errorf("expected sequence 10, got %d", res.Sequence)
		}
	})

	// 5. Higher version, but same sequence -> ErrSequenceRollback (sequence must strictly advance for new version)
	t.Run("same_sequence_higher_version", func(t *testing.T) {
		env := createTestEnvelope(t, priv, basePayload)
		opts := baseOpts
		opts.CurrentSequence = 10
		opts.CurrentVersion = "v1.4.0"
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrSequenceRollback) {
			t.Fatalf("expected ErrSequenceRollback for non-increasing sequence with new version, got %v", err)
		}
	})

	// 6. Same version, lower sequence -> sequence rollback must be rejected, not return ErrNoUpdate
	t.Run("same_version_lower_sequence", func(t *testing.T) {
		env := createTestEnvelope(t, priv, basePayload) // sequence = 10, version = v1.5.0
		opts := baseOpts
		opts.CurrentSequence = 15
		opts.CurrentVersion = "v1.5.0"
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrSequenceRollback) {
			t.Fatalf("expected ErrSequenceRollback for lower sequence with same version, got %v", err)
		}
	})
}

func TestVerifyAndSelectUpdate_OptionsValidation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	basePayload := IndexPayload{
		Channel:   "stable",
		Sequence:  10,
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "v1.10.0",
		Artifacts: validTestArtifacts(),
	}
	env := createTestEnvelope(t, priv, basePayload)

	validOpts := CheckUpdateOptions{
		PublicKey:       pub,
		TargetOS:        "darwin",
		TargetArch:      "arm64",
		AllowedChannel:  "stable",
		CurrentSequence: 0,
		CurrentVersion:  "",
		AllowedHosts:    []string{"downloads.example.com"},
	}

	// 1. Bad public key size
	t.Run("bad_public_key_length", func(t *testing.T) {
		opts := validOpts
		opts.PublicKey = []byte("short")
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("expected ErrInvalidOptions for bad public key, got %v", err)
		}
	})

	// 2. Negative MaxArtifactSize
	t.Run("negative_max_artifact_size", func(t *testing.T) {
		opts := validOpts
		opts.MaxArtifactSize = -1
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("expected ErrInvalidOptions for negative MaxArtifactSize, got %v", err)
		}
	})

	// 3. Whitespace or invalid CurrentVersion
	t.Run("whitespace_current_version", func(t *testing.T) {
		opts := validOpts
		opts.CurrentVersion = " "
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("expected ErrInvalidOptions for whitespace CurrentVersion, got %v", err)
		}
	})

	// 4. Empty CurrentVersion with non-zero sequence
	t.Run("empty_version_with_nonzero_sequence", func(t *testing.T) {
		opts := validOpts
		opts.CurrentVersion = ""
		opts.CurrentSequence = 1
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("expected ErrInvalidOptions for empty version with non-zero sequence, got %v", err)
		}
	})

	// 5. AllowedHosts with whitespace, uppercase, port, trailing dot, or duplicates
	t.Run("invalid_allowed_hosts_format", func(t *testing.T) {
		badHostsList := [][]string{
			{" downloads.example.com"},
			{"downloads.example.com "},
			{"DOWNLOADS.EXAMPLE.COM"},
			{"downloads.example.com:443"},
			{"https://downloads.example.com"},
			{"downloads.example.com."},
			{"downloads.example.com", "downloads.example.com"}, // duplicate
		}
		for _, bh := range badHostsList {
			opts := validOpts
			opts.AllowedHosts = bh
			_, err := VerifyAndSelectUpdate(env, opts)
			if !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("expected ErrInvalidOptions for host list %v, got %v", bh, err)
			}
		}
	})

	// 6. Empty allowed hosts
	t.Run("empty_allowed_hosts", func(t *testing.T) {
		opts := validOpts
		opts.AllowedHosts = nil
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("expected ErrInvalidOptions for empty AllowedHosts, got %v", err)
		}
	})

	// 7. Invalid/Empty allowed channel
	t.Run("invalid_allowed_channel", func(t *testing.T) {
		opts := validOpts
		opts.AllowedChannel = ""
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("expected ErrInvalidOptions for empty AllowedChannel, got %v", err)
		}
	})
}

func TestVerifyAndSelectUpdate_SecurityAndTampering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	basePayload := IndexPayload{
		Channel:   "stable",
		Sequence:  10,
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		Version:   "v1.10.0",
		Artifacts: validTestArtifacts(),
	}

	opts := CheckUpdateOptions{
		PublicKey:      pub,
		TargetOS:       "darwin",
		TargetArch:     "arm64",
		AllowedChannel: "stable",
		CurrentVersion: "v1.9.0",
		AllowedHosts:   []string{"downloads.example.com"},
	}

	// 1. Wrong public key
	t.Run("wrong_public_key", func(t *testing.T) {
		env := createTestEnvelope(t, priv, basePayload)
		badOpts := opts
		badOpts.PublicKey = otherPub
		_, err := VerifyAndSelectUpdate(env, badOpts)
		if !errors.Is(err, ErrSignatureMismatch) {
			t.Fatalf("expected ErrSignatureMismatch, got %v", err)
		}
	})

	// 2. Tampered payload content
	t.Run("tampered_payload", func(t *testing.T) {
		payloadBytes, _ := json.Marshal(basePayload)
		sig := ed25519.Sign(priv, payloadBytes)
		payloadBytes[5] ^= 0xff
		env := map[string]any{
			"schema_version": 1,
			"payload":        base64.StdEncoding.EncodeToString(payloadBytes),
			"signature":      base64.StdEncoding.EncodeToString(sig),
		}
		raw, _ := json.Marshal(env)
		_, err := VerifyAndSelectUpdate(raw, opts)
		if !errors.Is(err, ErrSignatureMismatch) {
			t.Fatalf("expected ErrSignatureMismatch, got %v", err)
		}
	})

	// 3. Duplicate JSON keys in envelope (exact duplicate)
	t.Run("exact_duplicate_envelope_key", func(t *testing.T) {
		dupJSON := []byte(`{"schema_version":1,"payload":"abc","payload":"def","signature":""}`)
		_, err := VerifyAndSelectUpdate(dupJSON, opts)
		if !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("expected ErrInvalidEnvelope for duplicate key, got %v", err)
		}
	})

	// 4. Duplicate JSON keys in envelope (case conflict e.g. Payload vs payload)
	t.Run("case_conflict_envelope_key", func(t *testing.T) {
		dupJSON := []byte(`{"schema_version":1,"payload":"abc","Payload":"def","signature":""}`)
		_, err := VerifyAndSelectUpdate(dupJSON, opts)
		if !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("expected ErrInvalidEnvelope for case conflicting key, got %v", err)
		}
	})

	// 5. Duplicate JSON keys in payload (exact duplicate)
	t.Run("exact_duplicate_payload_key", func(t *testing.T) {
		badPayload := []byte(`{"channel":"stable","channel":"stable","sequence":1,"expires_at":"2099-01-01T00:00:00Z","version":"1.0.0","artifacts":[]}`)
		sig := ed25519.Sign(priv, badPayload)
		env := map[string]any{
			"schema_version": 1,
			"payload":        base64.StdEncoding.EncodeToString(badPayload),
			"signature":      base64.StdEncoding.EncodeToString(sig),
		}
		raw, _ := json.Marshal(env)
		_, err := VerifyAndSelectUpdate(raw, opts)
		if !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for exact duplicate payload key, got %v", err)
		}
	})

	// 6. Duplicate JSON keys in artifact object inside payload
	t.Run("duplicate_key_in_artifact_object", func(t *testing.T) {
		badPayload := []byte(`{"channel":"stable","sequence":1,"expires_at":"2099-01-01T00:00:00Z","version":"1.0.0","artifacts":[{"os":"darwin","os":"darwin","arch":"arm64","url":"https://downloads.example.com/1","sha256":"0000000000000000000000000000000000000000000000000000000000000000","size":1}]}`)
		sig := ed25519.Sign(priv, badPayload)
		env := map[string]any{
			"schema_version": 1,
			"payload":        base64.StdEncoding.EncodeToString(badPayload),
			"signature":      base64.StdEncoding.EncodeToString(sig),
		}
		raw, _ := json.Marshal(env)
		_, err := VerifyAndSelectUpdate(raw, opts)
		if !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for duplicate key in artifact, got %v", err)
		}
	})

	// 7. Duplicate JSON keys in payload (case conflict e.g. Channel vs channel)
	t.Run("case_conflict_payload_key", func(t *testing.T) {
		badPayload := []byte(`{"channel":"stable","Channel":"stable","sequence":1,"expires_at":"2099-01-01T00:00:00Z","version":"1.0.0","artifacts":[]}`)
		sig := ed25519.Sign(priv, badPayload)
		env := map[string]any{
			"schema_version": 1,
			"payload":        base64.StdEncoding.EncodeToString(badPayload),
			"signature":      base64.StdEncoding.EncodeToString(sig),
		}
		raw, _ := json.Marshal(env)
		_, err := VerifyAndSelectUpdate(raw, opts)
		if !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for duplicate payload key, got %v", err)
		}
	})

	// 5. Trailing second JSON object
	t.Run("trailing_second_object", func(t *testing.T) {
		env := createTestEnvelope(t, priv, basePayload)
		withTrailing := append(env, []byte(`{"extra": true}`)...)
		_, err := VerifyAndSelectUpdate(withTrailing, opts)
		if !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("expected ErrInvalidEnvelope for trailing object, got %v", err)
		}
	})

	// 6. Unknown fields in envelope
	t.Run("unknown_field_in_envelope", func(t *testing.T) {
		payloadBytes, _ := json.Marshal(basePayload)
		sig := ed25519.Sign(priv, payloadBytes)
		env := map[string]any{
			"schema_version": 1,
			"payload":        base64.StdEncoding.EncodeToString(payloadBytes),
			"signature":      base64.StdEncoding.EncodeToString(sig),
			"extra_field":    "malicious",
		}
		raw, _ := json.Marshal(env)
		_, err := VerifyAndSelectUpdate(raw, opts)
		if !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("expected ErrInvalidEnvelope for unknown field, got %v", err)
		}
	})

	// 7. Expired index
	t.Run("expired_index", func(t *testing.T) {
		expiredPayload := basePayload
		expiredPayload.ExpiresAt = time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
		env := createTestEnvelope(t, priv, expiredPayload)
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrExpired) {
			t.Fatalf("expected ErrExpired, got %v", err)
		}
	})

	// 8. Channel mismatch (user requested beta, index is stable)
	t.Run("channel_mismatch", func(t *testing.T) {
		env := createTestEnvelope(t, priv, basePayload)
		chOpts := opts
		chOpts.AllowedChannel = "beta"
		_, err := VerifyAndSelectUpdate(env, chOpts)
		if !errors.Is(err, ErrChannelMismatch) {
			t.Fatalf("expected ErrChannelMismatch, got %v", err)
		}
	})

	// 9. Prerelease version on stable channel
	t.Run("prerelease_on_stable", func(t *testing.T) {
		prePayload := basePayload
		prePayload.Channel = "stable"
		prePayload.Version = "v1.10.0-beta.1"
		env := createTestEnvelope(t, priv, prePayload)
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for prerelease on stable, got %v", err)
		}
	})
}

func TestVerifyAndSelectUpdate_ArtifactValidation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dummySHA := strings.Repeat("a", 64)

	opts := CheckUpdateOptions{
		PublicKey:      pub,
		TargetOS:       "darwin",
		TargetArch:     "arm64",
		AllowedChannel: "stable",
		AllowedHosts:   []string{"downloads.example.com"},
	}

	// 1. Duplicate os/arch artifact
	t.Run("duplicate_artifact_platform", func(t *testing.T) {
		p := IndexPayload{
			Channel:   "stable",
			Sequence:  10,
			ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			Version:   "v1.10.0",
			Artifacts: []Artifact{
				{OS: "darwin", Arch: "arm64", URL: "https://downloads.example.com/1.tar.gz", SHA256: dummySHA, Size: 100},
				{OS: "darwin", Arch: "arm64", URL: "https://downloads.example.com/2.tar.gz", SHA256: dummySHA, Size: 200},
			},
		}
		env := createTestEnvelope(t, priv, p)
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrInvalidArtifact) {
			t.Fatalf("expected ErrInvalidArtifact for duplicate platform, got %v", err)
		}
	})

	// 2. Malicious / Disallowed URL: http instead of https
	t.Run("http_scheme_rejected", func(t *testing.T) {
		p := IndexPayload{
			Channel:   "stable",
			Sequence:  10,
			ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			Version:   "v1.10.0",
			Artifacts: []Artifact{
				{OS: "darwin", Arch: "arm64", URL: "http://downloads.example.com/1.tar.gz", SHA256: dummySHA, Size: 100},
			},
		}
		env := createTestEnvelope(t, priv, p)
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrURLNotAllowed) {
			t.Fatalf("expected ErrURLNotAllowed for http url, got %v", err)
		}
	})

	// 3. Userinfo in URL
	t.Run("userinfo_rejected", func(t *testing.T) {
		p := IndexPayload{
			Channel:   "stable",
			Sequence:  10,
			ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			Version:   "v1.10.0",
			Artifacts: []Artifact{
				{OS: "darwin", Arch: "arm64", URL: "https://user:pass@downloads.example.com/1.tar.gz", SHA256: dummySHA, Size: 100},
			},
		}
		env := createTestEnvelope(t, priv, p)
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrURLNotAllowed) {
			t.Fatalf("expected ErrURLNotAllowed for userinfo, got %v", err)
		}
	})

	// 4. Query parameters in URL
	t.Run("query_in_url_rejected", func(t *testing.T) {
		p := IndexPayload{
			Channel:   "stable",
			Sequence:  10,
			ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			Version:   "v1.10.0",
			Artifacts: []Artifact{
				{OS: "darwin", Arch: "arm64", URL: "https://downloads.example.com/1.tar.gz?token=secret", SHA256: dummySHA, Size: 100},
			},
		}
		env := createTestEnvelope(t, priv, p)
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrURLNotAllowed) {
			t.Fatalf("expected ErrURLNotAllowed for query param in URL, got %v", err)
		}
	})

	// 5. Host not in allowlist
	t.Run("host_not_in_allowlist", func(t *testing.T) {
		p := IndexPayload{
			Channel:   "stable",
			Sequence:  10,
			ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			Version:   "v1.10.0",
			Artifacts: []Artifact{
				{OS: "darwin", Arch: "arm64", URL: "https://attacker.com/malicious.tar.gz", SHA256: dummySHA, Size: 100},
			},
		}
		env := createTestEnvelope(t, priv, p)
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrURLNotAllowed) {
			t.Fatalf("expected ErrURLNotAllowed for disallowed host, got %v", err)
		}
	})

	// 6. Invalid SHA256 (uppercase or length != 64)
	t.Run("uppercase_sha256_rejected", func(t *testing.T) {
		p := IndexPayload{
			Channel:   "stable",
			Sequence:  10,
			ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			Version:   "v1.10.0",
			Artifacts: []Artifact{
				{OS: "darwin", Arch: "arm64", URL: "https://downloads.example.com/1.tar.gz", SHA256: strings.Repeat("A", 64), Size: 100},
			},
		}
		env := createTestEnvelope(t, priv, p)
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrInvalidArtifact) {
			t.Fatalf("expected ErrInvalidArtifact for uppercase sha256, got %v", err)
		}
	})

	// 7. Size 0 or negative
	t.Run("zero_size", func(t *testing.T) {
		p := IndexPayload{
			Channel:   "stable",
			Sequence:  10,
			ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			Version:   "v1.10.0",
			Artifacts: []Artifact{
				{OS: "darwin", Arch: "arm64", URL: "https://downloads.example.com/1.tar.gz", SHA256: dummySHA, Size: 0},
			},
		}
		env := createTestEnvelope(t, priv, p)
		_, err := VerifyAndSelectUpdate(env, opts)
		if !errors.Is(err, ErrInvalidArtifact) {
			t.Fatalf("expected ErrInvalidArtifact for 0 size, got %v", err)
		}
	})

	// 8. Size exceeds configured limit
	t.Run("size_exceeds_limit", func(t *testing.T) {
		p := IndexPayload{
			Channel:   "stable",
			Sequence:  10,
			ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			Version:   "v1.10.0",
			Artifacts: []Artifact{
				{OS: "darwin", Arch: "arm64", URL: "https://downloads.example.com/1.tar.gz", SHA256: dummySHA, Size: 5000},
			},
		}
		env := createTestEnvelope(t, priv, p)
		limitOpts := opts
		limitOpts.MaxArtifactSize = 1000
		_, err := VerifyAndSelectUpdate(env, limitOpts)
		if !errors.Is(err, ErrInvalidArtifact) {
			t.Fatalf("expected ErrInvalidArtifact for exceeding size limit, got %v", err)
		}
	})

	// 9. Unsupported target platform
	t.Run("unsupported_platform", func(t *testing.T) {
		p := IndexPayload{
			Channel:   "stable",
			Sequence:  10,
			ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			Version:   "v1.10.0",
			Artifacts: []Artifact{
				{OS: "windows", Arch: "amd64", URL: "https://downloads.example.com/win.zip", SHA256: dummySHA, Size: 100},
			},
		}
		env := createTestEnvelope(t, priv, p)
		_, err := VerifyAndSelectUpdate(env, opts) // opts targets darwin/arm64
		if !errors.Is(err, ErrUnsupportedPlatform) {
			t.Fatalf("expected ErrUnsupportedPlatform when platform not in artifacts, got %v", err)
		}
	})
}
