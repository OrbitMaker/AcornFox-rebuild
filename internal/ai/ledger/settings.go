package ledger

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Profile string

const (
	ProfileMainland Profile = "mainland"
	ProfileChina    Profile = ProfileMainland
	ProfileGlobal   Profile = "global"
	ProfileLocal    Profile = "local"
	ProfileDisabled Profile = "disabled"
)

type AISettings struct {
	ID             string    `json:"id"`
	IdempotencyKey string    `json:"idempotency_key"`
	RequestDigest  string    `json:"request_digest"`
	Version        int64     `json:"version"`
	Enabled        bool      `json:"enabled"`
	Profile        Profile   `json:"profile"`
	Provider       string    `json:"provider,omitempty"`
	Model          string    `json:"model,omitempty"`
	DataScopes     []string  `json:"data_scopes"`
	MaxTokens      int64     `json:"max_tokens"`
	MaxDurationMS  int64     `json:"max_duration_ms"`
	CooldownMS     int64     `json:"cooldown_ms"`
	CacheEnabled   bool      `json:"cache_enabled"`
	Actor          string    `json:"actor"`
	ExternalCalls  bool      `json:"external_calls"`
	CreatedAt      time.Time `json:"created_at"`
}

type SettingsRequest struct {
	IdempotencyKey string
	RequestDigest  string
	Settings       AISettings
}

func (s AISettings) Validate() error {
	switch s.Profile {
	case ProfileMainland, ProfileGlobal, ProfileLocal, ProfileDisabled:
	default:
		return fmt.Errorf("%w: unsupported AI profile", ErrInvalid)
	}
	if s.Version < 1 || s.MaxTokens < 0 || s.MaxDurationMS < 0 || s.CooldownMS < 0 || s.ExternalCalls {
		return fmt.Errorf("%w: AI settings bounds or external-call policy is invalid", ErrInvalid)
	}
	if s.Profile == ProfileDisabled {
		if s.Enabled || strings.TrimSpace(s.Provider) != "" || strings.TrimSpace(s.Model) != "" {
			return fmt.Errorf("%w: disabled profile cannot be enabled or carry a provider", ErrInvalid)
		}
	} else if s.Enabled && (strings.TrimSpace(s.Provider) == "" || strings.TrimSpace(s.Model) == "") {
		return fmt.Errorf("%w: enabled AI profile requires provider and model", ErrInvalid)
	}
	if len(s.DataScopes) == 0 && s.Profile != ProfileDisabled {
		return fmt.Errorf("%w: AI data scopes are required", ErrInvalid)
	}
	for _, scope := range s.DataScopes {
		if strings.TrimSpace(scope) == "" || strings.ContainsAny(scope, "\x00\r\n") {
			return fmt.Errorf("%w: AI data scope is invalid", ErrInvalid)
		}
	}
	if s.CreatedAt.IsZero() || strings.TrimSpace(s.Actor) == "" {
		return fmt.Errorf("%w: AI settings actor and timestamp are required", ErrInvalid)
	}
	return ValidateNoPlaintext(s)
}

func (s *LocalStore) AppendSettings(ctx context.Context, request SettingsRequest) (AISettings, bool, error) {
	if err := checkContext(ctx); err != nil {
		return AISettings{}, false, err
	}
	if s == nil {
		return AISettings{}, false, ErrInvalid
	}
	settings := request.Settings
	key := firstNonEmpty(request.IdempotencyKey, settings.IdempotencyKey)
	digest := firstNonEmpty(request.RequestDigest, settings.RequestDigest)
	if key == "" {
		key = settings.ID
	}
	if digest == "" {
		digest = Digest(settings)
	}
	if settings.ID == "" {
		settings.ID = ensureID("aiset", settings.ID, key, digest)
	}
	settings.IdempotencyKey, settings.RequestDigest = key, digest
	if settings.CreatedAt.IsZero() {
		settings.CreatedAt = time.Now().UTC()
	}
	if err := settings.Validate(); err != nil {
		return AISettings{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.keys["settings:"+key]; ok {
		if entry.Digest != digest || entry.Kind != "settings" {
			return AISettings{}, false, ErrConflict
		}
		for _, item := range s.settings {
			if item.ID == entry.ID {
				return item, true, nil
			}
		}
		return AISettings{}, false, ErrCorrupt
	}
	if current, ok := s.currentSettingsLocked(); ok && settings.Version <= current.Version {
		return AISettings{}, false, fmt.Errorf("%w: settings version must increase", ErrConflict)
	}
	s.settings = append(s.settings, settings)
	s.keys["settings:"+key] = idempotencyEntry{Digest: digest, Kind: "settings", ID: settings.ID}
	return settings, false, nil
}

func (s *LocalStore) CurrentSettings(ctx context.Context) (AISettings, error) {
	if err := checkContext(ctx); err != nil {
		return AISettings{}, err
	}
	if s == nil {
		return AISettings{}, ErrInvalid
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	settings, ok := s.currentSettingsLocked()
	if !ok {
		return AISettings{}, ErrNotFound
	}
	return settings, nil
}

func (s *LocalStore) currentSettingsLocked() (AISettings, bool) {
	if len(s.settings) == 0 {
		return AISettings{}, false
	}
	latest := s.settings[0]
	for _, item := range s.settings[1:] {
		if item.Version > latest.Version || (item.Version == latest.Version && item.CreatedAt.After(latest.CreatedAt)) {
			latest = item
		}
	}
	return latest, true
}

func (s *PostgresStore) AppendSettings(ctx context.Context, request SettingsRequest) (AISettings, bool, error) {
	if err := checkContext(ctx); err != nil {
		return AISettings{}, false, err
	}
	if err := s.requireDB(); err != nil {
		return AISettings{}, false, err
	}
	settings := request.Settings
	key := firstNonEmpty(request.IdempotencyKey, settings.IdempotencyKey)
	digest := firstNonEmpty(request.RequestDigest, settings.RequestDigest)
	if key == "" {
		key = settings.ID
	}
	if digest == "" {
		digest = Digest(settings)
	}
	if settings.ID == "" {
		settings.ID = ensureID("aiset", settings.ID, key, digest)
	}
	settings.IdempotencyKey, settings.RequestDigest = key, digest
	if settings.CreatedAt.IsZero() {
		settings.CreatedAt = time.Now().UTC()
	}
	if err := settings.Validate(); err != nil {
		return AISettings{}, false, err
	}
	var latestVersion sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT max(version) FROM m6_ai_settings_events`).Scan(&latestVersion); err != nil {
		return AISettings{}, false, err
	}
	if latestVersion.Valid && settings.Version <= latestVersion.Int64 {
		var replayDigest string
		var replayPayload []byte
		if err := s.db.QueryRowContext(ctx, `SELECT request_digest,payload FROM m6_ai_settings_events WHERE idempotency_key=$1`, key).Scan(&replayDigest, &replayPayload); err == nil {
			if replayDigest != digest {
				return AISettings{}, false, ErrConflict
			}
			var existing AISettings
			if json.Unmarshal(replayPayload, &existing) != nil {
				return AISettings{}, false, ErrCorrupt
			}
			return existing, true, nil
		}
		return AISettings{}, false, fmt.Errorf("%w: settings version must increase", ErrConflict)
	}
	scopes, _ := json.Marshal(settings.DataScopes)
	payload, _ := json.Marshal(settings)
	result, err := s.db.ExecContext(ctx, `INSERT INTO m6_ai_settings_events(id,idempotency_key,request_digest,version,enabled,profile,provider,model,data_scopes,max_tokens,max_duration_ms,cooldown_ms,cache_enabled,actor,external_calls,payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,$14,$15,$16::jsonb,$17) ON CONFLICT(idempotency_key) DO NOTHING`, settings.ID, key, digest, settings.Version, settings.Enabled, string(settings.Profile), settings.Provider, settings.Model, scopes, settings.MaxTokens, settings.MaxDurationMS, settings.CooldownMS, settings.CacheEnabled, settings.Actor, settings.ExternalCalls, payload, settings.CreatedAt.UTC())
	if err != nil {
		return AISettings{}, false, err
	}
	rows, _ := result.RowsAffected()
	if rows == 1 {
		return settings, false, nil
	}
	var storedDigest string
	var stored []byte
	if err := s.db.QueryRowContext(ctx, `SELECT request_digest,payload FROM m6_ai_settings_events WHERE idempotency_key=$1`, key).Scan(&storedDigest, &stored); err != nil {
		return AISettings{}, false, err
	}
	if storedDigest != digest {
		return AISettings{}, false, ErrConflict
	}
	var existing AISettings
	if json.Unmarshal(stored, &existing) != nil {
		return AISettings{}, false, ErrCorrupt
	}
	return existing, true, nil
}

func (s *PostgresStore) CurrentSettings(ctx context.Context) (AISettings, error) {
	if err := checkContext(ctx); err != nil {
		return AISettings{}, err
	}
	if err := s.requireDB(); err != nil {
		return AISettings{}, err
	}
	var payload []byte
	if err := s.db.QueryRowContext(ctx, `SELECT payload FROM m6_ai_settings_current`).Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return AISettings{}, ErrNotFound
		}
		return AISettings{}, err
	}
	var settings AISettings
	if json.Unmarshal(payload, &settings) != nil {
		return AISettings{}, ErrCorrupt
	}
	return settings, nil
}
