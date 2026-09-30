package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// AddonCredentials is the JSON stored in addons.credentials. It is plaintext
// in the SQLite file (0600, readable by the server administrator) and is
// never returned by any read API.
type AddonCredentials struct {
	Username     string `json:"username,omitempty"`
	Password     string `json:"password"`
	RootPassword string `json:"root_password,omitempty"` // MySQL only
	Database     string `json:"database,omitempty"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	URL          string `json:"url"` // value injected into the app as EnvVar
}

// ValidAddonKind reports whether kind is a supported add-on.
func ValidAddonKind(kind string) bool {
	switch kind {
	case AddonPostgres, AddonMySQL, AddonRedis:
		return true
	}
	return false
}

// AddonEnvVar is the app environment variable an add-on kind provides.
func AddonEnvVar(kind string) string {
	if kind == AddonRedis {
		return "REDIS_URL"
	}
	return "DATABASE_URL"
}

// mysqlMaxUser is MySQL's user name limit; PostgreSQL allows 63.
const mysqlMaxUser = 32

// addonDBName derives the database user and database name for app:
// "acornfox_<app>" with '-' mapped to '_' so the identifier never needs
// quoting. Names longer than MySQL's 32-character user limit keep a prefix
// plus 8 hex chars of the app name's SHA-256, so they stay unique per app.
func addonDBName(app string) string {
	name := "acornfox_" + strings.ReplaceAll(app, "-", "_")
	if len(name) <= mysqlMaxUser {
		return name
	}
	sum := sha256.Sum256([]byte(app))
	return name[:mysqlMaxUser-9] + "_" + hex.EncodeToString(sum[:4])
}

// NewAddonCredentials generates fresh random credentials for one add-on
// reachable at host:port inside the app network. Passwords are 32 hex chars
// (128 bits), so they are safe in URLs and config files without escaping.
func NewAddonCredentials(app, kind, host string, port int) (AddonCredentials, error) {
	if !ValidAppName(app) || !ValidAddonKind(kind) || host == "" || port <= 0 {
		return AddonCredentials{}, fmt.Errorf("%w: addon %s/%s", ErrInvalid, app, kind)
	}
	password, err := randomHex(16)
	if err != nil {
		return AddonCredentials{}, err
	}
	c := AddonCredentials{Password: password, Host: host, Port: port}
	switch kind {
	case AddonPostgres:
		c.Username = addonDBName(app)
		c.Database = c.Username
		c.URL = fmt.Sprintf("postgresql://%s:%s@%s:%d/%s", c.Username, password, host, port, c.Database)
	case AddonMySQL:
		root, err := randomHex(16)
		if err != nil {
			return AddonCredentials{}, err
		}
		c.RootPassword = root
		c.Username = addonDBName(app)
		c.Database = c.Username
		c.URL = fmt.Sprintf("mysql://%s:%s@%s:%d/%s", c.Username, password, host, port, c.Database)
	case AddonRedis:
		c.URL = fmt.Sprintf("redis://:%s@%s:%d/0", password, host, port)
	}
	return c, nil
}

// Marshal encodes the credentials for Addon.Credentials.
func (c AddonCredentials) Marshal() (json.RawMessage, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshal addon credentials: %w", err)
	}
	return b, nil
}

// DecodeCredentials parses the stored credentials of an add-on.
func (a Addon) DecodeCredentials() (AddonCredentials, error) {
	var c AddonCredentials
	if len(a.Credentials) == 0 {
		return c, fmt.Errorf("%w: addon %s/%s has no credentials", ErrInvalid, a.App, a.Kind)
	}
	if err := json.Unmarshal(a.Credentials, &c); err != nil {
		return c, fmt.Errorf("decode addon credentials %s/%s: %w", a.App, a.Kind, err)
	}
	return c, nil
}
