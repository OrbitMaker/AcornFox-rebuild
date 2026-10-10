package publicconsole

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Config is the persisted public console configuration. It exists only while
// the public console is enabled. The password is stored as a SHA-256 digest:
// it is generated with well over 120 bits of entropy, so a slow hash adds
// nothing.
type Config struct {
	Domain         string          `json:"domain"`
	PasswordSHA256 string          `json:"password_sha256"`
	EnabledAt      time.Time       `json:"enabled_at"`
	Sessions       []IssuedSession `json:"sessions,omitempty"` // sessions issued by the gateway
}

// IssuedSession records one console session created through the public
// login, by the SHA-256 digest of its secret.
type IssuedSession struct {
	Digest   string    `json:"digest"`
	IssuedAt time.Time `json:"issued_at"`
}

// HasSession reports whether the session with this digest was issued by the
// gateway under the current configuration.
func (c *Config) HasSession(digest string) bool {
	for _, s := range c.Sessions {
		if subtle.ConstantTimeCompare([]byte(s.Digest), []byte(digest)) == 1 {
			return true
		}
	}
	return false
}

// FileStore keeps Config in one 0600 JSON file under the data directory, so
// upgrades (which never touch the data directory) keep it.
type FileStore struct {
	path string
	mu   sync.Mutex
}

// NewFileStore returns a store at path.
func NewFileStore(path string) *FileStore { return &FileStore{path: path} }

// Load returns the configuration, or nil when the public console is off.
func (s *FileStore) Load() (*Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

func (s *FileStore) load() (*Config, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取公网控制台配置失败：%w", err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("公网控制台配置损坏：%w", err)
	}
	return &c, nil
}

// Save replaces the configuration atomically.
func (s *FileStore) Save(c *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save(c)
}

func (s *FileStore) save(c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".public-console-*.json")
	if err != nil {
		return fmt.Errorf("写入公网控制台配置失败：%w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// Update loads, mutates and saves under one lock. fn is not called when the
// public console is off.
func (s *FileStore) Update(fn func(*Config)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.load()
	if err != nil || c == nil {
		return err
	}
	fn(c)
	return s.save(c)
}

// Delete removes the configuration; a no-op when absent.
func (s *FileStore) Delete() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// passwordAlphabet omits look-alike characters (0/O, 1/l/I).
const passwordAlphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// GeneratePassword returns 24 random characters from a 55-letter alphabet
// (about 138 bits), grouped by dashes for reading: xxxxxx-xxxxxx-xxxxxx-xxxxxx.
func GeneratePassword() (string, error) {
	var b strings.Builder
	max := big.NewInt(int64(len(passwordAlphabet)))
	for i := 0; i < 24; i++ {
		if i > 0 && i%6 == 0 {
			b.WriteByte('-')
		}
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(passwordAlphabet[n.Int64()])
	}
	return b.String(), nil
}

// Digest is the lowercase hex SHA-256 of s (same as the state package uses for
// console session secrets).
func Digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// CheckPassword compares password with the stored digest in constant time.
func (c *Config) CheckPassword(password string) bool {
	return subtle.ConstantTimeCompare([]byte(Digest(password)), []byte(c.PasswordSHA256)) == 1
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
