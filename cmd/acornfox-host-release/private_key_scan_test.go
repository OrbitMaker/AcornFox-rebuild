package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestHostReleasePrivateKeyScan(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	secret := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("public fixture")})
	cases := []struct {
		name   string
		data   []byte
		reject bool
	}{
		{"ordinary_diagnostic", []byte("crypto: unable to parse PRIVATE KEY type"), false},
		{"binary_diagnostic", append([]byte{0x7f, 'E', 'L', 'F', 0}, []byte("PRIVATE KEY unsupported")...), false},
		{"real_private_key", secret, true},
		{"embedded_private_key", append([]byte{'x', 0}, secret...), true},
		{"private_after_public", append(public, secret...), true},
		{"truncated_private_boundary", []byte("-----BEGIN RSA PRIVATE KEY-----"), true},
		{"private_footer", []byte("-----END OPENSSH PRIVATE KEY-----"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sub := filepath.Join(dir, "controller")
			if err := os.Mkdir(sub, 0755); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(sub, "sample.bin")
			if err := os.WriteFile(file, tc.data, 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(file, 0644); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			_, _, err = scanPayloadDirectory(root)
			if (err != nil) != tc.reject {
				t.Fatalf("reject=%v, got error=%v", tc.reject, err)
			}
		})
	}
}
