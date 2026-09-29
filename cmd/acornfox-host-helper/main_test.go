package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestHelperRuntimeConfigLoad(t *testing.T) {
	tempDir := t.TempDir()
	cfgFile := filepath.Join(tempDir, "pack-runtime.json")

	raw := `{
		"socket_path": "/tmp/helper.sock",
		"state_dir": "/tmp/state",
		"packs_dir": "/tmp/packs",
		"core_uid": 1000,
		"core_gid": 1000,
		"trusted_core_executable_sha": "abc123",
		"installation_binding": "binding123",
		"publishers": [
			{
				"publisher": "test-pub",
				"public_key": "dGVzdC1wdWItZWRwMjU1MTktMzJieXRlcy1rZXk=",
				"allowed_hosts": ["test.invalid"]
			}
		]
	}`
	if err := os.WriteFile(cfgFile, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatal(err)
	}

	var cfg runtimeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}

	if cfg.SocketPath != "/tmp/helper.sock" || cfg.CoreUID != 1000 || len(cfg.Publishers) != 1 {
		t.Fatalf("unexpected config parsed: %+v", cfg)
	}
}
