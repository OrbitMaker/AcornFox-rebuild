//go:build !windows

package main

import (
	"strings"
	"testing"
)

func TestValidateTrustedListen(t *testing.T) {
	valid := []string{
		"unix:/run/acornfox/api.sock",
		"/run/acornfox/api.sock",
	}
	for _, addr := range valid {
		if err := validateTrustedListen(addr); err != nil {
			t.Errorf("validateTrustedListen(%q) = %v, want nil", addr, err)
		}
	}

	// TCP addresses must be rejected with guidance to -console-listen.
	tcp := []string{"127.0.0.1:18800", "localhost:8080", "[::1]:9000", "0.0.0.0:80"}
	for _, addr := range tcp {
		err := validateTrustedListen(addr)
		if err == nil {
			t.Errorf("validateTrustedListen(%q) = nil, want error", addr)
			continue
		}
		if !strings.Contains(err.Error(), "-console-listen") {
			t.Errorf("error for %q does not mention -console-listen: %v", addr, err)
		}
	}
}

func TestValidateConsoleListen(t *testing.T) {
	valid := []string{
		"", // disabled
		"127.0.0.1:18800",
		"localhost:5000",
		"[::1]:9000",
	}
	for _, addr := range valid {
		if err := validateConsoleListen(addr); err != nil {
			t.Errorf("validateConsoleListen(%q) = %v, want nil", addr, err)
		}
	}

	invalid := []string{
		"0.0.0.0:18800",
		"192.168.1.10:18800",
		"example.com:80",
		"127.0.0.1", // no port
		"notanaddr",
	}
	for _, addr := range invalid {
		if err := validateConsoleListen(addr); err == nil {
			t.Errorf("validateConsoleListen(%q) = nil, want error", addr)
		}
	}
}
