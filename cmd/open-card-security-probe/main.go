package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fail()
	}
	switch os.Args[1] {
	case "isolation":
		isolation()
	case "secret":
		if len(os.Args) != 4 {
			fail()
		}
		secret(os.Args[2], os.Args[3])
	case "sleep":
		if len(os.Args) != 2 {
			fail()
		}
		time.Sleep(30 * time.Second)
	default:
		fail()
	}
}
func isolation() {
	for _, path := range []string{"/var/run/docker.sock", "/run/docker.sock", "/dev/kvm", "/host", "/sys/class/dmi/id/product_uuid"} {
		if _, err := os.Stat(path); err == nil {
			fail()
		}
	}
	for _, address := range []string{"169.254.169.254:80", "192.168.31.1:80", "10.96.0.1:443"} {
		connection, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
		if err == nil {
			connection.Close()
			fail()
		}
	}
	for _, value := range os.Environ() {
		if strings.Contains(strings.ToLower(value), "secret") || strings.Contains(value, "OPENCARD_M1_CANARY") {
			fail()
		}
	}
	fmt.Println("isolation=pass")
}
func secret(id, expected string) {
	if id == "" || !strings.HasPrefix(expected, "sha256:") {
		fail()
	}
	value, err := os.ReadFile("/run/secrets/" + id)
	if err != nil || len(value) == 0 {
		fail()
	}
	digest := sha256.Sum256(value)
	for index := range value {
		value[index] = 0
	}
	if "sha256:"+hex.EncodeToString(digest[:]) != expected {
		fail()
	}
	fmt.Println("secret=pass")
}
func fail() { os.Exit(42) }
