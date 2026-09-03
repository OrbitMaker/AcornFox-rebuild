package main

import (
	"testing"
	"time"

	"github.com/open-card/open-card/internal/acornfoxenv"
)

func TestM4LogStoreConfigKeepsProductionDefaultsAndBoundsTestOverrides(t *testing.T) {
	values := map[acornfoxenv.Key]string{}
	getenv := func(key acornfoxenv.Key) string { return values[key] }
	legacy := acornfoxenv.Environment{}
	config, err := m4LogStoreConfig("/var/lib/open-card/logs", getenv, legacy)
	if err != nil || config.MaxFileBytes != m4DefaultLogFileBytes || config.MaxTotalBytes != m4DefaultLogTotalBytes || config.MaxBuildFiles != 20 {
		t.Fatalf("default M4 log config=%#v err=%v", config, err)
	}
	values[acornfoxenv.LogMaxFileBytes], values[acornfoxenv.LogMaxTotalBytes] = "256", "1048576"
	config, err = m4LogStoreConfig("/var/lib/open-card/logs", getenv, legacy)
	if err != nil || config.MaxFileBytes != 256 || config.MaxTotalBytes != 1048576 {
		t.Fatalf("bounded M4 log config=%#v err=%v", config, err)
	}
	for _, values := range [][2]string{{"63", "1048576"}, {"256", "128"}, {"not-a-number", "1048576"}} {
		values := map[acornfoxenv.Key]string{acornfoxenv.LogMaxFileBytes: values[0], acornfoxenv.LogMaxTotalBytes: values[1]}
		if _, err := m4LogStoreConfig("/var/lib/open-card/logs", func(key acornfoxenv.Key) string { return values[key] }, legacy); err == nil {
			t.Fatalf("unsafe M4 log config accepted: %#v", values)
		}
	}
}

func TestM4LogCollectionIntervalIsBounded(t *testing.T) {
	legacy := acornfoxenv.Environment{}
	if value, err := m4LogCollectionInterval("", legacy); err != nil || value != 30*time.Second {
		t.Fatalf("default interval=%v err=%v", value, err)
	}
	if value, err := m4LogCollectionInterval("1s", legacy); err != nil || value != time.Second {
		t.Fatalf("test interval=%v err=%v", value, err)
	}
	for _, value := range []string{"999ms", "6m", "invalid"} {
		if _, err := m4LogCollectionInterval(value, legacy); err == nil {
			t.Fatalf("unsafe interval accepted: %s", value)
		}
	}
}
