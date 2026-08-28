package main

import (
	"testing"
	"time"
)

func TestM4LogStoreConfigKeepsProductionDefaultsAndBoundsTestOverrides(t *testing.T) {
	config, err := m4LogStoreConfig("/var/lib/open-card/logs", "", "")
	if err != nil || config.MaxFileBytes != m4DefaultLogFileBytes || config.MaxTotalBytes != m4DefaultLogTotalBytes || config.MaxBuildFiles != 20 {
		t.Fatalf("default M4 log config=%#v err=%v", config, err)
	}
	config, err = m4LogStoreConfig("/var/lib/open-card/logs", "256", "1048576")
	if err != nil || config.MaxFileBytes != 256 || config.MaxTotalBytes != 1048576 {
		t.Fatalf("bounded M4 log config=%#v err=%v", config, err)
	}
	for _, values := range [][2]string{{"63", "1048576"}, {"256", "128"}, {"not-a-number", "1048576"}} {
		if _, err := m4LogStoreConfig("/var/lib/open-card/logs", values[0], values[1]); err == nil {
			t.Fatalf("unsafe M4 log config accepted: %#v", values)
		}
	}
}

func TestM4LogCollectionIntervalIsBounded(t *testing.T) {
	if value, err := m4LogCollectionInterval(""); err != nil || value != 30*time.Second {
		t.Fatalf("default interval=%v err=%v", value, err)
	}
	if value, err := m4LogCollectionInterval("1s"); err != nil || value != time.Second {
		t.Fatalf("test interval=%v err=%v", value, err)
	}
	for _, value := range []string{"999ms", "6m", "invalid"} {
		if _, err := m4LogCollectionInterval(value); err == nil {
			t.Fatalf("unsafe interval accepted: %s", value)
		}
	}
}
