package apiserver

import (
	"errors"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

type cpuSource struct{ stat string }

func (s *cpuSource) readFile(path string) ([]byte, error) {
	if path != "/proc/stat" {
		return nil, errors.New("not supplied")
	}
	return []byte(s.stat), nil
}
func (*cpuSource) statfs(string) (unix.Statfs_t, error) {
	return unix.Statfs_t{}, errors.New("not supplied")
}

func TestHostCPUDeltaFirstSampleAndReset(t *testing.T) {
	source := &cpuSource{stat: "cpu 100 0 0 100 0 0 0 0 50 0\n"}
	provider := &procHostProvider{src: source}
	if _, ok := provider.readCPUPercent(); ok {
		t.Fatal("first sample is not a rate")
	}
	source.stat = "cpu 110 0 0 190 0 0 0 0 100 0\n"
	value, ok := provider.readCPUPercent()
	if !ok || value != 10 {
		t.Fatalf("delta value=%v ok=%v", value, ok)
	}
	if _, ok := provider.readCPUPercent(); ok {
		t.Fatal("unchanged counters are not a new sample")
	}
	source.stat = "cpu 10 0 0 20 0 0 0 0\n"
	if _, ok := provider.readCPUPercent(); ok {
		t.Fatal("counter reset is not a valid rate")
	}
}

func TestHostCPUSamplingConcurrentReaders(t *testing.T) {
	provider := &procHostProvider{src: &cpuSource{stat: "cpu 10 0 0 20 0 0 0 0\n"}}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); provider.readCPUPercent() }()
	}
	wg.Wait()
}

func TestHostCPUDoesNotDoubleCountGuest(t *testing.T) {
	total, idle, ok := parseCPUCounter([]byte("cpu 10 20 30 40 50 60 70 80 999 999\n"))
	if !ok || total != 360 || idle != 90 {
		t.Fatalf("total=%d idle=%d ok=%v", total, idle, ok)
	}
}
