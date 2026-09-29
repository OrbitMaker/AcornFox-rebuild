package capacity

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// SystemReader reads allocatable CPU, memory, and disk from the local host.
// Linux cgroup limits are honored when present, so a provider running inside a
// constrained worker does not advertise the physical host's full capacity.
type SystemReader struct{}

// LinuxReader is an explicit alias for deployments that want to document the
// operating-system boundary in their wiring.
type LinuxReader = SystemReader

func NewSystemReader() SystemReader { return SystemReader{} }

func (SystemReader) Read(ctx context.Context, diskPath string) (HostCapacity, error) {
	if err := ctx.Err(); err != nil {
		return HostCapacity{}, err
	}
	cpu, err := readCPU()
	if err != nil {
		return HostCapacity{}, fmt.Errorf("read CPU capacity: %w", err)
	}
	memory, err := readMemory()
	if err != nil {
		return HostCapacity{}, fmt.Errorf("read memory capacity: %w", err)
	}
	disk, err := readDisk(diskPath)
	if err != nil {
		return HostCapacity{}, fmt.Errorf("read disk capacity: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return HostCapacity{}, err
	}
	return HostCapacity{
		TotalCPUMillis:       cpu.total,
		AvailableCPUMillis:   cpu.available,
		TotalMemoryBytes:     memory.total,
		AvailableMemoryBytes: memory.available,
		TotalDiskBytes:       disk.total,
		AvailableDiskBytes:   disk.available,
	}, nil
}

type quantity struct {
	total     int64
	available int64
}

func readCPU() (quantity, error) {
	processors := runtime.NumCPU()
	if processors < 1 {
		return quantity{}, errors.New("runtime reported no CPUs")
	}
	total := int64(processors) * 1000
	if quota, ok := cgroupCPUQuota(); ok && quota > 0 && quota < total {
		total = quota
	}
	return quantity{total: total, available: total}, nil
}

func cgroupCPUQuota() (int64, bool) {
	if value, ok := readCgroupPair("/sys/fs/cgroup/cpu.max"); ok {
		return value, true
	}
	quotaBytes, err := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	if err != nil {
		return 0, false
	}
	periodBytes, err := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if err != nil {
		return 0, false
	}
	quota, err := strconv.ParseInt(strings.TrimSpace(string(quotaBytes)), 10, 64)
	if err != nil || quota <= 0 {
		return 0, false
	}
	period, err := strconv.ParseInt(strings.TrimSpace(string(periodBytes)), 10, 64)
	if err != nil || period <= 0 {
		return 0, false
	}
	return cpuQuotaMillis(quota, period), true
}

func readCgroupPair(path string) (int64, bool) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	parts := strings.Fields(string(contents))
	if len(parts) != 2 || parts[0] == "max" {
		return 0, false
	}
	quota, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || quota <= 0 {
		return 0, false
	}
	period, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || period <= 0 {
		return 0, false
	}
	return cpuQuotaMillis(quota, period), true
}

func cpuQuotaMillis(quota, period int64) int64 {
	if quota <= 0 || period <= 0 {
		return 0
	}
	// Round down to keep capacity checks fail closed.  A fractional CPU still
	// gets one allocatable millisecond instead of becoming an unusable zero.
	value := quota * 1000 / period
	if value < 1 {
		return 1
	}
	return value
}

func readMemory() (quantity, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return quantity{}, err
	}
	defer file.Close()
	values := map[string]int64{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, parseErr := strconv.ParseInt(fields[1], 10, 64)
		if parseErr != nil || value < 0 {
			continue
		}
		// Linux /proc/meminfo uses kB for these fields.  Be conservative if a
		// test fixture omits the unit and gives bytes directly.
		if len(fields) >= 3 && strings.EqualFold(fields[2], "kb") {
			value *= 1024
		}
		values[strings.TrimSuffix(fields[0], ":")] = value
	}
	if err := scanner.Err(); err != nil {
		return quantity{}, err
	}
	total := values["MemTotal"]
	available := values["MemAvailable"]
	if available == 0 {
		available = values["MemFree"] + values["Buffers"] + values["Cached"]
	}
	if total <= 0 || available < 0 {
		return quantity{}, errors.New("/proc/meminfo did not contain usable memory totals")
	}
	if limit, current, ok := cgroupMemoryLimit(); ok && limit > 0 && limit < total {
		total = limit
		if current >= limit {
			available = 0
		} else if remaining := limit - current; remaining < available {
			available = remaining
		}
	}
	if available > total {
		available = total
	}
	return quantity{total: total, available: available}, nil
}

func cgroupMemoryLimit() (limit, current int64, ok bool) {
	limitBytes, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	if err != nil {
		return 0, 0, false
	}
	limitText := strings.TrimSpace(string(limitBytes))
	if limitText == "max" {
		return 0, 0, false
	}
	parsedLimit, err := strconv.ParseInt(limitText, 10, 64)
	if err != nil || parsedLimit <= 0 {
		return 0, 0, false
	}
	currentBytes, err := os.ReadFile("/sys/fs/cgroup/memory.current")
	if err != nil {
		return parsedLimit, 0, true
	}
	parsedCurrent, err := strconv.ParseInt(strings.TrimSpace(string(currentBytes)), 10, 64)
	if err != nil || parsedCurrent < 0 {
		parsedCurrent = 0
	}
	return parsedLimit, parsedCurrent, true
}

func readDisk(path string) (quantity, error) {
	if strings.TrimSpace(path) == "" {
		path = "/"
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return quantity{}, err
	}
	blockSize := uint64(stat.Bsize)
	total, err := multiplyBytes(uint64(stat.Blocks), blockSize)
	if err != nil {
		return quantity{}, err
	}
	available, err := multiplyBytes(uint64(stat.Bavail), blockSize)
	if err != nil {
		return quantity{}, err
	}
	if total <= 0 || available < 0 || available > total {
		return quantity{}, errors.New("filesystem reported invalid disk totals")
	}
	return quantity{total: total, available: available}, nil
}

func multiplyBytes(left, right uint64) (int64, error) {
	if left != 0 && right > uint64(1<<63-1)/left {
		return 0, errors.New("filesystem byte count overflow")
	}
	return int64(left * right), nil
}
