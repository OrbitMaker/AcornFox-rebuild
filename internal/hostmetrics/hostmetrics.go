// Package hostmetrics samples a small, read-only projection of host health.
// It intentionally has no network, command, or privilege boundary.
package hostmetrics

import (
	"bufio"
	"context"
	"errors"
	"math"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultSampleInterval = 5 * time.Second
	DefaultStaleAfter     = 15 * time.Second
	maxProcFileBytes      = 64 << 10
)

// Reader isolates the fixed Linux files and root filesystem stat for tests.
// Implementations must return at most limit bytes from ReadFile.
type Reader interface {
	ReadFile(path string, limit int64) ([]byte, error)
	Statfs(path string) (Filesystem, error)
}

// Filesystem is the subset of statfs needed for the root volume projection.
type Filesystem struct {
	Blocks          uint64
	AvailableBlocks uint64
	BlockSize       uint64
}

type Config struct {
	Reader         Reader
	OS             string
	Now            func() time.Time
	LogicalCores   func() int
	SampleInterval time.Duration
	StaleAfter     time.Duration
}

type Availability string

const (
	Available   Availability = "available"
	WarmingUp   Availability = "warming_up"
	Unavailable Availability = "unavailable"
	Unsupported Availability = "unsupported"
)

// Response is the JSON shape for GET /api/v1/acornfox/host/metrics.
type Response struct {
	SchemaVersion     int          `json:"schema_version"`
	Availability      Availability `json:"availability"`
	ObservedAt        *time.Time   `json:"observed_at,omitempty"`
	StaleAfterSeconds int          `json:"stale_after_seconds"`
	CPU               *CPU         `json:"cpu,omitempty"`
	Memory            *Memory      `json:"memory,omitempty"`
	Disk              *Disk        `json:"disk,omitempty"`
	Network           *Network     `json:"network,omitempty"`
}

type CPU struct {
	LogicalCores int      `json:"logical_cores"`
	UsagePercent *float64 `json:"usage_percent,omitempty"`
}

type Memory struct {
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
	UsedBytes      uint64 `json:"used_bytes"`
}

type Disk struct {
	Mountpoint string `json:"mountpoint"`
	TotalBytes uint64 `json:"total_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
	UsedBytes  uint64 `json:"used_bytes"`
}

type Network struct {
	Interface        string   `json:"interface"`
	RXBytesPerSecond *float64 `json:"rx_bytes_per_second,omitempty"`
	TXBytesPerSecond *float64 `json:"tx_bytes_per_second,omitempty"`
}

type cpuCounters struct{ total, idle uint64 }
type networkCounters struct {
	interfaceName string
	rx, tx        uint64
}
type rawSample struct {
	at      time.Time
	cpu     cpuCounters
	cores   int
	memory  Memory
	disk    Disk
	network *networkCounters
}
type recordedSample struct {
	raw    rawSample
	cpuUse *float64
	netRX  *float64
	netTX  *float64
}

// Sampler owns the only proc and filesystem reads. Snapshot never performs IO.
type Sampler struct {
	reader       Reader
	os           string
	now          func() time.Time
	logicalCores func() int
	interval     time.Duration
	staleAfter   time.Duration

	mu       sync.RWMutex
	latest   *recordedSample
	previous *rawSample
	failed   bool
	start    sync.Once
}

func NewSampler(config Config) *Sampler {
	reader := config.Reader
	if reader == nil {
		reader = defaultReader()
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	cores := config.LogicalCores
	if cores == nil {
		cores = runtime.NumCPU
	}
	if config.OS == "" {
		config.OS = runtime.GOOS
	}
	if config.SampleInterval <= 0 {
		config.SampleInterval = DefaultSampleInterval
	}
	if config.StaleAfter <= 0 {
		config.StaleAfter = DefaultStaleAfter
	}
	return &Sampler{reader: reader, os: config.OS, now: now, logicalCores: cores, interval: config.SampleInterval, staleAfter: config.StaleAfter}
}

// Start schedules an immediate sample and then samples until ctx is done.
// Calling Start more than once is safe and creates only one worker.
func (s *Sampler) Start(ctx context.Context) {
	if s == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.start.Do(func() {
		go func() {
			s.sample(ctx)
			ticker := time.NewTicker(s.interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					s.sample(ctx)
				}
			}
		}()
	})
}

// Sample is available for controlled startup and tests. HTTP handlers must use
// Snapshot instead so serving a request never reads proc or the filesystem.
func (s *Sampler) Sample(ctx context.Context) {
	if s != nil {
		s.sample(ctx)
	}
}

func (s *Sampler) sample(ctx context.Context) {
	if ctx != nil && ctx.Err() != nil {
		return
	}
	if s.os != "linux" {
		return
	}
	value, err := s.collect()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.latest, s.previous, s.failed = nil, nil, true
		return
	}
	recorded := &recordedSample{raw: value}
	if s.previous != nil {
		recorded.cpuUse = cpuUsage(s.previous.cpu, value.cpu)
		recorded.netRX, recorded.netTX = networkRates(*s.previous, value)
	}
	s.latest = recorded
	s.failed = false
	copy := value
	if value.network != nil {
		network := *value.network
		copy.network = &network
	}
	s.previous = &copy
}

func (s *Sampler) collect() (rawSample, error) {
	stat, err := s.read("/proc/stat")
	if err != nil {
		return rawSample{}, err
	}
	cpu, err := parseCPU(stat)
	if err != nil {
		return rawSample{}, err
	}
	meminfo, err := s.read("/proc/meminfo")
	if err != nil {
		return rawSample{}, err
	}
	memory, err := parseMemory(meminfo)
	if err != nil {
		return rawSample{}, err
	}
	filesystem, err := s.reader.Statfs("/")
	if err != nil {
		return rawSample{}, err
	}
	disk, err := parseDisk(filesystem)
	if err != nil {
		return rawSample{}, err
	}
	value := rawSample{at: s.now().UTC(), cpu: cpu, cores: s.logicalCores(), memory: memory, disk: disk}
	if value.cores < 1 {
		return rawSample{}, errors.New("invalid logical core count")
	}
	if route, err := s.read("/proc/net/route"); err == nil {
		if name, routeErr := parseDefaultInterface(route); routeErr == nil {
			if dev, devErr := s.read("/proc/net/dev"); devErr == nil {
				if rx, tx, devParseErr := parseInterfaceBytes(dev, name); devParseErr == nil {
					value.network = &networkCounters{interfaceName: name, rx: rx, tx: tx}
				}
			}
		}
	}
	return value, nil
}

func (s *Sampler) read(path string) ([]byte, error) {
	value, err := s.reader.ReadFile(path, maxProcFileBytes)
	if err != nil || len(value) > maxProcFileBytes {
		return nil, errors.New("host metric input unavailable")
	}
	return value, nil
}

func (s *Sampler) Snapshot() Response {
	if s == nil {
		return unavailableResponse(DefaultStaleAfter, nil)
	}
	if s.os != "linux" {
		return Response{SchemaVersion: 1, Availability: Unsupported, StaleAfterSeconds: seconds(s.staleAfter)}
	}
	s.mu.RLock()
	value := s.latest
	failed := s.failed
	if value != nil {
		copy := *value
		value = &copy
	}
	s.mu.RUnlock()
	if value == nil {
		if failed {
			return unavailableResponse(s.staleAfter, nil)
		}
		return Response{SchemaVersion: 1, Availability: WarmingUp, StaleAfterSeconds: seconds(s.staleAfter)}
	}
	observed := value.raw.at.UTC()
	if s.now().Sub(observed) > s.staleAfter {
		return unavailableResponse(s.staleAfter, &observed)
	}
	cpu := CPU{LogicalCores: value.raw.cores, UsagePercent: copyFloat(value.cpuUse)}
	memory := value.raw.memory
	disk := value.raw.disk
	var network *Network
	if value.raw.network != nil {
		network = &Network{Interface: value.raw.network.interfaceName, RXBytesPerSecond: copyFloat(value.netRX), TXBytesPerSecond: copyFloat(value.netTX)}
	}
	availability := Available
	if cpu.UsagePercent == nil {
		availability = WarmingUp
	}
	return Response{SchemaVersion: 1, Availability: availability, ObservedAt: &observed, StaleAfterSeconds: seconds(s.staleAfter), CPU: &cpu, Memory: &memory, Disk: &disk, Network: network}
}

func unavailableResponse(staleAfter time.Duration, observed *time.Time) Response {
	return Response{SchemaVersion: 1, Availability: Unavailable, ObservedAt: observed, StaleAfterSeconds: seconds(staleAfter)}
}

func seconds(value time.Duration) int {
	if value <= 0 {
		return int(DefaultStaleAfter / time.Second)
	}
	return int(value / time.Second)
}

func copyFloat(value *float64) *float64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cpuUsage(previous, current cpuCounters) *float64 {
	if current.total <= previous.total || current.idle < previous.idle {
		return nil
	}
	total := current.total - previous.total
	idle := current.idle - previous.idle
	if total == 0 || idle > total {
		return nil
	}
	value := math.Round((float64(total-idle)/float64(total))*10000) / 100
	return &value
}

func networkRates(previous rawSample, current rawSample) (*float64, *float64) {
	if previous.network == nil || current.network == nil || previous.network.interfaceName != current.network.interfaceName || !current.at.After(previous.at) || current.network.rx < previous.network.rx || current.network.tx < previous.network.tx {
		return nil, nil
	}
	seconds := current.at.Sub(previous.at).Seconds()
	rx := math.Round((float64(current.network.rx-previous.network.rx)/seconds)*100) / 100
	tx := math.Round((float64(current.network.tx-previous.network.tx)/seconds)*100) / 100
	return &rx, &tx
}

func parseCPU(value []byte) (cpuCounters, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(value)))
	scanner.Buffer(make([]byte, 1024), 8192)
	if !scanner.Scan() {
		return cpuCounters{}, errors.New("missing cpu line")
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuCounters{}, errors.New("invalid cpu line")
	}
	var total uint64
	var idle uint64
	// guest and guest_nice, when present, are already included in user and
	// nice respectively. Count through steal only to avoid double-counting.
	end := len(fields)
	if end > 9 { // label plus user..steal
		end = 9
	}
	for index, field := range fields[1:end] {
		parsed, err := strconv.ParseUint(field, 10, 64)
		if err != nil || math.MaxUint64-total < parsed {
			return cpuCounters{}, errors.New("invalid cpu counter")
		}
		total += parsed
		if index == 3 || index == 4 { // idle and iowait
			if math.MaxUint64-idle < parsed {
				return cpuCounters{}, errors.New("invalid cpu counter")
			}
			idle += parsed
		}
	}
	if total == 0 || idle > total {
		return cpuCounters{}, errors.New("invalid cpu counters")
	}
	return cpuCounters{total: total, idle: idle}, nil
}

func parseMemory(value []byte) (Memory, error) {
	var total, available uint64
	foundTotal, foundAvailable := false, false
	scanner := bufio.NewScanner(strings.NewReader(string(value)))
	scanner.Buffer(make([]byte, 1024), 8192)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || fields[2] != "kB" {
			continue
		}
		parsed, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || parsed > math.MaxUint64/1024 {
			return Memory{}, errors.New("invalid memory counter")
		}
		switch fields[0] {
		case "MemTotal:":
			total, foundTotal = parsed*1024, true
		case "MemAvailable:":
			available, foundAvailable = parsed*1024, true
		}
	}
	if scanner.Err() != nil || !foundTotal || !foundAvailable || total == 0 || available > total {
		return Memory{}, errors.New("invalid memory counters")
	}
	return Memory{TotalBytes: total, AvailableBytes: available, UsedBytes: total - available}, nil
}

func parseDisk(value Filesystem) (Disk, error) {
	if value.Blocks == 0 || value.BlockSize == 0 || value.Blocks > math.MaxUint64/value.BlockSize || value.AvailableBlocks > value.Blocks || value.AvailableBlocks > math.MaxUint64/value.BlockSize {
		return Disk{}, errors.New("invalid filesystem counters")
	}
	total, free := value.Blocks*value.BlockSize, value.AvailableBlocks*value.BlockSize
	return Disk{Mountpoint: "/", TotalBytes: total, FreeBytes: free, UsedBytes: total - free}, nil
}

func parseDefaultInterface(value []byte) (string, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(value)))
	scanner.Buffer(make([]byte, 1024), 8192)
	if !scanner.Scan() { // header
		return "", errors.New("missing route header")
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 64)
		if err != nil || flags&1 == 0 || !validInterfaceName(fields[0]) {
			continue
		}
		return fields[0], nil
	}
	return "", errors.New("no default route")
}

func parseInterfaceBytes(value []byte, name string) (uint64, uint64, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(value)))
	scanner.Buffer(make([]byte, 1024), 8192)
	for scanner.Scan() {
		line := scanner.Text()
		left, right, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(left) != name {
			continue
		}
		fields := strings.Fields(right)
		if len(fields) < 9 {
			return 0, 0, errors.New("invalid network counters")
		}
		rx, rxErr := strconv.ParseUint(fields[0], 10, 64)
		tx, txErr := strconv.ParseUint(fields[8], 10, 64)
		if rxErr != nil || txErr != nil {
			return 0, 0, errors.New("invalid network counters")
		}
		return rx, tx, nil
	}
	return 0, 0, errors.New("network interface unavailable")
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-' || char == '.') {
			return false
		}
	}
	return true
}
