package apiserver

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// HostView is the wire shape of GET /v1/host. On any error the provider returns
// Available=false and the numeric fields are omitted.
type HostView struct {
	MemoryPercent *float64 `json:"memory_percent,omitempty"`
	DiskPercent   *float64 `json:"disk_percent,omitempty"`
	Available     bool     `json:"available"`
	CPUPercent    *float64 `json:"cpu_percent,omitempty"`
	MemoryUsed    *uint64  `json:"memory_used,omitempty"`
	MemoryTotal   *uint64  `json:"memory_total,omitempty"`
	DiskUsed      *uint64  `json:"disk_used,omitempty"`
	DiskTotal     *uint64  `json:"disk_total,omitempty"`
	Load1         *float64 `json:"load1,omitempty"`
	UptimeSeconds *float64 `json:"uptime_seconds,omitempty"`
}

// getHost implements GET /v1/host.
func (s *server) getHost(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.hostMetrics.Host(r.Context()))
}

// procSource abstracts the OS-specific reads so tests can supply fakes.
type procSource interface {
	readFile(path string) ([]byte, error)
	statfs(path string) (unix.Statfs_t, error)
}

// osProcSource reads real files and statfs.
type osProcSource struct{}

func (osProcSource) readFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (osProcSource) statfs(path string) (unix.Statfs_t, error) {
	var st unix.Statfs_t
	err := unix.Statfs(path, &st)
	return st, err
}

// procHostProvider reads host metrics from /proc and statfs on a data dir.
// A single-shot CPU reading needs two samples; to keep GET /v1/host cheap and
// side-effect free it reports CPU only when it can take a brief second sample.
type procHostProvider struct {
	cpuMu         sync.Mutex
	previousTotal uint64
	previousIdle  uint64
	hasPrevious   bool
	src           procSource
	dataDir       string
}

func newProcHostProvider(dataDir string) *procHostProvider {
	if dataDir == "" {
		dataDir = "/"
	}
	return &procHostProvider{src: osProcSource{}, dataDir: dataDir}
}

// Host returns a best-effort snapshot. Any failure to read the core files marks
// the whole snapshot unavailable; individual optional metrics that fail are
// simply omitted.
func (p *procHostProvider) Host(ctx context.Context) HostView {
	memTotal, memAvail, memOK := p.readMemory()
	diskUsed, diskTotal, diskOK := p.readDisk()
	if !memOK && !diskOK {
		return HostView{Available: false}
	}
	v := HostView{Available: true}
	if memOK {
		used := memTotal - memAvail
		v.MemoryUsed = &used
		v.MemoryTotal = &memTotal
		if memTotal > 0 {
			percent := float64(used) / float64(memTotal) * 100
			v.MemoryPercent = &percent
		}
	}
	if diskOK {
		v.DiskUsed = &diskUsed
		v.DiskTotal = &diskTotal
		if diskTotal > 0 {
			percent := float64(diskUsed) / float64(diskTotal) * 100
			v.DiskPercent = &percent
		}
	}
	if load1, ok := p.readLoad1(); ok {
		v.Load1 = &load1
	}
	if up, ok := p.readUptime(); ok {
		v.UptimeSeconds = &up
	}
	if cpu, ok := p.readCPUPercent(); ok {
		v.CPUPercent = &cpu
	}
	return v
}

func (p *procHostProvider) readMemory() (total, avail uint64, ok bool) {
	data, err := p.src.readFile("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	var foundTotal, foundAvail bool
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		kb, perr := strconv.ParseUint(f[1], 10, 64)
		if perr != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total, foundTotal = kb*1024, true
		case "MemAvailable:":
			avail, foundAvail = kb*1024, true
		}
	}
	if !foundTotal || !foundAvail || total == 0 || avail > total {
		return 0, 0, false
	}
	return total, avail, true
}

func (p *procHostProvider) readDisk() (used, total uint64, ok bool) {
	st, err := p.src.statfs(p.dataDir)
	if err != nil || st.Blocks == 0 || st.Bsize <= 0 {
		return 0, 0, false
	}
	bs := uint64(st.Bsize)
	total = st.Blocks * bs
	free := st.Bavail * bs
	if free > total {
		return 0, 0, false
	}
	return total - free, total, true
}

func (p *procHostProvider) readLoad1() (float64, bool) {
	data, err := p.src.readFile("/proc/loadavg")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(data))
	if len(f) < 1 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func (p *procHostProvider) readUptime() (float64, bool) {
	data, err := p.src.readFile("/proc/uptime")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(data))
	if len(f) < 1 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// readCPUPercent measures changes between requests, never the average since boot.
// The first request and reset/unchanged counters intentionally omit CPU.
func (p *procHostProvider) readCPUPercent() (float64, bool) {
	p.cpuMu.Lock()
	defer p.cpuMu.Unlock()
	data, err := p.src.readFile("/proc/stat")
	if err != nil {
		return 0, false
	}
	total, idle, ok := parseCPUCounter(data)
	if !ok {
		return 0, false
	}
	previousTotal, previousIdle, hasPrevious := p.previousTotal, p.previousIdle, p.hasPrevious
	p.previousTotal, p.previousIdle, p.hasPrevious = total, idle, true
	if !hasPrevious || total <= previousTotal || idle < previousIdle {
		return 0, false
	}
	dt, di := total-previousTotal, idle-previousIdle
	if di > dt {
		return 0, false
	}
	return float64(dt-di) / float64(dt) * 100, true
}

func parseCPUCounter(data []byte) (total, idle uint64, ok bool) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	if !sc.Scan() {
		return 0, 0, false
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	// Guest times are already included in user/nice, so do not double-count.
	end := len(fields)
	if end > 9 {
		end = 9
	}
	for i, s := range fields[1:end] {
		value, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		total += value
		if i == 3 || i == 4 {
			idle += value
		}
	}
	return total, idle, total > 0 && idle <= total
}
