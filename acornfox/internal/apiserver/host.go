package apiserver

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// HostView is the wire shape of GET /v1/host. On any error the provider returns
// Available=false and the numeric fields are omitted.
type HostView struct {
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
	src     procSource
	dataDir string
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
	}
	if diskOK {
		v.DiskUsed = &diskUsed
		v.DiskTotal = &diskTotal
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

// readCPUPercent computes utilisation from a single /proc/stat aggregate line:
// (total-idle)/total since boot. This is an average since boot rather than an
// instantaneous rate, but it needs no second sample and never fails a request.
func (p *procHostProvider) readCPUPercent() (float64, bool) {
	data, err := p.src.readFile("/proc/stat")
	if err != nil {
		return 0, false
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	if !sc.Scan() {
		return 0, false
	}
	f := strings.Fields(sc.Text())
	if len(f) < 5 || f[0] != "cpu" {
		return 0, false
	}
	var total, idle uint64
	end := len(f)
	if end > 9 {
		end = 9
	}
	for i, s := range f[1:end] {
		n, perr := strconv.ParseUint(s, 10, 64)
		if perr != nil {
			return 0, false
		}
		total += n
		if i == 3 || i == 4 { // idle + iowait
			idle += n
		}
	}
	if total == 0 || idle > total {
		return 0, false
	}
	pct := float64(total-idle) / float64(total) * 100
	// Round to two decimals.
	pct = float64(int64(pct*100+0.5)) / 100
	return pct, true
}
