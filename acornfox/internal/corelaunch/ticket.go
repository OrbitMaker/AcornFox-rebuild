package corelaunch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Ticket is written by the root Native launcher only after its generation
// reservation is durable. The inherited descriptor, not CLI text, is authority.
type Ticket struct {
	InstallationID   string `json:"installation_id"`
	ReleaseID        string `json:"release_id"`
	ManifestSHA256   string `json:"manifest_sha256"`
	ExecutableSHA256 string `json:"executable_sha256"`
	DataDirectory    string `json:"data_directory"`
	DatabaseInode    uint64 `json:"database_inode"`
	ChildPID         int    `json:"child_pid"`
	ParentPID        int    `json:"parent_pid"`
	CoreUID          int    `json:"core_uid"`
	Generation       int64  `json:"generation"`
}

var ErrInvalidTicket = errors.New("invalid Native Core launch ticket")

// ReadInherited waits for the root parent's signal after it has written and
// synced the PID-bound ticket, then validates the inherited root-only file.
func ReadInherited(ticketFD, signalFD uintptr, dataDirectory string) (Ticket, error) {
	var zero Ticket
	if ticketFD != 3 || signalFD != 4 || dataDirectory == "" {
		return zero, ErrInvalidTicket
	}
	signal := os.NewFile(signalFD, "native-launch-signal")
	if signal == nil {
		return zero, ErrInvalidTicket
	}
	defer signal.Close()
	var ready [1]byte
	if n, err := signal.Read(ready[:]); err != nil || n != 1 || ready[0] != 1 {
		return zero, ErrInvalidTicket
	}
	file := os.NewFile(ticketFD, "native-launch-ticket")
	if file == nil {
		return zero, ErrInvalidTicket
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > 4096 {
		return zero, ErrInvalidTicket
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		return zero, ErrInvalidTicket
	}
	b := make([]byte, info.Size())
	if n, err := file.ReadAt(b, 0); err != nil || n != len(b) {
		return zero, ErrInvalidTicket
	}
	var ticket Ticket
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&ticket) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return zero, ErrInvalidTicket
	}
	if ticket.ChildPID != os.Getpid() || ticket.ParentPID != os.Getppid() || ticket.CoreUID != os.Getuid() || ticket.Generation < 1 || ticket.DataDirectory != filepath.Clean(dataDirectory) || ticket.InstallationID == "" || ticket.ReleaseID == "" || len(ticket.ManifestSHA256) != 64 || len(ticket.ExecutableSHA256) != 64 {
		return zero, ErrInvalidTicket
	}
	exe, err := os.Open("/proc/self/exe")
	if err != nil {
		return zero, ErrInvalidTicket
	}
	defer exe.Close()
	h := sha256.New()
	if _, err := io.Copy(h, exe); err != nil || hex.EncodeToString(h.Sum(nil)) != ticket.ExecutableSHA256 {
		return zero, ErrInvalidTicket
	}
	db, err := os.Lstat(filepath.Join(dataDirectory, "acornfox.db"))
	if ticket.DatabaseInode == 0 {
		if !os.IsNotExist(err) {
			return zero, ErrInvalidTicket
		}
	} else {
		if err != nil || !db.Mode().IsRegular() {
			return zero, ErrInvalidTicket
		}
		identity, ok := db.Sys().(*syscall.Stat_t)
		if !ok || identity.Ino != ticket.DatabaseInode {
			return zero, ErrInvalidTicket
		}
	}
	return ticket, nil
}
