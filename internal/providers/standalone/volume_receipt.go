package standalone

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"io"
	"os"
	"path/filepath"
)

type runtimeVolumeClaim struct {
	ApplicationID domain.ID            `json:"application_id"`
	LogicalName   string               `json:"logical_name"`
	Volume        contracts.VolumeSpec `json:"volume"`
}

func runtimeVolumeClaimFor(prefix string, spec contracts.RuntimeSpec, v contracts.AcornFoxRuntimeVolume) runtimeVolumeClaim {
	return runtimeVolumeClaim{spec.ApplicationID, v.Name, runtimeVolumeSpec(prefix, spec, v)}
}
func (p *Provider) runtimeVolumeReceiptPath(claim runtimeVolumeClaim) string {
	return filepath.Join(p.config.WorkRoot, ".standalone-volume-"+hash(claim.ApplicationID.String(), claim.LogicalName)[:40]+".json")
}

type runtimeVolumeReceipt struct {
	Version int                `json:"version"`
	State   string             `json:"state"`
	Claim   runtimeVolumeClaim `json:"claim"`
}

func runtimeVolumeReceiptBytes(claim runtimeVolumeClaim, state string) []byte {
	raw, _ := json.Marshal(runtimeVolumeReceipt{1, state, claim})
	return raw
}
func (p *Provider) readRuntimeVolumeReceipt(claim runtimeVolumeClaim) (string, error) {
	path := p.runtimeVolumeReceiptPath(claim)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return "", fmt.Errorf("retained volume receipt is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", fmt.Errorf("retained volume receipt changed while reading")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return "", err
	}
	var receipt runtimeVolumeReceipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.Version != 1 || (receipt.State != "pending" && receipt.State != "accepted") || !bytes.Equal(raw, runtimeVolumeReceiptBytes(claim, receipt.State)) {
		return "", fmt.Errorf("retained volume receipt or configuration is invalid")
	}
	return receipt.State, nil
}
func (p *Provider) persistRuntimeVolumeReceipt(claim runtimeVolumeClaim, state string) error {
	if state != "pending" && state != "accepted" {
		return fmt.Errorf("invalid volume receipt transition")
	}
	previous, err := p.readRuntimeVolumeReceipt(claim)
	if err != nil {
		return err
	}
	if previous == state || previous == "accepted" {
		return nil
	}
	if state == "accepted" && previous != "pending" {
		return fmt.Errorf("volume acceptance requires a pending receipt")
	}
	temp, err := os.CreateTemp(p.config.WorkRoot, ".standalone-volume-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(runtimeVolumeReceiptBytes(claim, state)); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if state == "pending" {
		if err := os.Link(temp.Name(), p.runtimeVolumeReceiptPath(claim)); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return err
			}
			_, err = p.readRuntimeVolumeReceipt(claim)
			return err
		}
		if err := os.Remove(temp.Name()); err != nil {
			return err
		}
	} else {
		if err := os.Rename(temp.Name(), p.runtimeVolumeReceiptPath(claim)); err != nil {
			return err
		}
	}
	return syncRuntimeStateDirectory(p.config.WorkRoot)
}
