//go:build linux

package desktopupdateguest

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
)

// A new quarantine owner binds the precise torn writer object to the committed
// baseline and its fixed snapshot header. Existing legacy quarantines without
// this evidence never acquire inferred deletion authority.
func (x *Executor) quarantineTorn(raw, current []byte, old snapshot) error {
	source, e := x.fileIdentity("state-next.json", 0600)
	if e != nil {
		return e
	}
	if source.SHA256 != digest(raw) || source.Size != int64(len(raw)) {
		return ErrConflict
	}
	baselineSHA := ""
	if len(current) > 0 {
		baselineSHA = digest(current)
	}
	header := encoded(struct {
		Revision    uint64 `json:"revision"`
		PreviousSHA string `json:"previous_sha256"`
		Schema      int    `json:"schema_version"`
		PolicySHA   string `json:"policy_sha256"`
		InstanceSHA string `json:"instance_sha256"`
	}{old.Revision + 1, baselineSHA, 1, digest(encoded(x.policy)), digest(encoded(x.instance))})
	header = append(header[:len(header)-1], ',')
	if len(raw) < len(header) || !bytes.HasPrefix(raw, header) {
		return ErrConflict
	}
	if e := x.syncSafeFile(filepath.Join(x.paths.state, "state-next.json")); e != nil {
		return e
	}
	owner := quarantineOwner{1, digest(encoded(x.policy)), digest(encoded(x.instance)), old, baselineSHA, source}
	p := filepath.Join(x.paths.state, "quarantine-owner.json")
	if e := x.ensureExactFile(p, encoded(owner), "quarantine-owner"); e != nil {
		return e
	}
	if _, e := os.Lstat(filepath.Join(x.paths.state, "state-quarantine")); !errors.Is(e, os.ErrNotExist) {
		return ErrConflict
	}
	if e := x.sameGCFile(source, false); e != nil {
		return e
	}
	if e := os.Rename(filepath.Join(x.paths.state, "state-next.json"), filepath.Join(x.paths.state, "state-quarantine")); e != nil {
		return e
	}
	if x.fault != nil {
		x.fault("quarantine-renamed")
	}
	return syncDir(x.paths.state)
}
func (x *Executor) prepareQuarantineGC(s snapshot) (*gcIntent, error) {
	q, e := x.fileIdentity("state-quarantine", 0600)
	if errors.Is(e, os.ErrNotExist) {
		if _, e := os.Lstat(filepath.Join(x.paths.state, "quarantine-owner.json")); e == nil {
			return nil, ErrConflict
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	raw, e := readSafe(x.paths.anchor, filepath.Join(x.paths.state, "quarantine-owner.json"), 0600, 512<<10)
	if e != nil {
		return nil, ErrConflict
	}
	var owner quarantineOwner
	if decode(raw, &owner) != nil || owner.Schema != 1 || owner.PolicySHA != s.PolicySHA || owner.InstanceSHA != s.InstanceSHA || owner.Source.Path != "state-next.json" || s.Revision < owner.Baseline.Revision {
		return nil, ErrConflict
	}
	previous := owner.Baseline
	if previous.Revision > 0 {
		if x.validateSnapshot(previous) != nil || owner.BaselineSHA != digest(encoded(previous)) {
			return nil, ErrConflict
		}
	} else if owner.BaselineSHA != "" {
		return nil, ErrConflict
	}
	expected := owner.Source
	expected.Path = "state-quarantine"
	if q != expected {
		return nil, ErrConflict
	}
	// A prior in-flight job must have converged to a retained terminal receipt or
	// an exact terminal tombstone. Healthy-looking unrelated state is insufficient.
	for _, before := range previous.Jobs {
		if terminal(before.State) {
			continue
		}
		if i := jobIndex(s, before.Intent.AttemptID); i >= 0 {
			after := s.Jobs[i]
			if !terminal(after.State) || after.Intent != before.Intent || after.EnvelopeSHA != before.EnvelopeSHA {
				return nil, ErrBusy
			}
		} else {
			retired, e := x.readRetired(before.Intent.AttemptID)
			if e != nil || retired.IntentSHA != digest(encoded(before.Intent)) || retired.EnvelopeSHA != before.EnvelopeSHA {
				return nil, ErrBusy
			}
		}
	}
	metadata, e := x.fileIdentity("quarantine-owner.json", 0600)
	if e != nil {
		return nil, e
	}
	if metadata.SHA256 != digest(raw) || metadata.Size != int64(len(raw)) {
		return nil, ErrConflict
	}
	return &gcIntent{Kind: "quarantine", Files: []gcFile{q, metadata}}, nil
}
