package install

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/open-card/open-card/internal/acornfoxsetup"
	"github.com/open-card/open-card/internal/providers/acornfoxroute"
)

// Only the exact old/new runtime edge file and marker of the installed
// transaction authorize legacy QUIT. This never edits a persisted config.
func acornFoxEdgeLegacyStopAuthority() (bool, error) {
	layout, err := newProductionAcornFoxLayout()
	if err != nil {
		return false, ErrAcornFoxUpgradeConflict
	}
	store, err := newAcornFoxRepoStoreForLayout(layout)
	if err != nil {
		return false, ErrAcornFoxUpgradeConflict
	}
	defer store.Close()
	reader := newAcornFoxUpgrade(layout)
	journal, err := reader.load(store)
	if err != nil {
		return false, ErrAcornFoxUpgradeConflict
	}
	return reader.edgeLegacyStopAuthority(store, journal)
}
func (u *acornFoxUpgrade) edgeLegacyStopAuthority(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal) (bool, error) {
	marker, err := u.read(s.hostRoot, acornFoxUpgradeMarkerPath, 0600, 256)
	if err != nil || !bytes.Equal(marker, []byte(j.Old.Repo.BindingSHA256+"\n"+j.Next.Repo.BindingSHA256+"\n")) {
		return false, ErrAcornFoxUpgradeConflict
	}
	path := strings.TrimPrefix(acornfoxsetup.EdgeConfiguration, "/")
	raw, err := u.read(s.hostRoot, path, 0644, 16384)
	if err != nil {
		return false, err
	}
	matched := false
	for _, image := range []acornFoxUpgradeImage{j.Old, j.Next} {
		for _, file := range image.Runtime.Files {
			if strings.TrimPrefix(file.Path, "/") == path && file.Mode == 0644 && bytes.Equal(file.Data, raw) {
				matched = true
			}
		}
	}
	if !matched {
		return false, ErrAcornFoxUpgradeConflict
	}
	dropin := "etc/systemd/system/acornfox-edge.service.d/10-upgrade-marker.conf"
	guard, err := u.read(s.hostRoot, dropin, 0644, 16384)
	if err != nil {
		return false, err
	}
	guardMatched := false
	for _, image := range []acornFoxUpgradeImage{j.Old, j.Next} {
		entry := substrateEntryAt(image.Substrate.Entries, dropin)
		if entry != nil && entry.SHA256 == sha256Hex(guard) {
			guardMatched = true
		}
	}
	if !guardMatched || !bytes.Contains(guard, []byte("ConditionPathExists=!/var/lib/acornfox/upgrade-in-progress")) {
		return false, ErrAcornFoxUpgradeConflict
	}
	var config struct {
		Apps struct {
			HTTP struct {
				Grace json.RawMessage `json:"grace_period"`
			} `json:"http"`
		} `json:"apps"`
	}
	if json.Unmarshal(raw, &config) != nil {
		return false, ErrAcornFoxUpgradeConflict
	}
	if len(config.Apps.HTTP.Grace) == 0 {
		return true, nil
	}
	var grace string
	if json.Unmarshal(config.Apps.HTTP.Grace, &grace) != nil || grace != acornfoxroute.EdgeGracePeriod {
		return false, ErrAcornFoxUpgradeConflict
	}
	return false, nil
}
