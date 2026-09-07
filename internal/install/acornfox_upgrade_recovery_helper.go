package install

import "context"

// Application rollback and recovery executable selection are separate. A
// cross-schema journal must retain its authenticated successor reader at the
// fixed boot entrypoint; the previous release and its snapshots remain intact.
func acornFoxCrossSchemaRecoveryHelperEntry(j acornFoxUpgradeJournal, layout acornFoxInstallLayout) (SubstrateEntry, error) {
	if j.CrossSchema == nil || j.validate(layout) != nil {
		return SubstrateEntry{}, ErrAcornFoxUpgradeConflict
	}
	entry := substrateEntryAt(j.Next.Substrate.Entries, AcornFoxUpgradeHelperPath)
	if entry == nil || entry.Kind != SubstrateEntryFile || entry.Mode != 0755 || entry.Role != OwnerRoleRoot || entry.Group != GroupRoleRoot || entry.SHA256 != j.Next.Substrate.UpgradeHelperSHA256 {
		return SubstrateEntry{}, ErrAcornFoxUpgradeConflict
	}
	return *entry, nil
}

func (u *acornFoxUpgrade) crossSchemaRecoveryHelper(s *TaskAcornFoxRepoStore, j acornFoxUpgradeJournal) (SubstrateEntry, []byte, error) {
	entry, err := acornFoxCrossSchemaRecoveryHelperEntry(j, u.layout)
	if err != nil {
		return SubstrateEntry{}, nil, err
	}
	sub, err := u.locateSubstrate(s, j, j.Next)
	if err != nil {
		return SubstrateEntry{}, nil, err
	}
	defer sub.Close()
	raw, err := acornFoxLiveReadSource(sub.root, sub, entry)
	if err != nil {
		return SubstrateEntry{}, nil, err
	}
	return entry, raw, nil
}

type acornFoxUpgradeRecoveryHelperHealth interface {
	HealthyWithRecoveryHelper(context.Context, acornFoxUpgradeImage, acornFoxUpgradeImage) error
}

func (u *acornFoxUpgrade) healthy(ctx context.Context, j acornFoxUpgradeJournal, next bool) error {
	image := j.Old
	if next {
		image = j.Next
	}
	if j.CrossSchema == nil {
		return u.services.Healthy(ctx, image)
	}
	if j.validate(u.layout) != nil {
		return ErrAcornFoxUpgradeConflict
	}
	services, ok := u.services.(acornFoxUpgradeRecoveryHelperHealth)
	if !ok {
		return ErrAcornFoxUpgradeConflict
	}
	return services.HealthyWithRecoveryHelper(ctx, image, j.Next)
}
