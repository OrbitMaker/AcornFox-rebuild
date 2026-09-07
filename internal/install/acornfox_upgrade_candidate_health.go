package install

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const acornFoxCandidatePrivilegeDropPath = "/usr/bin/setpriv"

type acornFoxCandidateHealthValidator struct {
	listen             func(string, string) (net.Listener, error)
	start              func(context.Context, string, []string, []string, *os.File) (candidateServerProcess, error)
	probe              func(context.Context, string) error
	probeTimeout       time.Duration
	terminationTimeout time.Duration
}

func validateProductionAcornFoxCandidateHealth(ctx context.Context, store *TaskAcornFoxRepoStore, image acornFoxUpgradeImage) error {
	if ctx == nil || ctx.Err() != nil || store == nil || !store.ownsLock() || store.layout.validate() != nil || len(image.DatabaseEnv) == 0 {
		return ErrAcornFoxUpgradeUnknown
	}
	if os.Geteuid() != 0 {
		return ErrAcornFoxUpgradeUnknown
	}
	if _, err := safeProductionExecutable(acornFoxCandidatePrivilegeDropPath); err != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	serverPath := "opt/acornfox/releases/" + image.Activation.ReleaseID + "/bin/acornfox-server"
	var expected SubstrateEntry
	found := false
	for _, entry := range image.Substrate.Entries {
		if entry.Path != serverPath {
			continue
		}
		if found || entry.Kind != SubstrateEntryFile || entry.Mode != 0o755 || entry.Role != OwnerRoleRoot || entry.Group != GroupRoleRoot || !validSHA(entry.SHA256) {
			return ErrAcornFoxUpgradeConflict
		}
		expected, found = entry, true
	}
	if !found || !acornFoxProductionEntryMatches(store.hostRoot, store, serverPath, expected) {
		return ErrAcornFoxUpgradeConflict
	}
	principal, ok := store.layout.owner(AcornFoxLiveServerRole)
	if !ok || principal.uid <= 0 || principal.gid <= 0 {
		return ErrAcornFoxUpgradeConflict
	}
	databaseURL, err := parseAcornFoxControlPlaneEnvironment(image.DatabaseEnv)
	if err != nil || databaseURL == "" {
		return ErrAcornFoxUpgradeConflict
	}
	validator := acornFoxCandidateHealthValidator{}
	return validator.validate(ctx, "/"+serverPath, databaseURL, principal)
}

func (v acornFoxCandidateHealthValidator) validate(ctx context.Context, serverPath, databaseURL string, principal acornFoxInstallPrincipal) error {
	if ctx == nil || ctx.Err() != nil || !safeAbsPath(serverPath) || databaseURL == "" || principal.uid <= 0 || principal.gid <= 0 {
		return ErrAcornFoxUpgradeUnknown
	}
	listen := v.listen
	if listen == nil {
		listen = net.Listen
	}
	listener, err := listen("tcp", "127.0.0.1:0")
	if err != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	listenerClosed := false
	defer func() {
		if !listenerClosed {
			_ = listener.Close()
		}
	}()
	tcp, ok := listener.(*net.TCPListener)
	if !ok || tcp == nil {
		return ErrAcornFoxUpgradeUnknown
	}
	address, ok := candidateLoopbackAddress(tcp.Addr())
	if !ok {
		return ErrAcornFoxUpgradeUnknown
	}
	listenerFile, err := tcp.File()
	if err != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	fileClosed := false
	defer func() {
		if !fileClosed {
			_ = listenerFile.Close()
		}
	}()
	start := v.start
	if start == nil {
		start = startProductionCandidateServer
	}
	args := []string{"--reuid=" + strconv.Itoa(principal.uid), "--regid=" + strconv.Itoa(principal.gid), "--clear-groups", "--", serverPath, "--candidate-validate"}
	process, err := start(ctx, acornFoxCandidatePrivilegeDropPath, args, acornFoxCandidateEnvironment(databaseURL, address), listenerFile)
	if err != nil || process == nil {
		return ErrAcornFoxUpgradeUnknown
	}
	wait := make(chan error, 1)
	go func() { wait <- process.Wait() }()
	if listenerFile.Close() != nil {
		_ = terminateCandidateProcess(process, wait, v.terminationTimeout)
		return ErrAcornFoxUpgradeUnknown
	}
	fileClosed = true
	if listener.Close() != nil {
		_ = terminateCandidateProcess(process, wait, v.terminationTimeout)
		return ErrAcornFoxUpgradeUnknown
	}
	listenerClosed = true
	probe := v.probe
	if probe == nil {
		probe = probeProductionCandidate
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		if err := waitForCandidateProbe(ctx, probe, wait, "http://"+address+path, v.probeTimeout); err != nil {
			if !errors.Is(err, errCandidateServerExited) {
				_ = terminateCandidateProcess(process, wait, v.terminationTimeout)
			}
			return ErrAcornFoxUpgradeUnknown
		}
	}
	if terminateCandidateProcess(process, wait, v.terminationTimeout) != nil {
		return ErrAcornFoxUpgradeUnknown
	}
	return nil
}

func acornFoxCandidateEnvironment(databaseURL, address string) []string {
	return append(append([]string(nil), productionSubprocessBaseEnv...),
		"ACORNFOX_RUNTIME_MODE=clean",
		"ACORNFOX_DATABASE_URL="+databaseURL,
		"ACORNFOX_SERVER_ADDR="+address,
		"ACORNFOX_CANDIDATE_LISTEN_FD=3",
		"ACORNFOX_M1_ENABLED=false",
		"ACORNFOX_M2_ENABLED=false",
		"ACORNFOX_M3_ENABLED=false",
		"ACORNFOX_M4_ENABLED=false",
		"ACORNFOX_M4_ROLLOUT_ENABLED=false",
		"ACORNFOX_M5_ENABLED=false",
		"ACORNFOX_M6_ENABLED=false",
	)
}

func acornFoxCandidateEnvironmentValue(environment []string, name string) (string, bool) {
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if ok && key == name {
			return value, true
		}
	}
	return "", false
}
