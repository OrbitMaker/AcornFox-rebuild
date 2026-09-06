package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// acornFoxInstallLayout is the one private seam between the task-root model
// and the later fixed host model.  It is deliberately a value: no caller can
// provide it through an exported constructor. L2 routes task-model writes
// through a separately pinned host descriptor while production stays gated.
type acornFoxInstallLayout struct {
	mode            acornFoxInstallLayoutMode
	stateRootPath   string
	hostRootPath    string
	livePrefix      string
	liveReceiptPath string
	stateOwner      acornFoxInstallPrincipal
	principals      map[AcornFoxLiveRole]acornFoxInstallPrincipal
	evidenceSHA256  string
	stateRootInfo   os.FileInfo
	hostRootInfo    os.FileInfo
}

type acornFoxInstallLayoutMode string

const (
	acornFoxInstallLayoutTask       acornFoxInstallLayoutMode = "task"
	acornFoxInstallLayoutProduction acornFoxInstallLayoutMode = "production"
)

type acornFoxInstallPrincipal struct {
	uid int
	gid int
}

// Service binaries follow current -> active/release. Production activation
// directories permit traversal, while root-only 0600 metadata stays private.
// Other users cannot list the activation directory or read its metadata.
func (l acornFoxInstallLayout) activationDirectoryMode() os.FileMode {
	if l.mode == acornFoxInstallLayoutProduction {
		return 0o711
	}
	return durableDirMode
}

var acornFoxInstallLayoutRoles = []AcornFoxLiveRole{
	AcornFoxLiveRootRole,
	AcornFoxLiveServerRole,
	AcornFoxLiveAgentRole,
	AcornFoxLiveBuildKitRole,
	AcornFoxLiveCaddyRole,
	AcornFoxLiveEdgeRole,
}

// newTaskAcornFoxLayout records the existing task-root topology exactly.  All
// symbolic roles map to the task owner; task receipts continue to expose only
// that symbolic fact and never this uid/gid data.
func newTaskAcornFoxLayout(root string, uid, gid int) (acornFoxInstallLayout, error) {
	if uid < 0 || gid < 0 || !safeAbsoluteDurableRoot(root) || filepath.Clean(root) == string(filepath.Separator) {
		return acornFoxInstallLayout{}, errors.New("AcornFox task layout root is unsafe")
	}
	info, err := os.Lstat(root)
	if err != nil || !safeAcornFoxInstallRoot(info, uid, gid, false) {
		return acornFoxInstallLayout{}, errors.New("AcornFox task layout root is unsafe")
	}
	owner := acornFoxInstallPrincipal{uid: uid, gid: gid}
	principals := make(map[AcornFoxLiveRole]acornFoxInstallPrincipal, len(acornFoxInstallLayoutRoles))
	for _, role := range acornFoxInstallLayoutRoles {
		principals[role] = owner
	}
	layout := acornFoxInstallLayout{
		mode: acornFoxInstallLayoutTask, stateRootPath: root, hostRootPath: root,
		livePrefix: acornFoxLiveDir, liveReceiptPath: acornFoxLiveReceipt,
		stateOwner: owner, principals: principals, stateRootInfo: info, hostRootInfo: info,
	}
	return layout, layout.validate()
}

// newTestProductionAcornFoxLayout is package-private test construction for
// the later fixed production bridge. It deliberately accepts only already
// created temporary roots and modeled principals; it never permits real / or
// a public configurable production path.
func newTestProductionAcornFoxLayout(stateRoot, hostRoot string, stateUID, stateGID int, principals map[AcornFoxLiveRole]acornFoxInstallPrincipal) (acornFoxInstallLayout, error) {
	if stateUID < 0 || stateGID < 0 || !safeAcornFoxTestRoot(stateRoot) || !safeAcornFoxTestRoot(hostRoot) || stateRoot != filepath.Join(hostRoot, "var", "lib", "acornfox", "install") {
		return acornFoxInstallLayout{}, errors.New("AcornFox production test layout roots are unsafe")
	}
	stateInfo, stateErr := os.Lstat(stateRoot)
	hostInfo, hostErr := os.Lstat(hostRoot)
	if stateErr != nil || hostErr != nil || !safeAcornFoxInstallRoot(stateInfo, stateUID, stateGID, true) || !safeAcornFoxHostRoot(hostInfo) {
		return acornFoxInstallLayout{}, errors.New("AcornFox production test layout roots are unsafe")
	}
	copyPrincipals := make(map[AcornFoxLiveRole]acornFoxInstallPrincipal, len(principals))
	for role, principal := range principals {
		copyPrincipals[role] = principal
	}
	layout := acornFoxInstallLayout{
		mode: acornFoxInstallLayoutProduction, stateRootPath: stateRoot, hostRootPath: hostRoot,
		livePrefix: "", liveReceiptPath: "var/lib/acornfox/install/live-receipt.json",
		stateOwner: acornFoxInstallPrincipal{uid: stateUID, gid: stateGID}, principals: copyPrincipals,
		stateRootInfo: stateInfo, hostRootInfo: hostInfo,
	}
	if err := layout.validate(); err != nil {
		return acornFoxInstallLayout{}, err
	}
	layout.evidenceSHA256 = layout.digest()
	return layout, nil
}

// newProductionAcornFoxLayout has deliberately no configurable inputs. It is
// the only production layout constructor and therefore cannot be redirected to
// a caller-selected host root, account, or state directory.
func newProductionAcornFoxLayout() (acornFoxInstallLayout, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return acornFoxInstallLayout{}, errors.New("AcornFox production layout requires Linux root")
	}
	stateRoot, hostRoot := "/var/lib/acornfox/install", "/"
	stateInfo, stateErr := os.Lstat(stateRoot)
	hostInfo, hostErr := os.Lstat(hostRoot)
	if stateErr != nil || hostErr != nil || !safeAcornFoxInstallRoot(stateInfo, 0, 0, true) || !safeAcornFoxProductionHostRoot(hostInfo) {
		return acornFoxInstallLayout{}, errors.New("AcornFox production layout roots are unsafe")
	}
	principals := map[AcornFoxLiveRole]acornFoxInstallPrincipal{AcornFoxLiveRootRole: {}}
	for role, name := range map[AcornFoxLiveRole]string{
		AcornFoxLiveServerRole: "acornfox", AcornFoxLiveAgentRole: "acornfox-agent", AcornFoxLiveBuildKitRole: "acornfox-buildkit", AcornFoxLiveCaddyRole: "acornfox-caddy", AcornFoxLiveEdgeRole: "acornfox-edge",
	} {
		account, err := user.Lookup(name)
		if err != nil {
			return acornFoxInstallLayout{}, errors.New("AcornFox production account is unavailable")
		}
		uid, uidErr := strconv.Atoi(account.Uid)
		gid, gidErr := strconv.Atoi(account.Gid)
		if uidErr != nil || gidErr != nil || uid <= 0 || gid <= 0 {
			return acornFoxInstallLayout{}, errors.New("AcornFox production account is invalid")
		}
		principals[role] = acornFoxInstallPrincipal{uid: uid, gid: gid}
	}
	layout := acornFoxInstallLayout{mode: acornFoxInstallLayoutProduction, stateRootPath: stateRoot, hostRootPath: hostRoot, liveReceiptPath: "var/lib/acornfox/install/live-receipt.json", stateOwner: acornFoxInstallPrincipal{}, principals: principals, stateRootInfo: stateInfo, hostRootInfo: hostInfo}
	if err := layout.validate(); err != nil {
		return acornFoxInstallLayout{}, err
	}
	layout.evidenceSHA256 = layout.digest()
	return layout, nil
}

func safeAcornFoxTestRoot(path string) bool {
	if !safeAbsoluteDurableRoot(path) || filepath.Clean(path) == string(filepath.Separator) {
		return false
	}
	relative, err := filepath.Rel(filepath.Clean(os.TempDir()), path)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func safeAcornFoxInstallRoot(info os.FileInfo, uid, gid int, exactMode bool) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || verifyOwner(info, uid, gid) != nil {
		return false
	}
	if exactMode {
		return info.Mode().Perm() == durableDirMode
	}
	return info.Mode().Perm()&0o022 == 0
}

func safeAcornFoxHostRoot(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0
}

func safeAcornFoxProductionHostRoot(info os.FileInfo) bool {
	return safeAcornFoxHostRoot(info) && verifyOwner(info, 0, 0) == nil
}

func (l acornFoxInstallLayout) validate() error {
	if l.mode != acornFoxInstallLayoutTask && l.mode != acornFoxInstallLayoutProduction || !safeAbsoluteDurableRoot(l.stateRootPath) || (!safeAbsoluteDurableRoot(l.hostRootPath) && filepath.Clean(l.hostRootPath) != string(filepath.Separator)) || filepath.Clean(l.stateRootPath) == string(filepath.Separator) || l.stateOwner.uid < 0 || l.stateOwner.gid < 0 || l.stateRootInfo == nil || l.hostRootInfo == nil || len(l.principals) != len(acornFoxInstallLayoutRoles) {
		return errors.New("AcornFox install layout is invalid")
	}
	if l.mode == acornFoxInstallLayoutTask {
		if l.stateRootPath != l.hostRootPath || l.livePrefix != acornFoxLiveDir || l.liveReceiptPath != acornFoxLiveReceipt || l.evidenceSHA256 != "" || !os.SameFile(l.stateRootInfo, l.hostRootInfo) || !safeAcornFoxInstallRoot(l.stateRootInfo, l.stateOwner.uid, l.stateOwner.gid, false) {
			return errors.New("AcornFox task install layout is invalid")
		}
		for _, role := range acornFoxInstallLayoutRoles {
			if l.principals[role] != l.stateOwner {
				return errors.New("AcornFox task install layout principal is invalid")
			}
		}
		return nil
	}
	productionRoot := l.hostRootPath == "/" && l.stateRootPath == "/var/lib/acornfox/install" && l.stateOwner == (acornFoxInstallPrincipal{})
	testRoot := l.stateRootPath != l.hostRootPath && safeAcornFoxTestRoot(l.stateRootPath) && safeAcornFoxTestRoot(l.hostRootPath) && l.stateRootPath == filepath.Join(l.hostRootPath, "var", "lib", "acornfox", "install")
	if (!productionRoot && !testRoot) || l.livePrefix != "" || l.liveReceiptPath != "var/lib/acornfox/install/live-receipt.json" || !safeAcornFoxInstallRoot(l.stateRootInfo, l.stateOwner.uid, l.stateOwner.gid, true) || !safeAcornFoxHostRoot(l.hostRootInfo) || l.principals[AcornFoxLiveRootRole] != (acornFoxInstallPrincipal{}) || (l.evidenceSHA256 != "" && (!validSHA(l.evidenceSHA256) || l.evidenceSHA256 != l.digest())) {
		return errors.New("AcornFox production install layout is invalid")
	}
	seen := map[acornFoxInstallPrincipal]bool{}
	for _, role := range acornFoxInstallLayoutRoles[1:] {
		principal, ok := l.principals[role]
		if !ok || principal.uid <= 0 || principal.gid <= 0 || seen[principal] {
			return errors.New("AcornFox production install layout principal is invalid")
		}
		seen[principal] = true
	}
	return nil
}

func (l acornFoxInstallLayout) digest() string {
	if l.mode != acornFoxInstallLayoutProduction {
		return ""
	}
	type rolePrincipal struct {
		Role string `json:"role"`
		UID  int    `json:"uid"`
		GID  int    `json:"gid"`
	}
	values := make([]rolePrincipal, 0, len(acornFoxInstallLayoutRoles))
	for _, role := range acornFoxInstallLayoutRoles {
		principal := l.principals[role]
		values = append(values, rolePrincipal{Role: string(role), UID: principal.uid, GID: principal.gid})
	}
	raw, err := json.Marshal(struct {
		Mode            acornFoxInstallLayoutMode `json:"mode"`
		StateRootPath   string                    `json:"state_root_path"`
		HostRootPath    string                    `json:"host_root_path"`
		LivePrefix      string                    `json:"live_prefix"`
		LiveReceiptPath string                    `json:"live_receipt_path"`
		StateUID        int                       `json:"state_uid"`
		StateGID        int                       `json:"state_gid"`
		Principals      []rolePrincipal           `json:"principals"`
	}{l.mode, l.stateRootPath, l.hostRootPath, l.livePrefix, l.liveReceiptPath, l.stateOwner.uid, l.stateOwner.gid, values})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (l acornFoxInstallLayout) livePath(path string) string {
	if cleanRelative(path) != nil {
		return ""
	}
	if l.livePrefix == "" {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(filepath.Join(l.livePrefix, path))
}

func (l acornFoxInstallLayout) activationPath(id string) string {
	return l.activationDir(id)
}

func (l acornFoxInstallLayout) activationDir(id string) string {
	if !validID(id) {
		return ""
	}
	return l.livePath("opt/acornfox/activations/" + id)
}

func (l acornFoxInstallLayout) activationReleasePath(id string) string {
	if directory := l.activationDir(id); directory != "" {
		return directory + "/release"
	}
	return ""
}

func (l acornFoxInstallLayout) activationReceiptPath(id string) string {
	if directory := l.activationDir(id); directory != "" {
		return directory + "/repo-activation.json"
	}
	return ""
}

func (l acornFoxInstallLayout) activePath() string  { return l.livePath("opt/acornfox/active") }
func (l acornFoxInstallLayout) currentPath() string { return l.livePath("opt/acornfox/current") }

func (l acornFoxInstallLayout) owner(role AcornFoxLiveRole) (acornFoxInstallPrincipal, bool) {
	principal, ok := l.principals[role]
	return principal, ok
}

func (l acornFoxInstallLayout) equivalent(other acornFoxInstallLayout) bool {
	if l.validate() != nil || other.validate() != nil || l.mode != other.mode || l.stateRootPath != other.stateRootPath || l.hostRootPath != other.hostRootPath || l.livePrefix != other.livePrefix || l.liveReceiptPath != other.liveReceiptPath || l.stateOwner != other.stateOwner || l.evidenceSHA256 != other.evidenceSHA256 || !os.SameFile(l.stateRootInfo, other.stateRootInfo) || !os.SameFile(l.hostRootInfo, other.hostRootInfo) {
		return false
	}
	for _, role := range acornFoxInstallLayoutRoles {
		if l.principals[role] != other.principals[role] {
			return false
		}
	}
	return true
}

func (l acornFoxInstallLayout) hostRootPinned() bool {
	if l.validate() != nil {
		return false
	}
	info, err := os.Lstat(l.hostRootPath)
	return err == nil && os.SameFile(info, l.hostRootInfo) && safeAcornFoxHostRoot(info)
}

func (l acornFoxInstallLayout) receiptPath() string {
	return strings.TrimPrefix(l.liveReceiptPath, "./")
}

func (l acornFoxInstallLayout) evidence() string {
	if l.mode == acornFoxInstallLayoutProduction {
		return l.evidenceSHA256
	}
	return ""
}

// acornFoxProductionManagedRoots is deliberately an enumeration, not a root
// walker. L2 may validate fixed descendants of these four paths later, but it
// must never recurse across a host root (and therefore never across /).
func acornFoxProductionManagedRoots() []string {
	return []string{"opt/acornfox", "etc/acornfox", "var/lib/acornfox", "var/log/acornfox"}
}
