package acornfoxrelease

import (
	"errors"
	"strings"
)

var ErrGoPlan = errors.New("acornfox go build plan is invalid")

type GoBuildTargetV1 struct {
	Name    string
	Package string
	Output  string
	Ldflags []string
}
type GoBuildPlanV1 struct {
	valid   bool
	targets []GoBuildTargetV1
}

var fixedTargets = []struct{ name, path, identity string }{
	{"acornfox-server", "./cmd/open-card-server", "acornfox"}, {"acornfox-agent", "./cmd/open-card-agent", "acornfox"}, {"acornfox-static-server", "./cmd/open-card-static-server", ""}, {"acornfox-secretctl", "./cmd/open-card-secretctl", ""}, {"acornfox-security-probe", "./cmd/open-card-security-probe", ""}, {"acornfox-imagegc", "./cmd/open-card-imagegc", ""}, {"acornfox", "./cmd/acornfox", ""}, {"acornfox-admin", "./cmd/open-card-admin", ""}, {"acornfox-upgrade", "./cmd/open-card-upgrade", "acornfox"}, {"acornfox-healthcheck", "./cmd/open-card-healthcheck", "acornfox"},
}

// PrepareGoBuildPlanV1 is an observation-only sealed plan: it never builds.
func PrepareGoBuildPlanV1(w Witness, p SourcePolicyV1) (GoBuildPlanV1, error) {
	if !w.Valid() || p.Validate() != nil || p.ModulePath != modulePathForRepository(w.decision.SourceRepository) {
		return GoBuildPlanV1{}, ErrGoPlan
	}
	pkgs := map[string]bool{}
	for _, v := range p.GoPackages {
		pkgs[v] = true
	}
	out := make([]GoBuildTargetV1, 0, len(fixedTargets))
	for _, t := range fixedTargets {
		if !pkgs[p.ModulePath+"/"+strings.TrimPrefix(t.path, "./")] {
			return GoBuildPlanV1{}, ErrGoPlan
		}
		flags := []string{"-buildid="}
		if t.identity != "" {
			flags = append(flags, "-X=main.processIdentity=acornfox")
		}
		if t.name == "acornfox-upgrade" || t.name == "acornfox-healthcheck" {
			flags = append(flags, "-X=main.buildVersion="+w.decision.Version, "-X=main.buildSourceCommit="+w.decision.SourceCommit, "-X=main.buildLayoutSchema=1")
		}
		out = append(out, GoBuildTargetV1{Name: t.name, Package: t.path, Output: "bin/" + t.name, Ldflags: []string{strings.Join(flags, " ")}})
	}
	return GoBuildPlanV1{valid: true, targets: out}, nil
}
func (p GoBuildPlanV1) Valid() bool { return p.valid && len(p.targets) == len(fixedTargets) }
func (p GoBuildPlanV1) Targets() []GoBuildTargetV1 {
	if !p.Valid() {
		return nil
	}
	out := make([]GoBuildTargetV1, len(p.targets))
	for i, v := range p.targets {
		out[i] = v
		out[i].Ldflags = append([]string(nil), v.Ldflags...)
	}
	return out
}
func GoBaseFlags() []string { return []string{"-trimpath", "-buildvcs=false"} }
