package healthcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/providers/edgeprobe"
)

const certificateSubjectVersion = "certificate_health_v1"
const maxCertificateTargets = 1024

var certificateFingerprintPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// CertificateTarget is public certificate projection only. ExpectedLeafSHA256
// is optional solely for the one console target; every other covered hostname
// must provide it. No secret reference belongs to this task boundary.
type CertificateTarget struct {
	Hostname           string
	ExpectedLeafSHA256 string
	PersistedNotAfter  *time.Time
	Console            bool
}

// CertificateTargetSource returns the complete currently-serving certificate
// coverage. Database, CLI, and systemd implementations intentionally remain
// outside this task-only health package.
type CertificateTargetSource interface {
	CertificateTargets(context.Context) ([]CertificateTarget, error)
}

// NewTaskCertificateProbe creates the task-testable Gate7 certificate probe.
// It keeps target selection and TLS observation injected, so constructing it
// cannot cause a database query or access an Edge configuration/private key.
func NewTaskCertificateProbe(source CertificateTargetSource, observer edgeprobe.CertificateObserver, clock func() time.Time) (HostProbe, error) {
	if source == nil || observer == nil || clock == nil {
		return HostProbe{}, errors.New("certificate probe dependencies are required")
	}
	return HostProbe{Kind: CheckCertificate, Check: func(ctx context.Context) (HostFact, error) {
		return checkCertificates(ctx, source, observer, clock)
	}}, nil
}

func checkCertificates(ctx context.Context, source CertificateTargetSource, observer edgeprobe.CertificateObserver, clock func() time.Time) (HostFact, error) {
	if ctx == nil {
		return certificateEmergencyFact("cancelled", nil), errors.New("certificate probe context is required")
	}
	if err := ctx.Err(); err != nil {
		return certificateEmergencyFact("cancelled", nil), err
	}
	targets, err := source.CertificateTargets(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return certificateEmergencyFact("cancelled", nil), ctx.Err()
		}
		return certificateEmergencyFact("source_failure", nil), nil
	}
	if err := ctx.Err(); err != nil {
		return certificateEmergencyFact("cancelled", nil), err
	}
	normalized, ok := normalizeCertificateTargets(targets)
	if !ok {
		return certificateEmergencyFact("invalid_coverage", nil), nil
	}

	now := clock().UTC()
	if now.IsZero() {
		return certificateEmergencyFact("clock_failure", nil), nil
	}
	severity := SeverityOK
	causes := make([]string, 0)
	records := make([]string, 0, len(normalized))
	for _, target := range normalized {
		if err := ctx.Err(); err != nil {
			return certificateEmergencyFact("cancelled", nil), err
		}
		observation, observeErr := observer.ObserveCertificate(ctx, target.Hostname)
		if observeErr != nil {
			if ctx.Err() != nil {
				return certificateEmergencyFact("cancelled", nil), ctx.Err()
			}
			severity = SeverityEmergency
			causes = append(causes, "tls_failure")
			records = append(records, certificateRecord(target, edgeprobe.CertificateObservation{}, "tls_failure"))
			continue
		}
		cause := "healthy"
		if observedHostname, hostnameErr := domain.NormalizeTLSAllowDomain(observation.Hostname); hostnameErr != nil || observedHostname != target.Hostname || observation.NotBefore.IsZero() || observation.NotAfter.IsZero() || !observation.NotAfter.After(observation.NotBefore) || !certificateFingerprintPattern.MatchString(observation.Fingerprint) {
			cause = "invalid_observation"
		} else if now.Before(observation.NotBefore.UTC()) || !now.Before(observation.NotAfter.UTC()) {
			cause = "certificate_validity"
		} else if target.ExpectedLeafSHA256 != "" && target.ExpectedLeafSHA256 != observation.Fingerprint {
			cause = "fingerprint_drift"
		} else if target.PersistedNotAfter != nil && !observation.NotAfter.UTC().Equal(target.PersistedNotAfter.UTC()) {
			cause = "persisted_validity_drift"
		}
		if cause != "healthy" {
			severity = SeverityEmergency
			causes = append(causes, cause)
		} else {
			severity = maxSeverity(severity, CertificateSeverity(observation.NotAfter.UTC().Sub(now)))
		}
		records = append(records, certificateRecord(target, observation, cause))
	}
	cause := "healthy"
	if len(causes) > 0 {
		sort.Strings(causes)
		cause = strings.Join(uniqueStrings(causes), "+")
	}
	return HostFact{Subject: certificateSubject(cause, records), Severity: severity}, nil
}

func normalizeCertificateTargets(targets []CertificateTarget) ([]CertificateTarget, bool) {
	if len(targets) == 0 || len(targets) > maxCertificateTargets {
		return nil, false
	}
	normalized := make([]CertificateTarget, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	consoleCount := 0
	for _, target := range targets {
		hostname, err := domain.NormalizeTLSAllowDomain(target.Hostname)
		if err != nil {
			return nil, false
		}
		if _, exists := seen[hostname]; exists {
			return nil, false
		}
		if target.ExpectedLeafSHA256 != "" && !certificateFingerprintPattern.MatchString(target.ExpectedLeafSHA256) {
			return nil, false
		}
		if !target.Console && target.ExpectedLeafSHA256 == "" {
			return nil, false
		}
		if target.Console {
			consoleCount++
			if consoleCount > 1 {
				return nil, false
			}
		}
		if target.PersistedNotAfter != nil && target.PersistedNotAfter.IsZero() {
			return nil, false
		}
		seen[hostname] = struct{}{}
		target.Hostname = hostname
		target.PersistedNotAfter = utcCopy(target.PersistedNotAfter)
		normalized = append(normalized, target)
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].Hostname < normalized[j].Hostname })
	return normalized, consoleCount == 1
}

func utcCopy(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC()
	return &copy
}

func certificateRecord(target CertificateTarget, observation edgeprobe.CertificateObservation, cause string) string {
	persisted := ""
	if target.PersistedNotAfter != nil {
		persisted = target.PersistedNotAfter.UTC().Format(time.RFC3339Nano)
	}
	return strings.Join([]string{target.Hostname, target.ExpectedLeafSHA256, persisted, observation.Fingerprint, observation.NotBefore.UTC().Format(time.RFC3339Nano), observation.NotAfter.UTC().Format(time.RFC3339Nano), cause}, "\x00")
}

func certificateEmergencyFact(cause string, records []string) HostFact {
	return HostFact{Subject: certificateSubject(cause, records), Severity: SeverityEmergency}
}

func certificateSubject(cause string, records []string) string {
	sorted := append([]string(nil), records...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(certificateSubjectVersion + "\n" + cause + "\n" + strings.Join(sorted, "\n")))
	return certificateSubjectVersion + ":" + cause + ":" + hex.EncodeToString(sum[:])
}

func uniqueStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
