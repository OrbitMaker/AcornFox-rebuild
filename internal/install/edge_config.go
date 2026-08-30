package install

import (
	"bytes"
	"fmt"
)

// edgeConfigHealthBlock is deliberately a byte-for-byte deployment contract.
// Rendering a candidate template without this local-only listener would make
// the later fixed health probe meaningless.
var edgeConfigHealthBlock = []byte("http://127.0.0.1:18482 {\n\t@edge_health path /healthz\n\trespond @edge_health 200\n\trespond 404\n}")

var edgeConfigDocumentationHost = []byte("console.example.invalid")

// renderEdgeConfigTemplate performs the only allowed Caddyfile substitution:
// the unique documentation hostname is replaced as an opaque byte sequence.
// It intentionally has no Caddyfile parser or regular-expression fallback.
func renderEdgeConfigTemplate(template []byte, hostname string) ([]byte, error) {
	if !normalizedConsoleHostname(hostname) || hostname == string(edgeConfigDocumentationHost) || bytes.Count(template, edgeConfigDocumentationHost) != 1 {
		return nil, ErrUpgradeJournalConflict
	}
	before, after, ok := bytes.Cut(template, edgeConfigDocumentationHost)
	if !ok {
		return nil, ErrUpgradeJournalConflict
	}
	rendered := make([]byte, 0, len(before)+len(hostname)+len(after))
	rendered = append(rendered, before...)
	rendered = append(rendered, hostname...)
	rendered = append(rendered, after...)
	return rendered, nil
}

// edgeConfigHostnameFromRenderedTemplate proves that installed content is an
// exact rendering of the immutable source template, then returns its host.
func edgeConfigHostnameFromRenderedTemplate(template, installed []byte) (string, error) {
	if bytes.Count(template, edgeConfigDocumentationHost) != 1 {
		return "", ErrUpgradeJournalConflict
	}
	before, after, _ := bytes.Cut(template, edgeConfigDocumentationHost)
	if !bytes.HasPrefix(installed, before) || !bytes.HasSuffix(installed, after) || len(installed) < len(before)+len(after) {
		return "", ErrUpgradeJournalConflict
	}
	host := string(installed[len(before) : len(installed)-len(after)])
	rendered, err := renderEdgeConfigTemplate(template, host)
	if err != nil || !bytes.Equal(rendered, installed) {
		return "", ErrUpgradeJournalConflict
	}
	return host, nil
}

func edgeConfigTransitionPlan(tx string, source, candidate ReleaseV1, sourceTemplate, installed, candidateTemplate, caddy []byte) (*EdgeConfigTransitionPlan, error) {
	if !validID(tx) || !validRC0Release(source) || !candidate.valid() || len(caddy) == 0 || !bytes.Contains(candidateTemplate, edgeConfigHealthBlock) {
		return nil, ErrUpgradeJournalConflict
	}
	host, err := edgeConfigHostnameFromRenderedTemplate(sourceTemplate, installed)
	if err != nil {
		return nil, err
	}
	target, err := renderEdgeConfigTemplate(candidateTemplate, host)
	if err != nil || !bytes.Contains(target, edgeConfigHealthBlock) {
		return nil, ErrUpgradeJournalConflict
	}
	plan := &EdgeConfigTransitionPlan{Evidence: EdgeConfigTransitionV1{
		SchemaVersion: 1, TransactionID: tx, SourceReleaseID: source.ID,
		CandidateReleaseID: candidate.ID, ConsoleHostname: host,
		SourceTemplateSHA256: bytesSHA256(sourceTemplate), CandidateTemplateSHA256: bytesSHA256(candidateTemplate),
		InstalledBeforeSHA256: bytesSHA256(installed), InstalledAfterSHA256: bytesSHA256(target),
		CandidateCaddySHA256: bytesSHA256(caddy),
	}, Target: target}
	if err := plan.Validate(); err != nil {
		return nil, fmt.Errorf("%w: invalid rendered edge configuration", ErrUpgradeJournalConflict)
	}
	return plan, nil
}
