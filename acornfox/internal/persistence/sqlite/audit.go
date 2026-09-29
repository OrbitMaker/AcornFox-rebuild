package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	contracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/foundation"
)

const auditV1 = "acornfox-audit-v1"

var _ contracts.AuditRepository = (*Store)(nil)

// Field order and tags are part of acornfox-audit-v1. PreviousHash is a JSON
// null for the first record; ordered refs always encode as an array, never null.
type auditCanonical struct {
	HashScheme   string   `json:"hash_scheme"`
	ID           string   `json:"id"`
	Sequence     int64    `json:"sequence"`
	ActorType    string   `json:"actor_type"`
	ActorID      string   `json:"actor_id"`
	Action       string   `json:"action"`
	Reason       string   `json:"reason"`
	InputDigest  string   `json:"input_digest"`
	Result       string   `json:"result"`
	EvidenceRefs []string `json:"evidence_refs"`
	PreviousHash *string  `json:"previous_hash"`
	CreatedAt    string   `json:"created_at"`
}

func auditCanonicalBytes(e contracts.AuditEvidence) ([]byte, error) {
	var refs []string
	if err := json.Unmarshal(e.EvidenceRefs, &refs); err != nil || refs == nil {
		return nil, errors.New("audit v1 references must be a string array")
	}
	return json.Marshal(auditCanonical{e.HashScheme, e.ID, e.Sequence, e.ActorType, e.ActorID, e.Action, e.Reason, e.InputDigest, e.Result, refs, e.PreviousHash, e.CreatedAt})
}
func auditRecordHash(e contracts.AuditEvidence) (string, error) {
	bytes, err := auditCanonicalBytes(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(auditV1+"\x00"), bytes...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
func validAuditID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	first := id[0]
	if !(first >= 'a' && first <= 'z' || first >= 'A' && first <= 'Z' || first >= '0' && first <= '9') {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}
func validateAuditContext(a contracts.AuditContext) error {
	if (a.ActorType != "system" && a.ActorType != "admin") || !validAuditID(a.ActorID) || strings.TrimSpace(a.Reason) == "" || len(a.Reason) > 4096 {
		return errors.New("trusted audit actor and bounded reason are required")
	}
	return nil
}
func validAuditDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	for _, r := range s[7:] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

type auditInput struct {
	ID           string
	Actor        contracts.AuditContext
	Action       string
	InputDigest  string
	Result       string
	EvidenceRefs []string
	CreatedAt    time.Time
}

// appendAuditTx has no caller-supplied scheme, sequence, previous or record hash.
// The owning business command controls replay and commits this same transaction.
func appendAuditTx(ctx context.Context, tx *sql.Tx, in auditInput) (contracts.AuditEvidence, error) {
	if err := validateAuditContext(in.Actor); err != nil {
		return contracts.AuditEvidence{}, err
	}
	if !validAuditID(in.ID) || !validAuditID(in.Action) || !validAuditID(in.Result) || !validAuditDigest(in.InputDigest) || in.CreatedAt.IsZero() || in.CreatedAt.Year() < 1 || in.CreatedAt.Year() > 9999 {
		return contracts.AuditEvidence{}, errors.New("invalid audit identity, action, digest, result or timestamp")
	}
	refs := append([]string{}, in.EvidenceRefs...)
	if len(refs) > 16 {
		return contracts.AuditEvidence{}, errors.New("audit evidence references exceed bound")
	}
	for _, ref := range refs {
		if !validAuditID(ref) || !(strings.HasPrefix(ref, "app_") || strings.HasPrefix(ref, "op_") || strings.HasPrefix(ref, "task_") || strings.HasPrefix(ref, "evt-") || strings.HasPrefix(ref, "evt_") || strings.HasPrefix(ref, "audit_")) {
			return contracts.AuditEvidence{}, errors.New("audit references must be safe evidence IDs")
		}
	}
	reason := strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(foundation.RedactText(in.Actor.Reason), "�")))
	if reason == "" {
		return contracts.AuditEvidence{}, errors.New("audit reason is empty after sanitization")
	}
	if len(reason) > 1024 {
		reason = reason[:1024]
		for !utf8.ValidString(reason) {
			reason = reason[:len(reason)-1]
		}
	}
	refsJSON, err := json.Marshal(refs)
	if err != nil {
		return contracts.AuditEvidence{}, err
	}
	e := contracts.AuditEvidence{ID: in.ID, ActorType: in.Actor.ActorType, ActorID: in.Actor.ActorID, Action: in.Action, Reason: reason, InputDigest: in.InputDigest, Result: in.Result, EvidenceRefs: json.RawMessage(refsJSON), HashScheme: auditV1, CreatedAt: FormatTime(in.CreatedAt)}
	var previous sql.NullString
	var head int64
	err = tx.QueryRowContext(ctx, `SELECT sequence,record_hash FROM audit_evidence ORDER BY sequence DESC LIMIT 1`).Scan(&head, &previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return e, err
	}
	if head == math.MaxInt64 {
		return e, errors.New("audit sequence exhausted")
	}
	e.Sequence = head + 1
	if previous.Valid {
		value := previous.String
		e.PreviousHash = &value
	}
	e.RecordHash, err = auditRecordHash(e)
	if err != nil {
		return e, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_evidence(id,sequence,actor_type,actor_id,action,reason,input_digest,result,evidence_refs,previous_hash,record_hash,hash_scheme,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, e.ID, e.Sequence, e.ActorType, e.ActorID, e.Action, e.Reason, e.InputDigest, e.Result, string(e.EvidenceRefs), e.PreviousHash, e.RecordHash, e.HashScheme, e.CreatedAt)
	return e, err
}

// ListAuditEvidence is bounded and read-only. New-scheme content is checked;
// legacy values remain verbatim and their producer hashes are not re-evaluated.
func (s *Store) ListAuditEvidence(ctx context.Context, f contracts.AuditFilter) ([]contracts.AuditEvidence, error) {
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	if f.AfterSequence < 0 {
		return nil, errors.New("audit cursor must not be negative")
	}
	if f.Limit <= 0 {
		f.Limit = defaultQueryLimit
	}
	if f.Limit > maxQueryLimit {
		return nil, errors.New("audit limit exceeds maximum")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,sequence,actor_type,actor_id,action,reason,input_digest,result,evidence_refs,previous_hash,record_hash,hash_scheme,created_at FROM audit_evidence WHERE sequence>? ORDER BY sequence LIMIT ?`, f.AfterSequence, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []contracts.AuditEvidence{}
	for rows.Next() {
		var e contracts.AuditEvidence
		var refs string
		var previous sql.NullString
		if err := rows.Scan(&e.ID, &e.Sequence, &e.ActorType, &e.ActorID, &e.Action, &e.Reason, &e.InputDigest, &e.Result, &refs, &previous, &e.RecordHash, &e.HashScheme, &e.CreatedAt); err != nil {
			return nil, err
		}
		if !json.Valid([]byte(refs)) {
			return nil, ErrCorruptData
		}
		e.EvidenceRefs = json.RawMessage(refs)
		if previous.Valid {
			v := previous.String
			e.PreviousHash = &v
		}
		if _, err := time.Parse(time.RFC3339Nano, e.CreatedAt); err != nil {
			return nil, fmt.Errorf("%w: invalid preserved audit timestamp", ErrCorruptData)
		}
		if e.HashScheme == auditV1 {
			if h, err := auditRecordHash(e); err != nil || h != e.RecordHash {
				return nil, fmt.Errorf("%w: audit v1 content hash mismatch", ErrCorruptData)
			}
		}
		result = append(result, e)
	}
	return result, rows.Err()
}
