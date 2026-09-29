package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/acornfox/acornfox/internal/client"
)

// Exit codes per docs/n2-contract.md section 3.
const (
	exitOK          = 0 // success
	exitOpFailed    = 1 // operation completed but failed (e.g. deploy failed)
	exitUsage       = 2 // usage error
	exitConnect     = 3 // connection failure (connect diagnosis)
	exitServerError = 4 // server returned an error
)

// outputWriter carries the shared output state: json mode, streams and the set
// of secret values that must never be printed.
type outputWriter struct {
	json    bool
	stdout  io.Writer
	stderr  io.Writer
	secrets []string
}

// redact removes every registered secret value from s. Only values of length
// >= 4 are treated as secrets to avoid mangling ordinary text.
func (o *outputWriter) redact(s string) string {
	for _, sec := range o.secrets {
		if len(sec) >= 4 {
			s = strings.ReplaceAll(s, sec, "******")
		}
	}
	return s
}

// addSecret registers a value that must be redacted from all output.
func (o *outputWriter) addSecret(v string) {
	if v != "" {
		o.secrets = append(o.secrets, v)
	}
}

// emitJSON writes a success JSON object {"ok":true, ...fields} to stdout.
func (o *outputWriter) emitJSON(fields map[string]any) {
	obj := map[string]any{"ok": true}
	for k, v := range fields {
		obj[k] = v
	}
	o.encodeRedacted(o.stdout, obj)
}

// emitDiagnosisJSON writes a failure JSON object with the diagnosis to stdout.
func (o *outputWriter) emitDiagnosisJSON(d client.Diagnosis) {
	obj := map[string]any{
		"ok": false,
		"diagnosis": map[string]any{
			"stage":       d.Stage,
			"code":        d.Code,
			"message":     o.redact(d.Message),
			"log_excerpt": o.redact(d.LogExcerpt),
			"hint":        o.redact(d.Hint),
		},
	}
	o.encodeRedacted(o.stdout, obj)
}

// encodeRedacted marshals v, redacts secrets from the serialized form and
// writes it as a single line.
func (o *outputWriter) encodeRedacted(w io.Writer, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintln(o.stderr, "internal: 无法序列化输出:", err)
		return
	}
	fmt.Fprintln(w, o.redact(string(data)))
}

// human prints a redacted line to stdout in human mode.
func (o *outputWriter) human(format string, args ...any) {
	fmt.Fprintln(o.stdout, o.redact(fmt.Sprintf(format, args...)))
}

// humanErr prints a redacted line to stderr.
func (o *outputWriter) humanErr(format string, args ...any) {
	fmt.Fprintln(o.stderr, o.redact(fmt.Sprintf(format, args...)))
}

// printDiagnosis renders a diagnosis for humans: message, hint and the log
// excerpt, then the "give this to your AI" note.
func (o *outputWriter) printDiagnosis(d client.Diagnosis) {
	o.humanErr("失败：%s", d.Message)
	if d.Hint != "" {
		o.humanErr("建议：%s", d.Hint)
	}
	if d.LogExcerpt != "" {
		o.humanErr("日志片段：\n%s", d.LogExcerpt)
	}
	o.humanErr("把以上内容交给 AI 修复。")
}

// exitCodeForError maps a client error to the contract exit code and its
// diagnosis. Connect-stage errors → exitConnect; any other server reply →
// exitServerError.
func exitCodeForError(err error) (int, client.Diagnosis) {
	if ce, ok := err.(*client.Error); ok {
		if ce.Diag.Stage == "connect" {
			return exitConnect, ce.Diag
		}
		return exitServerError, ce.Diag
	}
	return exitServerError, client.Diagnosis{
		Stage:   "server",
		Code:    "unknown",
		Message: err.Error(),
	}
}

// fail reports err via the appropriate output shape and returns its exit code.
func (o *outputWriter) fail(err error) int {
	code, diag := exitCodeForError(err)
	if o.json {
		o.emitDiagnosisJSON(diag)
	} else {
		o.printDiagnosis(diag)
	}
	return code
}

// usageError prints a usage message (Chinese) and returns exitUsage. In JSON
// mode it emits a diagnosis with stage=usage.
func (o *outputWriter) usageError(format string, args ...any) int {
	msg := fmt.Sprintf(format, args...)
	if o.json {
		o.emitDiagnosisJSON(client.Diagnosis{Stage: "usage", Code: "usage", Message: msg})
	} else {
		o.humanErr("用法错误：%s", msg)
	}
	return exitUsage
}
