package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The server's POST /v1/apps/{app}/domains reply wraps the domain; this test
// pins that wire shape (a mismatch shipped once between parallel implementations).
func TestAddDomainWireShape(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/apps/notes/domains" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"domain":{"app":"notes","name":"notes.example.com","status":"pending"},"warnings":[{"stage":"domain","code":"dns_mismatch","message":"m"}]}`)
	}))
	defer ts.Close()
	c := newDirectClient(t, ts)
	d, err := c.AddDomain(context.Background(), "notes", "notes.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "notes.example.com" || d.Status != "pending" || len(d.Warnings) != 1 || d.Warnings[0].Code != "dns_mismatch" {
		t.Fatalf("got %+v", d)
	}
}
