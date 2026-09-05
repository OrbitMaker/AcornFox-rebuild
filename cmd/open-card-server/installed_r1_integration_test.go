//go:build integration && linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

// Exercises the real installed server, PostgreSQL and worker. The disposable
// fixture is not evidence of installation, privileged helper identity or TLS.
func TestInstalledR1PublicGitBuild(t *testing.T) {
	if os.Getenv("ACORNFOX_R1_LIVE_TEST") != "enabled" {
		t.Skip("explicit disposable fixture required")
	}
	host, _ := os.Hostname()
	const marker = "/etc/acornfox/r1-fixture-uuid"
	uuid, err := os.ReadFile(marker)
	info, statErr := os.Lstat(marker)
	expectedUUID := os.Getenv("ACORNFOX_R1_VM_UUID")
	if err != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 || info.Sys().(*syscall.Stat_t).Uid != 0 || (host != "acornfox-r1-activate-20260905" && host != "acornfox-beta-test-20260905") || len(expectedUUID) != 36 || strings.TrimSpace(string(uuid)) != expectedUUID {
		t.Fatal("wrong fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	store, err := postgres.OpenStore(ctx, "postgres:///acornfox?host=/var/run/postgresql&sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err := auth.NewService(auth.Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(random)
	requestID, err := domain.NewID("request")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := service.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.ActiveAdminCredential(ctx)
	now := time.Now().UTC()
	if errors.Is(err, postgres.ErrNotFound) {
		id, e := domain.NewID("admin")
		if e != nil {
			t.Fatal(e)
		}
		err = store.CreateAdminCredential(ctx, domain.AdminCredential{ID: id, PasswordHashScheme: auth.PasswordHashScheme, PasswordHash: hash, CredentialVersion: 1, CreatedAt: now, UpdatedAt: now})
	} else if err == nil {
		_, err = store.RotateAdminCredential(ctx, credential.ID, credential.CredentialVersion, auth.PasswordHashScheme, hash, now)
	}
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 11 * time.Minute}
	repeatBuildOnly := os.Getenv("ACORNFOX_R1_BUILD_ONLY_REPEAT") == "enabled"
	var cookies []*http.Cookie
	csrf := ""
	call := func(method, path string, input any, output any) int {
		t.Helper()
		raw, _ := json.Marshal(input)
		req, e := http.NewRequestWithContext(ctx, method, "http://127.0.0.1:18481/api/v1/acornfox"+path, bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Origin", "https://r1.acornfox.invalid")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", requestID.String()+strings.ReplaceAll(path, "/", "-"))
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		if csrf != "" {
			req.Header.Set(acornFoxAuthCSRFHeader, csrf)
		}
		response, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		if path == "/auth/login" {
			cookies = response.Cookies()
			for _, cookie := range cookies {
				if cookie.Name == acornFoxAuthCSRFCookie {
					csrf = cookie.Value
				}
			}
		}
		body, e := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if e != nil {
			t.Fatal(e)
		}
		if response.StatusCode >= 300 {
			var failure struct {
				Code string `json:"code"`
			}
			_ = json.Unmarshal(body, &failure)
			if !repeatBuildOnly || response.StatusCode != http.StatusConflict || !strings.HasSuffix(path, "/deliveries") || failure.Code != "operation_conflict" {
				t.Fatalf("%s %s: status=%d body=%s", method, path, response.StatusCode, body)
			}
		}
		if output != nil {
			if e := json.Unmarshal(body, output); e != nil {
				t.Fatal(e)
			}
		}
		return response.StatusCode
	}
	call("POST", "/auth/login", map[string]string{"password": password}, nil)
	t.Log("actual administrator login passed")
	var app struct {
		Application struct {
			ID string `json:"id"`
		} `json:"application"`
		SourceID string `json:"source_revision_id"`
	}
	name := "R1 actual public Git build"
	if os.Getenv("ACORNFOX_R1_FRESH_APPLICATION") == "enabled" {
		name = "R1 fresh " + requestID.String()
	}
	if err := store.DB().QueryRowContext(ctx, `SELECT a.id,s.id FROM applications a JOIN source_revisions s ON s.application_id=a.id WHERE a.name=$1 ORDER BY a.created_at LIMIT 1`, name).Scan(&app.Application.ID, &app.SourceID); err != nil {
		call("POST", "/apps", map[string]any{"name": name, "source": map[string]string{"type": "public_git", "repository_url": "https://github.com/crccheck/docker-hello-world.git", "ref": "master"}}, &app)
	} else {
		t.Log("reusing the immutable source previously imported through the real API")
	}
	if app.Application.ID == "" || app.SourceID == "" {
		t.Fatal("missing immutable source")
	}
	t.Logf("public Git imported: app=%s source=%s", app.Application.ID, app.SourceID)
	var delivery struct {
		DeploymentID string `json:"deployment_id"`
		Status       string `json:"status"`
	}
	deliveryPath := fmt.Sprintf("/apps/%s/deliveries", app.Application.ID)
	status := call("POST", deliveryPath, map[string]any{"source_revision_id": app.SourceID, "container_port": 8000}, &delivery)
	if status != http.StatusAccepted && (!repeatBuildOnly || status != http.StatusConflict) {
		t.Fatalf("unexpected delivery status %d", status)
	}
	if status == http.StatusAccepted && delivery.DeploymentID == "" {
		t.Fatal("missing deployment after build")
	}
	var durable int
	callerKey := requestID.String() + strings.ReplaceAll(deliveryPath, "/", "-")
	buildKey := acornFoxHTTPKey("create", domain.ID(app.Application.ID), domain.ID(app.SourceID), callerKey) + ":build"
	if err := store.DB().QueryRowContext(ctx, `SELECT count(DISTINCT b.id) FROM builds b JOIN build_plans p ON p.id=b.plan_id JOIN source_revisions s ON s.id=p.source_revision_id JOIN artifacts a ON a.id=b.artifact_id AND a.build_id=b.id JOIN m4_log_indexes l ON l.build_id=b.id AND l.application_id=s.application_id WHERE p.idempotency_key=$1 AND s.id=$2 AND s.application_id=$3 AND b.state='succeeded' AND l.category='build' AND l.byte_size>0 AND l.content_digest<>''`, buildKey, app.SourceID, app.Application.ID).Scan(&durable); err != nil || durable != 1 {
		t.Fatalf("expected one newly successful build with durable artifact and log: count=%d error=%v", durable, err)
	}
	if status == http.StatusConflict {
		t.Log("real repeated build persisted artifact and log; active-operation guard retained (runtime acceptance pending)")
	} else {
		t.Logf("real product build admitted runtime task: deployment=%s status=%s", delivery.DeploymentID, delivery.Status)
	}
}
