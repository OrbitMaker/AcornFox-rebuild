package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/acornfoxenv"
	"github.com/open-card/open-card/internal/application"
)

type candidateUnavailableRepository struct{ *application.MemoryRepository }

func (candidateUnavailableRepository) PingContext(context.Context) error {
	return errors.New("postgresql://candidate:never-log-this@db.example/open_card")
}

func candidateValidationEnvironment(values map[string]string) func(acornfoxenv.Key) string {
	return func(key acornfoxenv.Key) string { return values[acornfoxenv.Environment{}.Name(key)] }
}

func TestCandidateValidationConfigIsExactAndSuppressesRuntimeWorkers(t *testing.T) {
	base := map[string]string{
		"OPEN_CARD_SERVER_ADDR":  "127.0.0.1:18481",
		"OPEN_CARD_DATABASE_URL": "postgresql://candidate:secret@127.0.0.1/open_card_candidate",
	}
	config, err := parseCandidateValidationConfig([]string{candidateValidationArgument}, candidateValidationEnvironment(base))
	if err != nil || config.address != "127.0.0.1:18481" || config.databaseURL == "" {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	for name, value := range map[string]string{
		"OPEN_CARD_SERVER_ADDR":                    "0.0.0.0:18481",
		"OPEN_CARD_AGENT_GATEWAY_ADDR":             "127.0.0.1:9443",
		"OPEN_CARD_AUTH_ORIGIN":                    "https://console.example.test",
		"OPEN_CARD_M1_ENABLED":                     "true",
		"OPEN_CARD_M6_ENABLED":                     "TRUE",
		"OPEN_CARD_CANDIDATE_LISTEN_FD":            "4",
		"OPEN_CARD_CANDIDATE_LISTEN_FD whitespace": " 3",
	} {
		t.Run(name, func(t *testing.T) {
			values := map[string]string{}
			for key, current := range base {
				values[key] = current
			}
			key := name
			if name == "OPEN_CARD_CANDIDATE_LISTEN_FD whitespace" {
				key = "OPEN_CARD_CANDIDATE_LISTEN_FD"
			}
			values[key] = value
			if _, err := parseCandidateValidationConfig([]string{candidateValidationArgument}, candidateValidationEnvironment(values)); err == nil {
				t.Fatalf("candidate validation accepted %s=%q", name, value)
			}
		})
	}
	for _, args := range [][]string{nil, {"--candidate-validate", "extra"}, {"--unknown"}} {
		if _, err := parseCandidateValidationConfig(args, candidateValidationEnvironment(base)); err == nil {
			t.Fatalf("candidate validation accepted args %#v", args)
		}
	}
}

func TestCandidateValidationInheritedListenerRequiresExactAddressAndCleansFDFile(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	file, err := os.CreateTemp(t.TempDir(), "candidate-listener-fd")
	if err != nil {
		t.Fatal(err)
	}
	config := candidateValidationConfig{address: listener.Addr().String(), inheritedListenerFD: true}
	accepted, err := candidateValidationListener(config, candidateListenerDependencies{
		openInheritedFile: func(uintptr, string) *os.File { return file },
		listenerFromFile:  func(*os.File) (net.Listener, error) { return listener, nil },
	})
	if err != nil || accepted != listener {
		t.Fatalf("listener=%v err=%v", accepted, err)
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("inherited descriptor file was not closed after listener handoff")
	}

	mismatch, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer mismatch.Close()
	otherFile, err := os.CreateTemp(t.TempDir(), "candidate-listener-mismatch")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := candidateValidationListener(config, candidateListenerDependencies{
		openInheritedFile: func(uintptr, string) *os.File { return otherFile },
		listenerFromFile:  func(*os.File) (net.Listener, error) { return mismatch, nil },
	}); err == nil {
		t.Fatal("candidate validation accepted an inherited listener with a different address")
	}
	if _, err := otherFile.Stat(); err == nil {
		t.Fatal("mismatched inherited descriptor file was not closed")
	}
}

func TestCandidateValidationInheritedListenerRejectsNonSocket(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "candidate-listener-not-socket")
	if err != nil {
		t.Fatal(err)
	}
	_, err = candidateValidationListener(candidateValidationConfig{address: "127.0.0.1:18481", inheritedListenerFD: true}, candidateListenerDependencies{
		openInheritedFile: func(uintptr, string) *os.File { return file },
		listenerFromFile:  net.FileListener,
	})
	if err == nil {
		t.Fatal("candidate validation accepted a non-socket inherited FD")
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("non-socket inherited descriptor file was not closed")
	}
}

func TestCandidateValidationListenerUsesModeSpecificDescriptorLabel(t *testing.T) {
	for _, test := range []struct {
		name  string
		label string
	}{
		{name: "legacy", label: "open-card-candidate-listener"},
		{name: "clean", label: "acornfox-candidate-listener"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var got string
			file, err := os.CreateTemp(t.TempDir(), "candidate-listener-label")
			if err != nil {
				t.Fatal(err)
			}
			_, err = candidateValidationListener(candidateValidationConfig{address: "127.0.0.1:18481", inheritedListenerFD: true, listenerLabel: test.label}, candidateListenerDependencies{
				openInheritedFile: func(_ uintptr, label string) *os.File { got = label; return file },
				listenerFromFile:  net.FileListener,
			})
			if got != test.label {
				t.Fatalf("descriptor label=%q want=%q", got, test.label)
			}
		})
	}
}

func TestCandidateValidationHandlerOnlyExposesHealthAndReadiness(t *testing.T) {
	server := NewServer()
	handler := candidateValidationHandler(server)
	for _, test := range []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodGet, "/readyz", http.StatusOK},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/applications", http.StatusNotFound},
		{http.MethodGet, "/api/v1/events", http.StatusNotFound},
	} {
		request := httptest.NewRequest(test.method, test.path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Fatalf("%s %s: got %d want %d body=%s", test.method, test.path, response.Code, test.want, response.Body.String())
		}
	}
}

func TestCandidateValidationErrorsDoNotExposeDatabaseURL(t *testing.T) {
	_, err := parseCandidateValidationConfig(
		[]string{candidateValidationArgument},
		candidateValidationEnvironment(map[string]string{
			"OPEN_CARD_SERVER_ADDR":  "127.0.0.1:18481",
			"OPEN_CARD_DATABASE_URL": "postgresql://candidate:never-log-this@127.0.0.1/open_card_candidate",
			"OPEN_CARD_M1_ENABLED":   "true",
		}),
	)
	if err == nil || strings.Contains(err.Error(), "never-log-this") || strings.Contains(err.Error(), "postgres") {
		t.Fatalf("candidate validation error leaked a database URL: %v", err)
	}
}

func TestCandidateValidationReadinessRedactsRepositoryFailure(t *testing.T) {
	server := NewServerWithRepository(candidateUnavailableRepository{MemoryRepository: application.NewMemoryRepository()})
	response := httptest.NewRecorder()
	candidateValidationHandler(server).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "never-log-this") || strings.Contains(response.Body.String(), "postgres") {
		t.Fatalf("candidate readiness leaked repository error: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestCandidateValidationServesLoopbackHealthAndStopsWithContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveCandidateValidationOnListener(ctx, listener, NewServer()) }()
	url := "http://" + listener.Addr().String() + "/readyz"
	var response *http.Response
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		response, err = http.Get(url)
		if err == nil {
			break
		}
	}
	if err != nil || response == nil {
		t.Fatalf("candidate readiness request failed: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("candidate readiness status=%s", response.Status)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("candidate validation server did not stop after cancellation")
	}
}

func TestNormalServerArgumentContractRemainsNoArgumentsOnly(t *testing.T) {
	if _, err := parseCandidateValidationConfig(nil, candidateValidationEnvironment(nil)); err == nil {
		t.Fatal("candidate parser accepted normal server invocation")
	}
}
