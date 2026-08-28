package controllers

import (
	"context"
	"errors"
	"testing"

	"github.com/open-card/open-card/internal/domain"
)

type tlsAllowMemoryStore struct {
	states map[string]domain.TLSAllowState
	err    error
}

func (s tlsAllowMemoryStore) TLSAllowState(_ context.Context, host string) (domain.TLSAllowState, error) {
	if s.err != nil {
		return domain.TLSAllowState{}, s.err
	}
	return s.states[host], nil
}

func TestTLSAllowControllerFailsClosedBeforeCertificateOrServingState(t *testing.T) {
	controller := &TLSAllowController{Store: tlsAllowMemoryStore{states: map[string]domain.TLSAllowState{
		"app.example.test": {Domain: "app.example.test", DNSVerified: true, RouteDesired: true, RuntimeReady: true},
	}}}
	allowed, err := controller.Allow(context.Background(), "APP.example.test.")
	if err != nil || !allowed {
		t.Fatalf("first issuance state allow=%v err=%v", allowed, err)
	}
	allowed, err = controller.Allow(context.Background(), "invalid")
	if err != nil || allowed {
		t.Fatalf("invalid domain allow=%v err=%v", allowed, err)
	}
}

func TestTLSAllowControllerFailsClosedOnLookupFailure(t *testing.T) {
	controller := &TLSAllowController{Store: tlsAllowMemoryStore{err: errors.New("database unavailable")}}
	allowed, err := controller.Allow(context.Background(), "app.example.test")
	if err == nil || allowed {
		t.Fatalf("lookup failure allow=%v err=%v", allowed, err)
	}
}
