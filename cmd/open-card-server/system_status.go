package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/open-card/open-card/internal/persistence/postgres"
)

type systemStatusStore interface {
	PlatformDomain(context.Context) (postgres.G3PlatformDomainFact, bool, error)
	CountEnabledWebhookEndpoints(context.Context) (int, error)
}

type systemStatusResponse struct {
	Version        string                     `json:"version"`
	Node           systemStatusNode           `json:"node"`
	PlatformDomain systemStatusPlatformDomain `json:"platform_domain"`
	Webhooks       systemStatusWebhooks       `json:"webhooks"`
	Backup         systemStatusCapability     `json:"backup"`
	Alerts         systemStatusCapability     `json:"alerts"`
}

type systemStatusNode struct {
	SingleNode bool    `json:"single_node"`
	InstanceID *string `json:"instance_id"`
	NodeID     *string `json:"node_id"`
	Readiness  string  `json:"readiness"`
}
type systemStatusPlatformDomain struct {
	Status     string  `json:"status"`
	BaseDomain *string `json:"base_domain"`
}
type systemStatusWebhooks struct {
	EnabledCount int    `json:"enabled_count"`
	Status       string `json:"status"`
}
type systemStatusCapability struct {
	Status string `json:"status"`
}

func (s *Server) handleSystemStatus(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", "GET, OPTIONS")
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	value, err := s.systemStatus(request.Context())
	if err != nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "system_status_unavailable", "system status is unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, value)
}

func (s *Server) systemStatus(ctx context.Context) (systemStatusResponse, error) {
	instanceID, nodeID := optionalStatusString(s.systemStatusInstanceID), optionalStatusString(s.systemStatusNodeID)
	node := systemStatusNode{SingleNode: true, InstanceID: instanceID, NodeID: nodeID, Readiness: "unconfigured"}
	if s.systemStatusStore != nil {
		node.Readiness = "ready"
		if !s.ready.Load() {
			node.Readiness = "not_ready"
		}
		if s.repositoryHealth != nil {
			if err := s.repositoryHealth.PingContext(ctx); err != nil {
				node.Readiness = "not_ready"
			}
		}
	}
	response := systemStatusResponse{Version: apiCurrentVersion, Node: node, PlatformDomain: systemStatusPlatformDomain{Status: "unconfigured"}, Webhooks: systemStatusWebhooks{Status: "unconfigured"}, Backup: systemStatusCapability{Status: "not_installed"}, Alerts: systemStatusCapability{Status: "not_installed"}}
	if s.systemStatusStore == nil {
		return response, nil
	}
	fact, found, err := s.systemStatusStore.PlatformDomain(ctx)
	if err != nil {
		return systemStatusResponse{}, err
	}
	if found {
		base := fact.BaseDomain
		response.PlatformDomain.BaseDomain = &base
		switch fact.VerificationStatus {
		case postgres.G3VerificationFailed:
			response.PlatformDomain.Status = "failed"
		case postgres.G3VerificationVerified:
			// DNS verification is only the prerequisite for Gate4B-2. Neither an
			// isolated certificate record nor an internal route proves public
			// Edge TLS/SNI serving, so system status remains pending.
			response.PlatformDomain.Status = "pending"
		default:
			response.PlatformDomain.Status = "pending"
		}
	}
	count, err := s.systemStatusStore.CountEnabledWebhookEndpoints(ctx)
	if err != nil {
		return systemStatusResponse{}, err
	}
	response.Webhooks.EnabledCount = count
	if count > 0 {
		response.Webhooks.Status = "configured"
	}
	return response, nil
}

func optionalStatusString(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}
