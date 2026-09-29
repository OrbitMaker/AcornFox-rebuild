package main

import (
	"net/http"

	"github.com/open-card/open-card/internal/auth"
	"github.com/open-card/open-card/internal/corehttp"
)

const (
	acornFoxSetupPath        = corehttp.AcornFoxSetupPath
	acornFoxSetupMaxJSONBody = corehttp.AcornFoxSetupMaxJSONBody
)

type AcornFoxWebSetupHTTPHandler = corehttp.AcornFoxWebSetupHTTPHandler

func NewAcornFoxWebSetupHTTPHandler(store auth.WebSetupStore, authService *auth.Service, setupTokenCredential []byte) (*AcornFoxWebSetupHTTPHandler, error) {
	return corehttp.NewAcornFoxWebSetupHTTPHandler(store, authService, setupTokenCredential)
}

func acornFoxSetupError(writer http.ResponseWriter, status int, message string) {
	corehttp.WriteJSONError(writer, status, "setup_failed", message)
}
