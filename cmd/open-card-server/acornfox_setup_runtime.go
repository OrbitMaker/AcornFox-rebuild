package main

import "github.com/open-card/open-card/internal/corehttp"

func acornFoxSetupCredential(directory string) []byte {
	return corehttp.AcornFoxSetupCredential(directory)
}
