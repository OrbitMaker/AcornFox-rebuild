package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/acornfoxenv"
	"github.com/open-card/open-card/internal/observability"
)

const (
	m4DefaultLogFileBytes  int64 = 10 << 20
	m4DefaultLogTotalBytes int64 = 5 << 30
)

func m4LogStoreConfig(root string, getenv func(acornfoxenv.Key) string, environment acornfoxenv.Environment) (observability.LogStoreConfig, error) {
	config := observability.LogStoreConfig{
		RootDir:          root,
		MaxFileBytes:     m4DefaultLogFileBytes,
		MaxTotalBytes:    m4DefaultLogTotalBytes,
		MaxBuildFiles:    20,
		MaxRuntimeFiles:  5,
		RuntimeRetention: 7 * 24 * time.Hour,
	}
	var err error
	if fileBytes := strings.TrimSpace(getenv(acornfoxenv.LogMaxFileBytes)); fileBytes != "" {
		config.MaxFileBytes, err = strconv.ParseInt(fileBytes, 10, 64)
		if err != nil || config.MaxFileBytes < 64 || config.MaxFileBytes > 1<<30 {
			return observability.LogStoreConfig{}, fmt.Errorf("%s must be between 64 bytes and 1 GiB", environment.Name(acornfoxenv.LogMaxFileBytes))
		}
	}
	if totalBytes := strings.TrimSpace(getenv(acornfoxenv.LogMaxTotalBytes)); totalBytes != "" {
		config.MaxTotalBytes, err = strconv.ParseInt(totalBytes, 10, 64)
		if err != nil || config.MaxTotalBytes < config.MaxFileBytes || config.MaxTotalBytes > 64<<30 {
			return observability.LogStoreConfig{}, fmt.Errorf("%s must be at least the file limit and at most 64 GiB", environment.Name(acornfoxenv.LogMaxTotalBytes))
		}
	}
	return config, nil
}

func m4LogCollectionInterval(value string, environment acornfoxenv.Environment) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return 30 * time.Second, nil
	}
	interval, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || interval < time.Second || interval > 5*time.Minute {
		return 0, fmt.Errorf("%s must be between 1s and 5m", environment.Name(acornfoxenv.M4LogCollectionInterval))
	}
	return interval, nil
}
