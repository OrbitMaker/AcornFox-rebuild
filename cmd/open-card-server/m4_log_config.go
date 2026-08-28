package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/observability"
)

const (
	m4DefaultLogFileBytes  int64 = 10 << 20
	m4DefaultLogTotalBytes int64 = 5 << 30
)

func m4LogStoreConfig(root, fileBytes, totalBytes string) (observability.LogStoreConfig, error) {
	config := observability.LogStoreConfig{
		RootDir:          root,
		MaxFileBytes:     m4DefaultLogFileBytes,
		MaxTotalBytes:    m4DefaultLogTotalBytes,
		MaxBuildFiles:    20,
		MaxRuntimeFiles:  5,
		RuntimeRetention: 7 * 24 * time.Hour,
	}
	var err error
	if strings.TrimSpace(fileBytes) != "" {
		config.MaxFileBytes, err = strconv.ParseInt(strings.TrimSpace(fileBytes), 10, 64)
		if err != nil || config.MaxFileBytes < 64 || config.MaxFileBytes > 1<<30 {
			return observability.LogStoreConfig{}, fmt.Errorf("OPEN_CARD_LOG_MAX_FILE_BYTES must be between 64 bytes and 1 GiB")
		}
	}
	if strings.TrimSpace(totalBytes) != "" {
		config.MaxTotalBytes, err = strconv.ParseInt(strings.TrimSpace(totalBytes), 10, 64)
		if err != nil || config.MaxTotalBytes < config.MaxFileBytes || config.MaxTotalBytes > 64<<30 {
			return observability.LogStoreConfig{}, fmt.Errorf("OPEN_CARD_LOG_MAX_TOTAL_BYTES must be at least the file limit and at most 64 GiB")
		}
	}
	return config, nil
}

func m4LogCollectionInterval(value string) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return 30 * time.Second, nil
	}
	interval, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || interval < time.Second || interval > 5*time.Minute {
		return 0, fmt.Errorf("OPEN_CARD_M4_LOG_COLLECTION_INTERVAL must be between 1s and 5m")
	}
	return interval, nil
}
