package main

import (
	"fmt"
	"os"
	"time"
)

// config holds all runtime settings, sourced from environment variables.
type config struct {
	port           string
	listenAddr     string
	googleSheetsID string
	sheetName      string
	homeRedirect   string
	projectID      string
	cacheTTL       time.Duration
}

// loadConfig reads configuration from the environment, applying defaults.
// It returns an error if a required value is missing (GOOGLE_SHEET_ID) or a
// value is malformed (CACHE_TTL).
func loadConfig() (config, error) {
	cfg := config{
		port:           getenv("PORT", "8080"),
		listenAddr:     os.Getenv("LISTEN_ADDR"),
		googleSheetsID: os.Getenv("GOOGLE_SHEET_ID"),
		sheetName:      os.Getenv("SHEET_NAME"),
		homeRedirect:   os.Getenv("HOME_REDIRECT"),
		projectID:      os.Getenv("GOOGLE_CLOUD_PROJECT"),
		cacheTTL:       5 * time.Second,
	}

	if cfg.googleSheetsID == "" {
		return config{}, fmt.Errorf("GOOGLE_SHEET_ID is required")
	}

	if v := os.Getenv("CACHE_TTL"); v != "" {
		ttl, err := time.ParseDuration(v)
		if err != nil {
			return config{}, fmt.Errorf("invalid CACHE_TTL %q: %w", v, err)
		}
		cfg.cacheTTL = ttl
	}

	return cfg, nil
}

// getenv returns the value of key, or fallback when key is unset or empty.
func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
