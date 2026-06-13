package main

import (
	"embed"
	"net/http"
)

//go:embed static/*
var static embed.FS

func faviconHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=7776000")
	data, err := static.ReadFile("static/favicon.ico")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_, _ = w.Write(data)
}

func robotsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "public, max-age=7776000")
	_, _ = w.Write([]byte("User-agent: *\nDisallow: /"))
}

// healthHandler is a liveness probe: it returns 200 as long as the process is
// running, regardless of cache state.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// readyHandler is a readiness probe: it returns 503 until the cache has been
// populated by a successful refresh, then 200. This lets the platform hold
// traffic until the service can actually resolve shortcuts.
func readyHandler(c *cachedURLMap) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !c.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}
