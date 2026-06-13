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

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
