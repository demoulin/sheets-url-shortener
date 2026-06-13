package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// JSON logs with Cloud Logging field names (severity/message/timestamp).
	slog.SetDefault(newCloudLogger())

	cfg, err := loadConfig()
	if err != nil {
		slog.Error("invalid configuration", "err", err)
		os.Exit(1)
	}

	cache := &cachedURLMap{
		ttl: cfg.cacheTTL,
		sheet: &sheetsProvider{
			googleSheetsID: cfg.googleSheetsID,
			sheetName:      cfg.sheetName,
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Start async — server is ready to accept requests immediately.
	cache.start(ctx)

	srv := &server{db: cache, homeRedirect: cfg.homeRedirect}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /favicon.ico", faviconHandler)
	mux.HandleFunc("GET /robots.txt", robotsHandler)
	mux.HandleFunc("GET /healthz", healthHandler)
	mux.HandleFunc("GET /readyz", readyHandler(cache))
	// GET-only (HEAD is matched implicitly); other methods get a 405.
	mux.HandleFunc("GET /", srv.handler)

	listenAddr := net.JoinHostPort(cfg.listenAddr, cfg.port)
	httpSrv := &http.Server{
		Addr:              listenAddr,
		Handler:           requestLogger(cfg.projectID)(recovery(securityHeaders(mux))),
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64 KiB
	}

	slog.Info("starting server", "addr", listenAddr, "cache_ttl", cfg.cacheTTL)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			slog.Error("graceful shutdown failed", "err", err)
		}
	}()

	if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
}
