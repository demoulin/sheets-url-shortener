package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed static/*
var static embed.FS

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := os.Getenv("LISTEN_ADDR")

	googleSheetsID := os.Getenv("GOOGLE_SHEET_ID")
	sheetName := os.Getenv("SHEET_NAME")
	homeRedirect := os.Getenv("HOME_REDIRECT")

	ttl := 5 * time.Second
	if ttlVal := os.Getenv("CACHE_TTL"); ttlVal != "" {
		v, err := time.ParseDuration(ttlVal)
		if err != nil {
			slog.Error("invalid CACHE_TTL", "value", ttlVal, "err", err)
			os.Exit(1)
		}
		ttl = v
	}

	cache := &cachedURLMap{
		ttl: ttl,
		sheet: &sheetsProvider{
			googleSheetsID: googleSheetsID,
			sheetName:      sheetName,
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	cache.start(ctx)

	srv := &server{db: cache, homeRedirect: homeRedirect}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /favicon.ico", faviconHandler)
	mux.HandleFunc("GET /robots.txt", robotsHandler)
	mux.HandleFunc("GET /healthz", healthHandler)
	mux.HandleFunc("/", srv.handler)

	listenAddr := net.JoinHostPort(addr, port)
	httpSrv := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	slog.Info("starting server", "addr", listenAddr, "cache_ttl", ttl)

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

type server struct {
	db           *cachedURLMap
	homeRedirect string
}

type URLMap map[string]*url.URL

type cachedURLMap struct {
	mu    sync.RWMutex
	v     URLMap
	ttl   time.Duration
	sheet *sheetsProvider
}

// start does an initial synchronous load then refreshes on the TTL interval in
// the background. Stale data is served if a refresh fails.
func (c *cachedURLMap) start(ctx context.Context) {
	c.doRefresh(ctx)
	go func() {
		ticker := time.NewTicker(c.ttl)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.doRefresh(ctx)
			}
		}
	}()
}

func (c *cachedURLMap) doRefresh(ctx context.Context) {
	rows, err := c.sheet.Query(ctx)
	if err != nil {
		slog.Error("failed to refresh URL cache", "err", err)
		return // keep serving stale data
	}
	m := urlMap(rows)
	c.mu.Lock()
	c.v = m
	c.mu.Unlock()
}

func (c *cachedURLMap) Get(key string) *url.URL {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.v[key]
}

func (s *server) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		s.home(w, r)
		return
	}
	s.redirect(w, r)
}

func (s *server) home(w http.ResponseWriter, r *http.Request) {
	if s.homeRedirect != "" {
		http.Redirect(w, r, s.homeRedirect, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, `<!DOCTYPE html>
<html><head><title>Not found</title></head><body>
<h1>Not found :(</h1>
<p>This URL redirector requires a shortcut in the path.</p>
</body></html>`)
}

func (s *server) redirect(w http.ResponseWriter, r *http.Request) {
	redirTo := s.findRedirect(r.URL)
	if redirTo == nil {
		http.NotFound(w, r)
		return
	}
	slog.Info("redirecting", "from", r.URL.String(), "to", redirTo.String())
	http.Redirect(w, r, redirTo.String(), http.StatusFound)
}

// findRedirect does longest-prefix path matching. For /a/b/c it tries
// "a/b/c" → "a/b" → "a", stopping at the first match. Any unmatched tail
// segments are appended to the destination URL. Lookup is case-insensitive.
func (s *server) findRedirect(req *url.URL) *url.URL {
	path := strings.TrimPrefix(req.Path, "/")
	segments := strings.Split(path, "/")
	var tail []string
	for len(segments) > 0 {
		key := strings.ToLower(strings.Join(segments, "/"))
		if v := s.db.Get(key); v != nil {
			return prepRedirect(v, strings.Join(tail, "/"), req.Query())
		}
		tail = append([]string{segments[len(segments)-1]}, tail...)
		segments = segments[:len(segments)-1]
	}
	return nil
}

// prepRedirect clones base and merges addPath and query into the clone.
func prepRedirect(base *url.URL, addPath string, query url.Values) *url.URL {
	out := *base // clone — never mutate the shared map entry
	if addPath != "" {
		if !strings.HasSuffix(out.Path, "/") {
			out.Path += "/"
		}
		out.Path += addPath
	}
	if len(query) > 0 {
		qs := out.Query()
		for k, vs := range query {
			for _, v := range vs {
				qs.Add(k, v)
			}
		}
		out.RawQuery = qs.Encode()
	}
	return &out
}

// urlMap parses sheet rows into a URLMap. Col A is the shortcut (lowercased),
// col B is the destination URL. Duplicate shortcuts log a warning; last wins.
func urlMap(in [][]interface{}) URLMap {
	out := make(URLMap, len(in))
	for _, row := range in {
		if len(row) < 2 {
			continue
		}
		k, ok := row[0].(string)
		if !ok || k == "" {
			continue
		}
		v, ok := row[1].(string)
		if !ok || v == "" {
			continue
		}
		k = strings.ToLower(k)
		u, err := url.Parse(v)
		if err != nil {
			slog.Warn("skipping invalid URL in sheet", "shortcut", k, "url", v, "err", err)
			continue
		}
		if _, dup := out[k]; dup {
			slog.Warn("duplicate shortcut in sheet, overwriting", "shortcut", k)
		}
		out[k] = u
	}
	return out
}

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
