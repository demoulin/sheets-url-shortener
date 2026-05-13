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
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

//go:embed static/*
var static embed.FS

func main() {
	// JSON logs so Cloud Logging can parse structured fields.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := os.Getenv("LISTEN_ADDR")

	googleSheetsID := os.Getenv("GOOGLE_SHEET_ID")
	sheetName := os.Getenv("SHEET_NAME")
	homeRedirect := os.Getenv("HOME_REDIRECT")
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")

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

	// Start async — server is ready to accept requests immediately.
	cache.start(ctx)

	srv := &server{db: cache, homeRedirect: homeRedirect}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /favicon.ico", faviconHandler)
	mux.HandleFunc("GET /robots.txt", robotsHandler)
	mux.HandleFunc("GET /healthz", healthHandler)
	mux.HandleFunc("/", srv.handler)

	listenAddr := net.JoinHostPort(addr, port)
	httpSrv := &http.Server{
		Addr:              listenAddr,
		Handler:           requestLogger(projectID)(recovery(securityHeaders(mux))),
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
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

type sheetQuerier interface {
	Query(ctx context.Context) ([][]interface{}, error)
}

type cachedURLMap struct {
	mu         sync.RWMutex
	v          URLMap
	lastUpdate time.Time

	// refreshing prevents concurrent on-request refresh kicks.
	refreshing atomic.Bool

	ttl   time.Duration
	sheet sheetQuerier
}

// start launches background refresh in a goroutine so the server can bind
// and accept health checks immediately. The cache populates asynchronously.
func (c *cachedURLMap) start(ctx context.Context) {
	go func() {
		c.doRefresh(ctx)
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
	c.lastUpdate = time.Now()
	c.mu.Unlock()
}

// kickRefresh fires a one-shot background refresh when the cache is stale and
// no on-request refresh is already running. This keeps the cache warm when
// Cloud Run's default CPU throttling prevents the background goroutine from
// ticking between requests.
func (c *cachedURLMap) kickRefresh() {
	c.mu.RLock()
	stale := !c.lastUpdate.IsZero() && time.Since(c.lastUpdate) > c.ttl
	c.mu.RUnlock()
	if stale && c.refreshing.CompareAndSwap(false, true) {
		go func() {
			defer c.refreshing.Store(false)
			c.doRefresh(context.Background())
		}()
	}
}

func (c *cachedURLMap) Get(key string) *url.URL {
	c.kickRefresh()
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
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
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
		if u.Scheme != "http" && u.Scheme != "https" {
			slog.Warn("skipping URL with non-http(s) scheme in sheet", "shortcut", k, "scheme", u.Scheme)
			continue
		}
		if _, dup := out[k]; dup {
			slog.Warn("duplicate shortcut in sheet, overwriting", "shortcut", k)
		}
		out[k] = u
	}
	return out
}

// statusWriter wraps ResponseWriter to capture the status code written by a handler.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// parseCloudTrace parses an X-Cloud-Trace-Context header value.
// Format: TRACE_ID[/SPAN_ID[;o=FLAGS]]
func parseCloudTrace(h string) (traceID, spanID string) {
	if h == "" {
		return
	}
	traceID, rest, _ := strings.Cut(h, "/")
	spanID, _, _ = strings.Cut(rest, ";")
	return
}

// requestLogger logs one structured access-log entry per request and attaches
// Cloud Trace fields so Cloud Logging can correlate log entries with traces.
func requestLogger(projectID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &statusWriter{ResponseWriter: w, status: http.StatusOK}

			logger := slog.Default()
			traceID, spanID := parseCloudTrace(r.Header.Get("X-Cloud-Trace-Context"))
			if traceID != "" {
				trace := traceID
				if projectID != "" {
					trace = "projects/" + projectID + "/traces/" + traceID
				}
				logger = logger.With(
					"logging.googleapis.com/trace", trace,
					"logging.googleapis.com/spanId", spanID,
				)
			}

			next.ServeHTTP(ww, r)

			attrs := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.status,
				"latency_ms", time.Since(start).Milliseconds(),
			}
			if loc := ww.Header().Get("Location"); loc != "" {
				attrs = append(attrs, "location", loc)
			}
			logger.Info("request", attrs...)
		})
	}
}

// securityHeaders adds baseline security headers to every response.
// CSP and X-Frame-Options are added per-handler for HTML responses.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// recovery wraps a handler with panic recovery. The panic value and full stack
// trace are written as a single JSON log entry so Cloud Error Reporting can
// group them correctly. net/http's built-in recovery is bypassed this way.
func recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				slog.Error("panic recovered",
					"panic", fmt.Sprintf("%v", p),
					"stack", string(debug.Stack()),
					"method", r.Method,
					"path", r.URL.Path,
				)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
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
