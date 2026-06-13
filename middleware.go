package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

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
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
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
