package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestURLMap(t *testing.T) {
	tests := []struct {
		name      string
		rows      [][]interface{}
		wantKeys  map[string]string // shortcut → expected URL string
		wantCount int
	}{
		{
			name:      "empty input",
			rows:      nil,
			wantCount: 0,
		},
		{
			name:      "valid row",
			rows:      [][]interface{}{{"gh", "https://github.com"}},
			wantKeys:  map[string]string{"gh": "https://github.com"},
			wantCount: 1,
		},
		{
			name:      "key normalized to lowercase",
			rows:      [][]interface{}{{"GH", "https://github.com"}},
			wantKeys:  map[string]string{"gh": "https://github.com"},
			wantCount: 1,
		},
		{
			name:      "row with fewer than 2 columns skipped",
			rows:      [][]interface{}{{"gh"}},
			wantCount: 0,
		},
		{
			name:      "empty key skipped",
			rows:      [][]interface{}{{"", "https://example.com"}},
			wantCount: 0,
		},
		{
			name:      "invalid URL skipped",
			rows:      [][]interface{}{{"bad", "://missing-scheme"}},
			wantCount: 0,
		},
		{
			name:      "javascript scheme rejected",
			rows:      [][]interface{}{{"xss", "javascript:alert(1)"}},
			wantCount: 0,
		},
		{
			name:      "relative URL rejected (no scheme)",
			rows:      [][]interface{}{{"rel", "/internal/path"}},
			wantCount: 0,
		},
		{
			name:      "ftp scheme rejected",
			rows:      [][]interface{}{{"ftp", "ftp://files.example.com"}},
			wantCount: 0,
		},
		{
			name: "duplicate key last wins",
			rows: [][]interface{}{
				{"gh", "https://github.com"},
				{"gh", "https://gitlab.com"},
			},
			wantKeys:  map[string]string{"gh": "https://gitlab.com"},
			wantCount: 1,
		},
		{
			name:      "non-string key skipped",
			rows:      [][]interface{}{{42, "https://example.com"}},
			wantCount: 0,
		},
		{
			name:      "empty URL value skipped",
			rows:      [][]interface{}{{"gh", ""}},
			wantCount: 0,
		},
		{
			name:      "non-string URL value skipped",
			rows:      [][]interface{}{{"gh", 42}},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := urlMap(tt.rows)
			if len(m) != tt.wantCount {
				t.Errorf("len=%d, want %d", len(m), tt.wantCount)
			}
			for k, wantURL := range tt.wantKeys {
				got, ok := m[k]
				if !ok {
					t.Errorf("missing key %q", k)
					continue
				}
				if got.String() != wantURL {
					t.Errorf("key %q: got %q, want %q", k, got.String(), wantURL)
				}
			}
		})
	}
}

func TestPrepRedirect(t *testing.T) {
	t.Run("clones base — original must not be mutated", func(t *testing.T) {
		base, _ := url.Parse("https://example.com/base?existing=1")
		origPath := base.Path
		origQuery := base.RawQuery

		_ = prepRedirect(base, "extra", url.Values{"added": {"2"}})

		if base.Path != origPath {
			t.Errorf("base.Path mutated: got %q, want %q", base.Path, origPath)
		}
		if base.RawQuery != origQuery {
			t.Errorf("base.RawQuery mutated: got %q, want %q", base.RawQuery, origQuery)
		}
	})

	t.Run("appends path segment", func(t *testing.T) {
		base, _ := url.Parse("https://example.com/root")
		out := prepRedirect(base, "sub/path", nil)
		if !strings.HasSuffix(out.Path, "/root/sub/path") {
			t.Errorf("unexpected path: %s", out.Path)
		}
	})

	t.Run("path already ending in slash", func(t *testing.T) {
		base, _ := url.Parse("https://example.com/root/")
		out := prepRedirect(base, "leaf", nil)
		if strings.Contains(out.Path, "//") {
			t.Errorf("double slash in path: %s", out.Path)
		}
	})

	t.Run("merges query params preserving existing", func(t *testing.T) {
		base, _ := url.Parse("https://example.com/?kept=yes")
		out := prepRedirect(base, "", url.Values{"added": {"val"}})
		q := out.Query()
		if q.Get("kept") != "yes" {
			t.Error("lost existing query param 'kept'")
		}
		if q.Get("added") != "val" {
			t.Error("missing forwarded query param 'added'")
		}
	})

	t.Run("multi-value query params forwarded", func(t *testing.T) {
		base, _ := url.Parse("https://example.com/")
		out := prepRedirect(base, "", url.Values{"tag": {"a", "b"}})
		q := out.Query()
		if got := q["tag"]; len(got) != 2 {
			t.Errorf("tag values: got %v, want [a b]", got)
		}
	})

	t.Run("no addPath and no query leaves URL unchanged", func(t *testing.T) {
		base, _ := url.Parse("https://example.com/path")
		out := prepRedirect(base, "", nil)
		if out.String() != base.String() {
			t.Errorf("got %s, want %s", out.String(), base.String())
		}
	})
}

// makeTestServer builds a server with a pre-populated in-memory URL map.
func makeTestServer(shortcuts map[string]string) *server {
	m := make(URLMap)
	for k, v := range shortcuts {
		u, _ := url.Parse(v)
		m[strings.ToLower(k)] = u
	}
	return &server{db: &cachedURLMap{v: m}}
}

func TestFindRedirect(t *testing.T) {
	srv := makeTestServer(map[string]string{
		"gh":  "https://github.com",
		"gcp": "https://cloud.google.com",
	})

	tests := []struct {
		path    string
		wantURL string // empty = expect nil
	}{
		{"/gh", "https://github.com"},
		{"/GH", "https://github.com"},            // case-insensitive
		{"/gcp", "https://cloud.google.com"},
		{"/gcp/docs", "https://cloud.google.com/docs"},
		{"/gcp/a/b/c", "https://cloud.google.com/a/b/c"},
		{"/gh/extra", "https://github.com/extra"},
		{"/notfound", ""},
		{"/gh/sub?foo=bar", "https://github.com/sub?foo=bar"},
		{"/gh?q=1", "https://github.com?q=1"},           // exact match forwards query params
		{"/gh/", "https://github.com"},                  // trailing slash collapses to base
	}

	t.Run("exact match beats prefix", func(t *testing.T) {
		s := makeTestServer(map[string]string{
			"gcp":      "https://cloud.google.com",
			"gcp/docs": "https://docs.google.com",
		})
		req, _ := url.Parse("https://go.example.com/gcp/docs")
		got := s.findRedirect(req)
		if got == nil {
			t.Fatal("expected a redirect, got nil")
		}
		if got.String() != "https://docs.google.com" {
			t.Errorf("got %s, want https://docs.google.com", got.String())
		}
	})

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req, _ := url.Parse("https://go.example.com" + tt.path)
			got := srv.findRedirect(req)
			if tt.wantURL == "" {
				if got != nil {
					t.Errorf("expected nil, got %s", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected %s, got nil", tt.wantURL)
			}
			if got.String() != tt.wantURL {
				t.Errorf("got %s, want %s", got.String(), tt.wantURL)
			}
		})
	}
}

func TestHandlers(t *testing.T) {
	srv := makeTestServer(map[string]string{
		"gh": "https://github.com",
	})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthHandler)
	mux.HandleFunc("/", srv.handler)

	t.Run("known shortcut redirects with 302", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/gh", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Errorf("status=%d, want %d", rec.Code, http.StatusFound)
		}
		if loc := rec.Header().Get("Location"); loc != "https://github.com" {
			t.Errorf("Location=%q, want %q", loc, "https://github.com")
		}
	})

	t.Run("unknown shortcut returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/missing", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("status=%d, want %d", rec.Code, http.StatusNotFound)
		}
	})

	t.Run("home without HOME_REDIRECT returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("status=%d, want %d", rec.Code, http.StatusNotFound)
		}
	})

	t.Run("home with HOME_REDIRECT redirects", func(t *testing.T) {
		s := makeTestServer(nil)
		s.homeRedirect = "https://example.com"
		mux2 := http.NewServeMux()
		mux2.HandleFunc("/", s.handler)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		mux2.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Errorf("status=%d, want %d", rec.Code, http.StatusFound)
		}
		if loc := rec.Header().Get("Location"); loc != "https://example.com" {
			t.Errorf("Location=%q, want %q", loc, "https://example.com")
		}
	})

	t.Run("healthz returns 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status=%d, want %d", rec.Code, http.StatusOK)
		}
	})
}

func TestSecurityHeaders(t *testing.T) {
	srv := makeTestServer(map[string]string{"gh": "https://github.com"})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthHandler)
	mux.HandleFunc("/", srv.handler)
	h := recovery(securityHeaders(mux))

	baselines := []struct {
		path string
		code int
	}{
		{"/gh", http.StatusFound},
		{"/missing", http.StatusNotFound},
		{"/healthz", http.StatusOK},
	}
	for _, tt := range baselines {
		t.Run("baseline headers on "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.code {
				t.Errorf("status=%d, want %d", rec.Code, tt.code)
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options=%q, want nosniff", got)
			}
			if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
				t.Errorf("Referrer-Policy=%q, want no-referrer", got)
			}
		})
	}

	t.Run("home 404 page has CSP and X-Frame-Options", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'none'" {
			t.Errorf("Content-Security-Policy=%q, want default-src 'none'", got)
		}
		if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("X-Frame-Options=%q, want DENY", got)
		}
	})
}

func TestParseCloudTrace(t *testing.T) {
	tests := []struct {
		header  string
		traceID string
		spanID  string
	}{
		{"", "", ""},
		{"abc123", "abc123", ""},
		{"abc123/456def", "abc123", "456def"},
		{"abc123/456def;o=1", "abc123", "456def"},
		{"abc123/456def;o=0", "abc123", "456def"},
	}
	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			traceID, spanID := parseCloudTrace(tt.header)
			if traceID != tt.traceID {
				t.Errorf("traceID=%q, want %q", traceID, tt.traceID)
			}
			if spanID != tt.spanID {
				t.Errorf("spanID=%q, want %q", spanID, tt.spanID)
			}
		})
	}
}

func TestStatusWriter(t *testing.T) {
	t.Run("defaults to 200 when WriteHeader not called", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ww := &statusWriter{ResponseWriter: rec, status: http.StatusOK}
		_, _ = ww.Write([]byte("body"))
		if ww.status != http.StatusOK {
			t.Errorf("status=%d, want 200", ww.status)
		}
	})

	t.Run("captures explicit status code", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ww := &statusWriter{ResponseWriter: rec, status: http.StatusOK}
		ww.WriteHeader(http.StatusNotFound)
		if ww.status != http.StatusNotFound {
			t.Errorf("status=%d, want 404", ww.status)
		}
	})
}

func TestRequestLogger(t *testing.T) {
	srv := makeTestServer(map[string]string{"gh": "https://github.com"})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthHandler)
	mux.HandleFunc("/", srv.handler)
	h := requestLogger("")(recovery(securityHeaders(mux)))

	t.Run("redirect response has Location in header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/gh", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Errorf("status=%d, want %d", rec.Code, http.StatusFound)
		}
		if loc := rec.Header().Get("Location"); loc != "https://github.com" {
			t.Errorf("Location=%q, want https://github.com", loc)
		}
	})

	t.Run("trace header is accepted without panic", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/gh", nil)
		req.Header.Set("X-Cloud-Trace-Context", "abc123/456def;o=1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req) // must not panic
		if rec.Code != http.StatusFound {
			t.Errorf("status=%d, want %d", rec.Code, http.StatusFound)
		}
	})

	t.Run("projectID forms full trace path", func(t *testing.T) {
		// Verify the middleware can be constructed with a project ID.
		// Actual log output verification would require a custom slog handler.
		h2 := requestLogger("my-project")(recovery(securityHeaders(mux)))
		req := httptest.NewRequest(http.MethodGet, "/gh", nil)
		req.Header.Set("X-Cloud-Trace-Context", "traceid123/spanid456;o=1")
		rec := httptest.NewRecorder()
		h2.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Errorf("status=%d, want %d", rec.Code, http.StatusFound)
		}
	})
}

func TestStaticHandlers(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /favicon.ico", faviconHandler)
	mux.HandleFunc("GET /robots.txt", robotsHandler)

	t.Run("favicon returns image/x-icon", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status=%d, want %d", rec.Code, http.StatusOK)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "image/x-icon" {
			t.Errorf("Content-Type=%q, want image/x-icon", ct)
		}
		if rec.Body.Len() == 0 {
			t.Error("favicon body is empty")
		}
	})

	t.Run("robots.txt disallows all", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status=%d, want %d", rec.Code, http.StatusOK)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/plain" {
			t.Errorf("Content-Type=%q, want text/plain", ct)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Disallow: /") {
			t.Errorf("robots.txt body missing Disallow: got %q", body)
		}
	})
}

func TestCachedURLMapConcurrentReads(t *testing.T) {
	m := make(URLMap)
	u, _ := url.Parse("https://github.com")
	m["gh"] = u
	cache := &cachedURLMap{v: m}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			got := cache.Get("gh")
			if got == nil {
				t.Errorf("expected URL, got nil")
			}
		}()
	}
	wg.Wait()
}
