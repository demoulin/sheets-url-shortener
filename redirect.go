package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type server struct {
	db           *cachedURLMap
	homeRedirect string
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
