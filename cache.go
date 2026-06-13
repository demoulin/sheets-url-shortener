package main

import (
	"context"
	"log/slog"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// URLMap maps a lowercased shortcut to its destination URL.
type URLMap map[string]*url.URL

type sheetQuerier interface {
	Query(ctx context.Context) ([][]any, error)
}

type cachedURLMap struct {
	// v holds the current immutable map. Each refresh builds a fresh map and
	// atomically swaps the pointer, so reads are lock-free and wait-free.
	v atomic.Pointer[URLMap]

	// lastUpdate is the unix-nanos timestamp of the last successful refresh
	// (0 = never refreshed).
	lastUpdate atomic.Int64

	// refreshing prevents concurrent on-request refresh kicks.
	refreshing atomic.Bool

	// ready is set once the first refresh succeeds; until then the cache is
	// empty and the service is not ready to serve real shortcuts.
	ready atomic.Bool

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
	c.v.Store(&m)
	c.lastUpdate.Store(time.Now().UnixNano())
	c.ready.Store(true)
}

// Ready reports whether the cache has been populated by at least one
// successful refresh.
func (c *cachedURLMap) Ready() bool {
	return c.ready.Load()
}

// kickRefresh fires a one-shot background refresh when the cache is stale and
// no on-request refresh is already running. This keeps the cache warm when
// Cloud Run's default CPU throttling prevents the background goroutine from
// ticking between requests.
func (c *cachedURLMap) kickRefresh() {
	last := c.lastUpdate.Load()
	stale := last != 0 && time.Since(time.Unix(0, last)) > c.ttl
	if stale && c.refreshing.CompareAndSwap(false, true) {
		go func() {
			defer c.refreshing.Store(false)
			c.doRefresh(context.Background())
		}()
	}
}

func (c *cachedURLMap) Get(key string) *url.URL {
	c.kickRefresh()
	m := c.v.Load()
	if m == nil {
		return nil
	}
	return (*m)[key]
}

// urlMap parses sheet rows into a URLMap. Col A is the shortcut (lowercased),
// col B is the destination URL. Duplicate shortcuts log a warning; last wins.
func urlMap(in [][]any) URLMap {
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
