package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mockSheet struct {
	calls atomic.Int64
	mu    sync.Mutex
	rows  [][]interface{}
	err   error
}

func (m *mockSheet) Query(_ context.Context) ([][]interface{}, error) {
	m.mu.Lock()
	rows, err := m.rows, m.err
	m.mu.Unlock()
	m.calls.Add(1)
	return rows, err
}

func (m *mockSheet) setErr(err error) {
	m.mu.Lock()
	m.err = err
	m.mu.Unlock()
}

// waitForCalls polls until mock.calls >= n or the timeout elapses.
func waitForCalls(t *testing.T, mock *mockSheet, n int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if mock.calls.Load() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Errorf("timed out waiting for %d calls; got %d", n, mock.calls.Load())
}

func TestCachedURLMapRefresh(t *testing.T) {
	const ttl = 20 * time.Millisecond

	mock := &mockSheet{rows: [][]interface{}{{"gh", "https://github.com"}}}
	cache := &cachedURLMap{ttl: ttl, sheet: mock}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cache.start(ctx)

	// initial refresh must happen asynchronously
	waitForCalls(t, mock, 1, time.Second)
	if cache.Get("gh") == nil {
		t.Error("'gh' should be in cache after initial refresh")
	}

	// ticker fires at least once more after one TTL
	waitForCalls(t, mock, 2, time.Second)

	// stale data must survive a failed refresh
	mock.setErr(errors.New("sheets unavailable"))
	waitForCalls(t, mock, 3, time.Second)
	if cache.Get("gh") == nil {
		t.Error("stale data should be served when refresh fails")
	}

	cancel()
}

func TestKickRefreshOnStaleCacheEntry(t *testing.T) {
	const ttl = 20 * time.Millisecond

	mock := &mockSheet{rows: [][]interface{}{{"gh", "https://github.com"}}}
	cache := &cachedURLMap{ttl: ttl, sheet: mock}

	ctx, cancel := context.WithCancel(context.Background())

	cache.start(ctx)
	waitForCalls(t, mock, 1, time.Second)

	// stop the background goroutine
	cancel()
	time.Sleep(ttl * 3)

	before := mock.calls.Load()

	// sleep past TTL so the cache entry is considered stale
	time.Sleep(ttl * 3)

	// Get must kick a one-shot background refresh
	cache.Get("gh")

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if mock.calls.Load() > before {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Errorf("stale Get did not trigger a refresh; calls stuck at %d", mock.calls.Load())
}
