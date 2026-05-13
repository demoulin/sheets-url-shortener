package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
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

func TestCachedURLMapRefresh(t *testing.T) {
	synctest.Run(func() {
		mock := &mockSheet{rows: [][]interface{}{{"gh", "https://github.com"}}}
		cache := &cachedURLMap{ttl: time.Second, sheet: mock}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// start() is async; Wait() lets the initial refresh and first ticker
		// select complete before we inspect state.
		cache.start(ctx)
		synctest.Wait()

		if n := mock.calls.Load(); n != 1 {
			t.Errorf("after start: calls=%d, want 1", n)
		}
		if cache.Get("gh") == nil {
			t.Error("'gh' should be in cache after initial refresh")
		}

		// advance virtual clock by one TTL — ticker fires, refresh runs
		time.Sleep(time.Second)
		synctest.Wait()

		if n := mock.calls.Load(); n != 2 {
			t.Errorf("after first tick: calls=%d, want 2", n)
		}

		// inject an error; stale data must survive the failed refresh
		mock.setErr(errors.New("sheets unavailable"))
		time.Sleep(time.Second)
		synctest.Wait()

		if n := mock.calls.Load(); n != 3 {
			t.Errorf("after error tick: calls=%d, want 3", n)
		}
		// lastUpdate was T1 (last success); at T2 time.Since(T1)=TTL which is
		// not > TTL, so kickRefresh does not fire — safe to call Get here.
		if cache.Get("gh") == nil {
			t.Error("stale data should be served when refresh fails")
		}

		// canceling ctx must stop the background goroutine cleanly
		cancel()
		synctest.Wait()
	})
}

func TestKickRefreshOnStaleCacheEntry(t *testing.T) {
	synctest.Run(func() {
		mock := &mockSheet{rows: [][]interface{}{{"gh", "https://github.com"}}}
		cache := &cachedURLMap{ttl: time.Second, sheet: mock}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cache.start(ctx)
		synctest.Wait() // initial refresh done, calls=1

		// Simulate CPU-throttled Cloud Run: stop the background goroutine
		// by canceling its context, then verify a stale Get kicks a refresh.
		cancel()
		synctest.Wait() // background goroutine exited

		// Advance past TTL without any background tick.
		time.Sleep(2 * time.Second)

		// A fresh context for any kick-triggered refresh goroutines.
		ctx2, cancel2 := context.WithCancel(context.Background())
		defer cancel2()
		_ = ctx2

		// Get sees the cache is stale (lastUpdate > TTL ago) and kicks a refresh.
		cache.Get("gh")
		synctest.Wait() // kick-triggered refresh goroutine completes

		if n := mock.calls.Load(); n != 2 {
			t.Errorf("after stale Get: calls=%d, want 2", n)
		}
	})
}
