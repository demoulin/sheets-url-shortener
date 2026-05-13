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

		cache.start(ctx)
		synctest.Wait() // background goroutine now blocked on ticker

		// initial synchronous refresh fires once
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
		if cache.Get("gh") == nil {
			t.Error("stale data should be served when refresh fails")
		}

		// canceling ctx must stop the background goroutine cleanly
		cancel()
		synctest.Wait()
	})
}
