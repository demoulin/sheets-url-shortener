# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A minimal Go HTTP server that uses a Google Spreadsheet as its URL shortcut database. Requests to `/<shortcut>` are redirected to the URL in column B of the matching row in column A. Designed to be deployed on Google Cloud Run.

## Commands

```bash
# Run locally (requires GOOGLE_SHEET_ID env var and ADC configured)
GOOGLE_SHEET_ID=<id> go run .

# Build binary
CGO_ENABLED=0 go build -o ./a.out .

# Run tests
go test -race ./...

# Run a single test
go test -race -run TestKickRefreshOnStaleCacheEntry .

# Vulnerability scan (also run in CI)
go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Build Docker image
docker build -t sheets-url-shortener .

# Update dependencies
go get -u google.golang.org/api
go mod tidy
```

There is no linter configuration in this project.

## Architecture

The application is split into small single-package files by concern:

**`main.go`** — bootstrap only: loads config, wires the cache + `server` + middleware chain into an `http.Server`, and handles graceful shutdown via `signal.NotifyContext` + `httpSrv.Shutdown` on SIGTERM/SIGINT. Routes registered here: `GET /favicon.ico`, `GET /robots.txt`, `GET /healthz` (liveness — always 200), `GET /readyz` (readiness — 503 until the cache's first successful refresh, then 200), and `GET /` (catch-all → home or redirect). All routes are GET-only (HEAD matched implicitly); other methods get a 405.

**`config.go`** — `config` struct and `loadConfig()`, which reads all env vars and applies defaults. Returns an error for a missing required value (`GOOGLE_SHEET_ID`) or a malformed one (`CACHE_TTL`); `main()` turns either into a fatal startup exit.

**`cache.go`** — `cachedURLMap` (the in-memory TTL cache) and the `urlMap()` row parser:
- `start()` (called once at boot) does an initial refresh then runs a background `time.Ticker` goroutine that re-fetches every TTL. The server binds and serves immediately; the cache populates asynchronously, so early requests may 404 until the first refresh lands. `Ready()` (a `ready atomic.Bool` set on first successful refresh) backs the `/readyz` probe so the platform can hold traffic until the cache is warm.
- `doRefresh()` queries Sheets **outside** any lock, then takes a brief write lock only to swap the map pointer — concurrent `Get()`s are not blocked during the Sheets API call.
- `kickRefresh()` (run on every `Get()`) fires a one-shot background refresh if the cache is stale and none is already running (guarded by an `atomic.Bool`). This keeps the cache warm under Cloud Run CPU throttling, where the background ticker may not fire between requests.
- Failed refreshes keep serving stale data (logged, never fatal).
- `urlMap()` converts raw `[][]interface{}` sheet rows into a `URLMap` (`map[string]*url.URL`). Keys are lowercased; rows with <2 columns, empty cells, unparseable URLs, or non-`http(s)` schemes are skipped with a warning; duplicate shortcuts log a warning and the last one wins.

**`redirect.go`** — the `server` type and redirect logic:
- `findRedirect()`: longest-prefix path matching. For a request path like `/gcp/foo/bar`, it tries `gcp/foo/bar` → `gcp/foo` → `gcp` in order, stopping at the first match. Any unmatched trailing segments are appended to the destination URL via `prepRedirect()`.
- `prepRedirect()`: clones the destination URL (never mutates the shared map entry), appends extra path segments, and merges query parameters from the incoming request.

**`middleware.go`** — the middleware chain (applied in `main()`): `requestLogger` → `recovery` → `securityHeaders` → mux. `requestLogger` emits one structured access-log line per request and correlates with Cloud Trace via the `X-Cloud-Trace-Context` header. `recovery` turns panics into a 500 plus a single JSON log entry with the stack (for Cloud Error Reporting). `securityHeaders` sets baseline headers on every response (`home()` in `redirect.go` adds CSP/`X-Frame-Options` for its HTML).

**`handlers.go`** — static/utility handlers (`favicon.ico` embedded from `static/` via `//go:embed`, `robots.txt`, `healthz`, `readyz`).

**`logging.go`** — `newCloudLogger()` builds the default JSON `slog` logger with a `ReplaceAttr` that maps slog's keys to Cloud Logging's special fields: `level` → `severity` (with `WARN` rewritten to `WARNING` via `cloudSeverity`), `msg` → `message`, `time` → `timestamp`. Without this remap, Cloud Logging would treat every entry as DEFAULT severity. `recovery` (in `middleware.go`) additionally tags panic logs with `@type` = `ReportedErrorEvent` so they surface in Cloud Error Reporting.

**`sheetsprovider.go`** — thin wrapper around the Google Sheets API. Reads columns A:B from the configured spreadsheet using Application Default Credentials (ADC). The range becomes `SheetName!A:B` if `SHEET_NAME` is set.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `GOOGLE_SHEET_ID` | (required) | Spreadsheet ID from the sheet URL |
| `SHEET_NAME` | `""` | Named tab within the spreadsheet |
| `CACHE_TTL` | `5s` | Go duration string; how often to re-fetch the sheet |
| `HOME_REDIRECT` | `""` | URL to redirect `/` to; shows a 404 page if unset |
| `PORT` | `8080` | HTTP listen port |
| `LISTEN_ADDR` | `""` | Network interface to bind (empty = all interfaces) |
| `GOOGLE_CLOUD_PROJECT` | `""` | Project ID; only used to format Cloud Trace log fields |

## Key Behaviours to Preserve

- Shortcuts are **case-insensitive** (normalized to lowercase at parse time).
- Redirects use **302 Found** (never 301) so browsers don't cache them permanently.
- The cache **never blocks reads on the Sheets API**: the network call happens outside the lock, and only the map-pointer swap is locked. Stale data is served on refresh failure.
- Only `http`/`https` destination URLs are accepted; other schemes are dropped at parse time.
- Logs are **structured JSON** (`slog`) on stdout for Cloud Logging, using Cloud's field names (`severity`/`message`/`timestamp`) via `newCloudLogger()`; do not switch to plain text or revert the field mapping.
- `robots.txt` disallows all crawlers; `favicon.ico` is embedded from `static/` via `//go:embed`.

## Deployment

- **Google Cloud Run**: click-to-deploy via the button in README. The Cloud Run service account must be granted "Viewer" access to the spreadsheet, and the Google Sheets API must be enabled in the project.
- **Tailscale variant**: `start.sh` starts `tailscaled` in userspace-networking mode before launching the server; used when the service needs to be reachable over a Tailscale network.
