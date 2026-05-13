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

# Build Docker image
docker build -t sheets-url-shortener .

# Update dependencies
go get -u google.golang.org/api
go mod tidy
```

There is no linter configuration in this project.

## Architecture

The entire application is two source files:

**`main.go`** — HTTP server, caching layer, redirect logic:
- `cachedURLMap`: wraps `sheetsProvider` with an in-memory TTL cache. On every `Get()`, if the TTL has expired it acquires a write lock and re-fetches from Sheets; otherwise it uses a read lock to serve from cache.
- `urlMap()`: converts raw `[][]interface{}` sheet rows into `map[string]*url.URL`. Keys are lowercased; duplicate shortcuts log a warning and the last one wins.
- `findRedirect()`: longest-prefix path matching. For a request path like `/gcp/foo/bar`, it tries `gcp/foo/bar` → `gcp/foo` → `gcp` in order, stopping at the first match. Any unmatched trailing segments are appended to the destination URL via `prepRedirect()`.
- `prepRedirect()`: merges query parameters from the incoming request into the destination URL and appends extra path segments.

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

## Key Behaviours to Preserve

- Shortcuts are **case-insensitive** (normalized to lowercase at parse time).
- Redirects use **302 Found** (never 301) so browsers don't cache them permanently.
- The cache refresh holds a **write lock for the full Sheets API call**, so concurrent requests block during refresh.
- `robots.txt` disallows all crawlers; `favicon.ico` is embedded from `static/` via `//go:embed`.

## Deployment

- **Google Cloud Run**: click-to-deploy via the button in README. The Cloud Run service account must be granted "Viewer" access to the spreadsheet, and the Google Sheets API must be enabled in the project.
- **Tailscale variant**: `start.sh` starts `tailscaled` in userspace-networking mode before launching the server; used when the service needs to be reachable over a Tailscale network.
