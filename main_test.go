package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	// "net/url" // Will be needed for specific test cases later
	// "strings" // Will be needed for specific test cases later
	"testing"
	"time"
)

// mockSheetsProvider is a mock implementation of the URLProvider interface.
type mockSheetsProvider struct {
	mockData [][]interface{}
	queryErr error
}

// Query implements the URLProvider interface for mockSheetsProvider.
func (m *mockSheetsProvider) Query(ctx context.Context) ([][]interface{}, error) {
	if m.queryErr != nil {
		return nil, m.queryErr
	}
	// Simulate a slight delay, similar to a real API call
	// time.Sleep(10 * time.Millisecond)
	return m.mockData, nil
}

// newTestServer sets up a test HTTP server with a given URLProvider and optional home redirect.
// It tries to mimic the main server setup including middlewares.
func newTestServer(t *testing.T, provider URLProvider, homeRedirectURL ...string) *httptest.Server {
	t.Helper()

	// Use a minimal config for tests, relying on Viper defaults where possible.
	// Override specific values if necessary for test behavior.
	testCfg := &Config{ // Renamed to avoid conflict with global cfg if any
		Port:                     "8080", // Default, not used by httptest
		CacheTTL:                 "1s",   // Short TTL for cache testing if needed, otherwise less critical
		SheetQueryTimeout:        "500ms", // Short timeout for sheet queries in tests
		OtelServiceName:          "test-url-shortener",
		OtelExporterOtlpEndpoint: "localhost:4318", // Standard, though likely not hit in tests
		OtelExporterOtlpProtocol: "http/protobuf",
		ServiceVersion:           "test",
		ServerShutdownTimeout:    "1s",
		RateLimitEnabled:         false, // Disable rate limiting for most tests unless testing it specifically
		// Other fields like GoogleSheetID, ProjectID can be empty if not directly used by core logic being tested
	}
	if len(homeRedirectURL) > 0 && homeRedirectURL[0] != "" {
		testCfg.HomeRedirect = homeRedirectURL[0]
	}


	// Parse durations
	cacheTTL, err := time.ParseDuration(testCfg.CacheTTL)
	if err != nil {
		t.Fatalf("Failed to parse CacheTTL for test server: %v", err)
	}
	sheetQueryTimeout, err := time.ParseDuration(testCfg.SheetQueryTimeout)
	if err != nil {
		t.Fatalf("Failed to parse SheetQueryTimeout for test server: %v", err)
	}

	// Initialize components as in main() but with mocks/test configs
	// No need to initialize actual OTel, Error Reporting, Rate Limiter for unit/core logic tests
	// unless those specific features are being tested.
	// For core redirect logic, these can be simplified or nilled out if their setup is complex
	// and not relevant to the redirect itself.

	// Initialize cachedURLMap with the mock provider
	testCachedURLMap := &cachedURLMap{
		ttl:               cacheTTL,
		sheetQueryTimeout: sheetQueryTimeout,
		sheet:             provider,
		// v and lastUpdate will be initialized on first refresh
	}

	// Create server instance
	testAppServer := &server{
		db:           testCachedURLMap,
		homeRedirect: testCfg.HomeRedirect, // Use from testCfg
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", testAppServer.handler)
	// Favicon and robots can be ignored for core redirect tests or added if full coverage is desired
	// mux.HandleFunc("/favicon.ico", faviconHandler)
	// mux.HandleFunc("/robots.txt", robotsHandler)

	// Apply middlewares - for integration tests, it's good to include them.
	// For pure unit tests of srv.handler, one might pass testAppServer.handler directly.
	// Here, we'll include them to be closer to the real setup.
	// Note: otelMiddleware, securityHeadersMiddleware, rateLimitMiddleware are from main.go
	
	// Simplified middleware chain for testing core redirect logic;
	// OTel and Rate Limiting might add noise or require more setup if fully enabled.
	// For now, let's test the core handler logic, then consider adding middlewares.
	// finalHandler := rateLimitMiddleware(securityHeadersMiddleware(otelMiddleware(mux)))
	// If otel.Tracer() is called directly in handlers, ensure it doesn't panic if OTel SDK is not fully init.
	// For these tests, we are not initializing the global OTel tracer provider or error client.
	// The production code's initTracer and initErrorReporting are not called.
	// This means calls to otel.Tracer() will get a no-op tracer.
	// Calls to reportError() will log "Error reporting is not initialized" if errorClient is nil.

	// Using a simplified chain for now to focus on redirect logic.
	// If middlewares are essential to the redirect logic being tested, they should be included.
	// For this initial test, let's use a simpler chain, perhaps only the core handler.
	// For a more "integration" style test, the full chain is better.
	// Let's assume the middlewares don't fundamentally change the redirect for now.
	// We can pass testAppServer.handler directly if we want to unit test just the handler.
	// Or pass the mux if we want to test routing by the mux.
	
	// Let's use the full chain to be closer to production, assuming no-op OTel/Error Reporting is fine.
	// Ensure global 'limiter' is nil or rate limiting is disabled in testCfg for tests not focusing on it.
	if testCfg.RateLimitEnabled {
		limiter = rate.NewLimiter(rate.Limit(testCfg.RateLimitRPS), testCfg.RateLimitBurst)
	} else {
		limiter = nil // Ensure limiter is nil if disabled for tests
	}


	finalHandler := rateLimitMiddleware(securityHeadersMiddleware(otelMiddleware(mux)))


	return httptest.NewServer(finalHandler)
}

// TestRedirectSuccess is a basic test for a successful redirect.
func TestRedirectSuccess(t *testing.T) {
	mockProvider := &mockSheetsProvider{
		mockData: [][]interface{}{
			{"/testpath", "http://example.com/redirected"},
		},
	}

	ts := newTestServer(t, mockProvider)
	defer ts.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Prevent following redirects
		},
	}

	req, err := http.NewRequest("GET", ts.URL+"/testpath", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("Expected status code %d, got %d", http.StatusFound, resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	expectedLocation := "http://example.com/redirected"
	if location != expectedLocation {
		t.Errorf("Expected Location header %q, got %q", expectedLocation, location)
	}
}

func TestRedirectPathAppending(t *testing.T) {
	tests := []struct {
		name             string
		basePath         string
		baseRedirectTo   string
		requestPathSuffix string
		expectedLocation string
	}{
		{
			name:             "no_trailing_slash_base_simple_suffix",
			basePath:         "/base1",
			baseRedirectTo:   "http://example.com/targetpath",
			requestPathSuffix: "/extra",
			expectedLocation: "http://example.com/targetpath/extra",
		},
		{
			name:             "trailing_slash_base_simple_suffix",
			basePath:         "/base2/",
			baseRedirectTo:   "http://example.com/targetpath/",
			requestPathSuffix: "extra/path", // No leading slash for suffix when base has trailing
			expectedLocation: "http://example.com/targetpath/extra/path",
		},
		{
			name:             "no_trailing_slash_base_empty_suffix_request_slash",
			basePath:         "/base3",
			baseRedirectTo:   "http://example.com/targetpath",
			requestPathSuffix: "/", // Requesting "/base3/"
			expectedLocation: "http://example.com/targetpath/",
		},
		{
			name:             "trailing_slash_base_empty_suffix",
			basePath:         "/base4/",
			baseRedirectTo:   "http://example.com/targetpath/",
			requestPathSuffix: "", // Requesting "/base4/"
			expectedLocation: "http://example.com/targetpath/",
		},
		{
			name:             "base_only_no_suffix",
			basePath:         "/base5",
			baseRedirectTo:   "http://example.com/targetpathonly",
			requestPathSuffix: "", // Requesting "/base5"
			expectedLocation: "http://example.com/targetpathonly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockProvider := &mockSheetsProvider{
				mockData: [][]interface{}{
					{tt.basePath, tt.baseRedirectTo},
				},
			}

			ts := newTestServer(t, mockProvider)
			defer ts.Close()

			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			requestURL := ts.URL + tt.basePath
			if tt.requestPathSuffix != "" && tt.basePath[len(tt.basePath)-1] == '/' && tt.requestPathSuffix[0] == '/' {
				// Avoid double slash if base ends with / and suffix starts with /
				requestURL = ts.URL + tt.basePath + tt.requestPathSuffix[1:]
			} else if tt.requestPathSuffix != "" && tt.basePath[len(tt.basePath)-1] != '/' && tt.requestPathSuffix[0] != '/' {
				// Add slash if base does not end with / and suffix does not start with /
				requestURL = ts.URL + tt.basePath + "/" + tt.requestPathSuffix
			} else if tt.requestPathSuffix != "" {
				requestURL = ts.URL + tt.basePath + tt.requestPathSuffix
			}
			
			// Special case for testing if just "/" is appended to a non-trailing slash base path
			if tt.requestPathSuffix == "/" && tt.basePath[len(tt.basePath)-1] != '/' {
				requestURL = ts.URL + tt.basePath + "/"
			}


			req, err := http.NewRequest("GET", requestURL, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusFound {
				t.Errorf("Expected status code %d, got %d for URL %s", http.StatusFound, resp.StatusCode, requestURL)
			}

			location := resp.Header.Get("Location")
			if location != tt.expectedLocation {
				t.Errorf("For request URL %s: Expected Location header %q, got %q", requestURL, tt.expectedLocation, location)
			}
		})
	}
}

func TestRedirectQueryParameters(t *testing.T) {
	tests := []struct {
		name             string
		basePath         string
		baseRedirectTo   string
		requestQuery     string
		expectedLocation string // Query params order might vary, so check carefully or parse
	}{
		{
			name:             "merge_query_params",
			basePath:         "/qp",
			baseRedirectTo:   "http://example.com/target?existing=true&color=blue",
			requestQuery:     "?new=yes&another=val",
			expectedLocation: "http://example.com/target?another=val&color=blue&existing=true&new=yes", // Sorted for assertion
		},
		{
			name:             "redirect_has_no_query_request_has_query",
			basePath:         "/noqp",
			baseRedirectTo:   "http://example.com/target",
			requestQuery:     "?new=yes&src=test",
			expectedLocation: "http://example.com/target?new=yes&src=test", // Sorted
		},
		{
			name:             "redirect_has_query_request_has_no_query",
			basePath:         "/onlyqp",
			baseRedirectTo:   "http://example.com/target?existing=true",
			requestQuery:     "",
			expectedLocation: "http://example.com/target?existing=true",
		},
		{
			name:             "both_have_no_query",
			basePath:         "/noqpeither",
			baseRedirectTo:   "http://example.com/target",
			requestQuery:     "",
			expectedLocation: "http://example.com/target",
		},
		{
			name:             "conflicting_params_request_overwrites", // Standard library http.Request.URL.Query() behavior
			basePath:         "/conflict",
			baseRedirectTo:   "http://example.com/target?param1=old&param2=original",
			requestQuery:     "?param1=new&param3=added",
			expectedLocation: "http://example.com/target?param1=new&param2=original&param3=added", // Sorted
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockProvider := &mockSheetsProvider{
				mockData: [][]interface{}{
					{tt.basePath, tt.baseRedirectTo},
				},
			}

			ts := newTestServer(t, mockProvider)
			defer ts.Close()

			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			requestURL := ts.URL + tt.basePath + tt.requestQuery
			req, err := http.NewRequest("GET", requestURL, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusFound {
				t.Errorf("Expected status code %d, got %d for URL %s", http.StatusFound, resp.StatusCode, requestURL)
			}

			locationHeader := resp.Header.Get("Location")
			
			// Parse URLs to compare query parameters irrespective of order
			expectedURL, _ := url.Parse(tt.expectedLocation)
			actualURL, _ := url.Parse(locationHeader)

			if expectedURL.Scheme != actualURL.Scheme || expectedURL.Host != actualURL.Host || expectedURL.Path != actualURL.Path {
				t.Errorf("Base URL mismatch for request URL %s: Expected %s, got %s", requestURL, expectedURL.String(), actualURL.String())
			}
			
			expectedParams := expectedURL.Query()
			actualParams := actualURL.Query()
			if len(expectedParams) != len(actualParams) {
				t.Errorf("Query param count mismatch for request URL %s: Expected %d params (%v), got %d params (%v). Full URLs: Expected %s, Got %s",
					requestURL, len(expectedParams), expectedParams, len(actualParams), actualParams, tt.expectedLocation, locationHeader)
			}
			for k, v := range expectedParams {
				if actualParams.Get(k) != v[0] { // Assuming single values for simplicity in test setup
					t.Errorf("Query param mismatch for key %s (request URL %s): Expected %s, got %s. Full URLs: Expected %s, Got %s",
						k, requestURL, v[0], actualParams.Get(k), tt.expectedLocation, locationHeader)
				}
			}
		})
	}
}

func TestHomeRedirect(t *testing.T) {
	homeURL := "http://example.com/testhomepage"
	// For this test, the mockProvider's data doesn't matter as we're hitting "/"
	mockProvider := &mockSheetsProvider{} 

	ts := newTestServer(t, mockProvider, homeURL) // Pass homeURL
	defer ts.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", ts.URL+"/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("Expected status code %d for home redirect, got %d", http.StatusFound, resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != homeURL {
		t.Errorf("Expected Location header %q for home redirect, got %q", homeURL, location)
	}
}

func TestHomeDefaultNotFound(t *testing.T) {
	// For this test, the mockProvider's data doesn't matter, and homeRedirectURL is empty.
	mockProvider := &mockSheetsProvider{} 

	ts := newTestServer(t, mockProvider) // No homeRedirectURL provided
	defer ts.Close()

	// Client that follows redirects, as we want to check the final page content
	client := &http.Client{} 

	req, err := http.NewRequest("GET", ts.URL+"/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status code %d for default home, got %d", http.StatusNotFound, resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	bodyString := string(bodyBytes)
	if !strings.Contains(bodyString, "Not found :(") {
		t.Errorf("Expected body to contain 'Not found :(', got: %s", bodyString)
	}
}

func TestRedirectNotFound(t *testing.T) {
	mockProvider := &mockSheetsProvider{
		mockData: [][]interface{}{
			{"/exists", "http://example.com/itdoesexist"},
		},
	}

	ts := newTestServer(t, mockProvider)
	defer ts.Close()

	// Client that follows redirects, as we want to check the final page content
	client := &http.Client{} 

	req, err := http.NewRequest("GET", ts.URL+"/doesnotexist", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status code %d for non-existent path, got %d", http.StatusNotFound, resp.StatusCode)
	}
	
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	bodyString := string(bodyBytes)
	if !strings.Contains(bodyString, "404 not found") { // This is the specific message for path not found
		t.Errorf("Expected body to contain '404 not found', got: %s", bodyString)
	}
}

func TestRedirectProviderError(t *testing.T) {
	mockProvider := &mockSheetsProvider{
		queryErr: fmt.Errorf("mock sheet query error"),
	}

	ts := newTestServer(t, mockProvider)
	defer ts.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Not expecting redirect, but good practice
		},
	}

	req, err := http.NewRequest("GET", ts.URL+"/somepath", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected status code %d for provider error, got %d", http.StatusInternalServerError, resp.StatusCode)
	}
	// We could also check if reportError was called, but that requires more advanced mocking of errorClient or log inspection.
}

func TestRedirectCache(t *testing.T) {
	cacheTestPath := "/cachetest"
	initialRedirectURL := "http://example.com/initial-cached"
	updatedRedirectURL := "http://example.com/updated-after-cache"

	mockProvider := &mockSheetsProvider{
		mockData: [][]interface{}{
			{cacheTestPath, initialRedirectURL},
		},
	}

	// Configure test server with a very short CacheTTL for this test
	// We need a way to pass custom config to newTestServer or have a dedicated one.
	// For now, let's assume newTestServer uses a short TTL (e.g., 100ms)
	// The current newTestServer has CacheTTL: "1s", SheetQueryTimeout: "500ms"
	// We will need to adjust these or make them configurable per test.
	// Let's modify newTestServer to accept a Config struct pointer, allowing overrides.

	// Create a custom config for this test
	testSpecificCfg := &Config{
		CacheTTL:          "100ms", // Very short TTL
		SheetQueryTimeout: "50ms",  // Short query timeout
		RateLimitEnabled:  false,   // Keep rate limiting off
		// Other fields can be default or test-specific if needed
	}


	ts := newTestServerWithConfig(t, mockProvider, testSpecificCfg)
	defer ts.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// --- First request: Populate cache ---
	req1, _ := http.NewRequest("GET", ts.URL+cacheTestPath, nil)
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("Request 1 failed: %v", err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusFound {
		t.Fatalf("Request 1: Expected status %d, got %d", http.StatusFound, resp1.StatusCode)
	}
	if loc1 := resp1.Header.Get("Location"); loc1 != initialRedirectURL {
		t.Fatalf("Request 1: Expected location %q, got %q", initialRedirectURL, loc1)
	}
	t.Logf("Request 1: Redirected to %s (cache populated)", initialRedirectURL)


	// --- Second request: Hit cache ---
	// Change mock provider data *after* first request, *before* second.
	// If cache works, this change should not be reflected yet.
	mockProvider.mockData = [][]interface{}{ 
		{cacheTestPath, updatedRedirectURL}, // Point to a new URL
	}
	mockProvider.queryErr = nil // Ensure no error for subsequent real queries if cache misses

	req2, _ := http.NewRequest("GET", ts.URL+cacheTestPath, nil)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("Request 2 failed: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("Request 2 (cache hit): Expected status %d, got %d", http.StatusFound, resp2.StatusCode)
	}
	if loc2 := resp2.Header.Get("Location"); loc2 != initialRedirectURL { // Should still be initial
		t.Fatalf("Request 2 (cache hit): Expected location %q (from cache), got %q", initialRedirectURL, loc2)
	}
	t.Logf("Request 2: Redirected to %s (from cache)", initialRedirectURL)


	// --- Third request: Cache expired, fetch new data ---
	// Wait for TTL (100ms) + a bit more to expire
	time.Sleep(150 * time.Millisecond)

	req3, _ := http.NewRequest("GET", ts.URL+cacheTestPath, nil)
	resp3, err := client.Do(req3)
	if err != nil {
		t.Fatalf("Request 3 failed: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusFound {
		t.Fatalf("Request 3 (cache expired): Expected status %d, got %d", http.StatusFound, resp3.StatusCode)
	}
	if loc3 := resp3.Header.Get("Location"); loc3 != updatedRedirectURL { // Should now be the updated URL
		t.Fatalf("Request 3 (cache expired): Expected location %q (new data), got %q", updatedRedirectURL, loc3)
	}
	t.Logf("Request 3: Redirected to %s (new data after cache expiry)", updatedRedirectURL)

	// --- Fourth request: Provider error after cache expiry ---
	mockProvider.mockData = nil
	mockProvider.queryErr = fmt.Errorf("mock sheet error after cache")
	
	time.Sleep(150 * time.Millisecond) // Ensure cache TTL expires again

	req4, _ := http.NewRequest("GET", ts.URL+cacheTestPath, nil)
	resp4, err := client.Do(req4)
	if err != nil {
		t.Fatalf("Request 4 failed: %v", err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusInternalServerError {
		// This assumes that an error during refresh (after cache expiry) leads to InternalServerError
		t.Fatalf("Request 4 (provider error after cache expiry): Expected status %d, got %d", http.StatusInternalServerError, resp4.StatusCode)
	}
	t.Logf("Request 4: Got status %d (provider error after cache expiry)", resp4.StatusCode)
}


// TODO: Add more test cases:
// - TestInvalidURLInSheet (e.g., non-HTTP/HTTPS URL, malformed URL - check for logged warnings)
// - TestRateLimiting (if rateLimitMiddleware is included and enabled in test server config)
// - TestSecurityHeaders (if securityHeadersMiddleware is included)
