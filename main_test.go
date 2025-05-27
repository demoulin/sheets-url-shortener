package main

import (
	"context"
	"fmt"     // For TestRedirectProviderError, TestRedirectCache
	"io"      // For TestHomeDefaultNotFound, TestRedirectNotFound
	"net/http"
	"net/http/httptest"
	"net/url" // For TestRedirectQueryParameters
	"strings" // For TestHomeDefaultNotFound, TestRedirectPathAppending (though path joining logic might remove direct need)
	"testing"
	"time"

	"golang.org/x/time/rate" // For limiter setup
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

// newTestServerWithConfig sets up a test HTTP server with a given URLProvider and a specific Config.
// It tries to mimic the main server setup including middlewares.
func newTestServerWithConfig(t *testing.T, provider URLProvider, cfgOverrides *Config) *httptest.Server {
	t.Helper()

	// Start with default-like config, then apply overrides
	baseCfg := &Config{
		Port:                     "8080",
		CacheTTL:                 "1s", // Default for most tests
		SheetQueryTimeout:        "500ms",
		OtelServiceName:          "test-url-shortener",
		OtelExporterOtlpEndpoint: "localhost:4318",
		OtelExporterOtlpProtocol: "http/protobuf",
		ServiceVersion:           "test",
		ServerShutdownTimeout:    "1s",
		RateLimitEnabled:         false, // Default to disabled for tests
		RateLimitRPS:             10,    // Default RPS if enabled
		RateLimitBurst:           20,    // Default Burst if enabled
		// Other fields like GoogleSheetID, ProjectID, HomeRedirect are empty by default
	}

	isRateLimitConfigPresentInOverrides := false
	if cfgOverrides != nil {
		if cfgOverrides.CacheTTL != "" {
			baseCfg.CacheTTL = cfgOverrides.CacheTTL
		}
		if cfgOverrides.SheetQueryTimeout != "" {
			baseCfg.SheetQueryTimeout = cfgOverrides.SheetQueryTimeout
		}
		if cfgOverrides.HomeRedirect != "" {
			baseCfg.HomeRedirect = cfgOverrides.HomeRedirect
		}
		
		// Check if RateLimitEnabled is explicitly set in overrides
		// This requires a bit of a workaround if cfgOverrides is a partially filled struct,
		// as a zero-value 'false' for RateLimitEnabled is ambiguous.
		// For this refactor, we'll assume if cfgOverrides is passed, its RateLimitEnabled value is intentional.
		// A better way would be to use pointers for boolean/numeric fields in cfgOverrides if more granularity is needed.
		// For simplicity now: if cfgOverrides is not nil, we check its RateLimitEnabled field.
		// This means if you pass cfgOverrides, you must specify RateLimitEnabled if you want it to be different from baseCfg's default.
		// Or, more simply, we can say that if cfgOverrides is present, its RateLimitEnabled field dictates the value.
		isRateLimitConfigPresentInOverrides = true // Assume if cfgOverrides is not nil, rate limit config is considered
		baseCfg.RateLimitEnabled = cfgOverrides.RateLimitEnabled

		if baseCfg.RateLimitEnabled {
			// Only use RPS/Burst from overrides if they are positive, otherwise use baseCfg defaults
			if cfgOverrides.RateLimitRPS > 0 {
				baseCfg.RateLimitRPS = cfgOverrides.RateLimitRPS
			}
			if cfgOverrides.RateLimitBurst > 0 {
				baseCfg.RateLimitBurst = cfgOverrides.RateLimitBurst
			}
		}
		// Add other overrides as needed, e.g., GoogleSheetID, SheetName for specific tests
	}
    // If cfgOverrides was nil, isRateLimitConfigPresentInOverrides remains false,
    // so baseCfg.RateLimitEnabled (defaulting to false) is used.

	// Parse durations from baseCfg
	cacheTTL, err := time.ParseDuration(baseCfg.CacheTTL)
	if err != nil {
		t.Fatalf("Failed to parse CacheTTL ('%s') for test server: %v", baseCfg.CacheTTL, err)
	}
	sheetQueryTimeout, err := time.ParseDuration(baseCfg.SheetQueryTimeout)
	if err != nil {
		t.Fatalf("Failed to parse SheetQueryTimeout ('%s') for test server: %v", baseCfg.SheetQueryTimeout, err)
	}

	// Initialize cachedURLMap with the mock provider
	testCachedURLMap := &cachedURLMap{
		ttl:               cacheTTL,
		sheetQueryTimeout: sheetQueryTimeout,
		sheet:             provider,
	}

	// Create server instance
	testAppServer := &server{
		db:           testCachedURLMap,
		homeRedirect: baseCfg.HomeRedirect,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", testAppServer.handler)
	// We can add favicon/robots if needed for specific tests, but usually not for core logic.

	// Create a local limiter for this specific test server instance
	var testSpecificLimiter *rate.Limiter
	if baseCfg.RateLimitEnabled {
		testSpecificLimiter = rate.NewLimiter(rate.Limit(baseCfg.RateLimitRPS), baseCfg.RateLimitBurst)
	}
	// The global 'limiter' variable is not modified by this test helper.

	// Create rate limit middleware instance using the factory with the local limiter
	rateLimitMwInstance := newRateLimitMiddleware(testSpecificLimiter)

	finalHandler := rateLimitMwInstance(securityHeadersMiddleware(otelMiddleware(mux)))
	return httptest.NewServer(finalHandler)
}

// newTestServer is a simplified wrapper around newTestServerWithConfig for common test cases.
// It defaults to rate-limiting disabled and allows easy overriding of HomeRedirect.
func newTestServer(t *testing.T, provider URLProvider, homeRedirectURL ...string) *httptest.Server {
	t.Helper()
	var overrides Config // Use a concrete Config struct for overrides

	// Default to RateLimitEnabled = false for this simple helper
	overrides.RateLimitEnabled = false

	if len(homeRedirectURL) > 0 && homeRedirectURL[0] != "" {
		overrides.HomeRedirect = homeRedirectURL[0]
	}
	
	// If a test needs specific rate limiting or other complex config, it should use newTestServerWithConfig directly
	// and set RateLimitEnabled = true in its cfgOverrides.
	return newTestServerWithConfig(t, provider, &overrides)
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
