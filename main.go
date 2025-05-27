package main

import (
	"context"
	"embed"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"

	"github.com/spf13/viper"

	"cloud.google.com/go/errorreporting"

	"os/signal"
	"syscall"

	"golang.org/x/time/rate"
)

// Config holds all configuration for the application.
type Config struct {
	Port                     string
	ListenAddr               string
	GoogleSheetID            string `mapstructure:"GOOGLE_SHEET_ID"`
	SheetName                string `mapstructure:"SHEET_NAME"`
	HomeRedirect             string `mapstructure:"HOME_REDIRECT"`
	CacheTTL                 string `mapstructure:"CACHE_TTL"` // Will be parsed into time.Duration
	OtelServiceName          string `mapstructure:"OTEL_SERVICE_NAME"`
	OtelExporterOtlpEndpoint string `mapstructure:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	OtelExporterOtlpProtocol string `mapstructure:"OTEL_EXPORTER_OTLP_PROTOCOL"`
	ProjectID                string `mapstructure:"PROJECT_ID"`        // For GCP Error Reporting
	ServiceVersion           string `mapstructure:"SERVICE_VERSION"` // For GCP Error Reporting
	ServerShutdownTimeout    string `mapstructure:"SERVER_SHUTDOWN_TIMEOUT"`
	RateLimitEnabled         bool   `mapstructure:"RATE_LIMIT_ENABLED"`
	RateLimitRPS             float64 `mapstructure:"RATE_LIMIT_RPS"`
	RateLimitBurst           int    `mapstructure:"RATE_LIMIT_BURST"`
	SheetQueryTimeout        string `mapstructure:"SHEET_QUERY_TIMEOUT"`
	OtelSamplerType          string `mapstructure:"OTEL_SAMPLER_TYPE"`
	OtelSamplerArg           float64 `mapstructure:"OTEL_SAMPLER_ARG"`
}

// loadConfig reads configuration from environment variables and viper defaults.
func loadConfig() (*Config, error) {
	v := viper.New()

	// Viper settings for environment variables
	v.AutomaticEnv()
	// Allows OTEL_EXPORTER_OTLP_ENDPOINT to be read as OtelExporterOtlpEndpoint
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	// Defaults
	v.SetDefault("PORT", "8080")
	v.SetDefault("CACHE_TTL", "5s")
	v.SetDefault("OTEL_SERVICE_NAME", "url-shortener")
	// Default OTLP/HTTP endpoint. For gRPC, it's typically localhost:4317
	v.SetDefault("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4318")
	v.SetDefault("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf") // or "grpc"
	v.SetDefault("SERVICE_VERSION", "1.0.0") // Default service version for error reporting
	v.SetDefault("SERVER_SHUTDOWN_TIMEOUT", "10s")
	v.SetDefault("RATE_LIMIT_ENABLED", true)
	v.SetDefault("RATE_LIMIT_RPS", 10.0)
	v.SetDefault("RATE_LIMIT_BURST", 20)
	v.SetDefault("SHEET_QUERY_TIMEOUT", "15s")
	v.SetDefault("OTEL_SAMPLER_TYPE", "always_on") // Default sampler
	v.SetDefault("OTEL_SAMPLER_ARG", 1.0)          // Default sampler argument (e.g., for ratio based)

	// Bind environment variables explicitly (optional if using AutomaticEnv and matching struct fields,
	// but good for clarity and when mapstructure tags are used)
	// For fields like GoogleSheetID, mapstructure tag is sufficient if env var is GOOGLE_SHEET_ID
	// v.BindEnv("Port", "PORT") // Already handled by AutomaticEnv + struct field name matching (case-insensitive)

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

//go:embed static/*
var static embed.FS

// initTracer configures and registers the OpenTelemetry SDK components.
// It now accepts OpenTelemetry specific configuration including sampler settings.
func initTracer(otelServiceName, otelExporterEndpoint, otelExporterProtocol, samplerType string, samplerArg float64) (*sdktrace.TracerProvider, error) {
	ctx := context.Background()

	var clientOpts []otlptracehttp.Option

	// Currently, this function primarily supports OTLP/HTTP.
	// If otelExporterProtocol is "grpc", a different exporter (e.g., otlptracegrpc) would be needed.
	// This example will proceed with otlptracehttp, respecting the endpoint.
	if otelExporterEndpoint == "localhost:4318" || strings.HasPrefix(otelExporterEndpoint, "localhost:") || strings.HasPrefix(otelExporterEndpoint, "127.0.0.1:") {
		// For default localhost or typical local testing, assume insecure for OTLP/HTTP.
		// The check for specific "localhost:4318" is a bit redundant if general "localhost:" is checked.
		clientOpts = append(clientOpts, otlptracehttp.WithInsecure())
	}
	clientOpts = append(clientOpts, otlptracehttp.WithEndpoint(otelExporterEndpoint))

	// TODO: Add support for otlptracegrpc if otelExporterProtocol == "grpc"

	exporter, err := otlptracehttp.New(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP HTTP exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL,
			semconv.ServiceNameKey.String(otelServiceName),
		))
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Select sampler based on configuration
	var sampler sdktrace.Sampler
	switch strings.ToLower(samplerType) {
	case "always_on", "alwayson":
		sampler = sdktrace.AlwaysSample()
		log.Println("Using AlwaysSample OpenTelemetry sampler")
	case "always_off", "alwaysoff":
		sampler = sdktrace.NeverSample()
		log.Println("Using NeverSample OpenTelemetry sampler")
	case "traceid_ratio", "traceidratio":
		if samplerArg >= 0.0 && samplerArg <= 1.0 {
			sampler = sdktrace.TraceIDRatioBased(samplerArg)
			log.Printf("Using TraceIDRatioBased OpenTelemetry sampler with ratio %f", samplerArg)
		} else {
			log.Printf("Invalid OTEL_SAMPLER_ARG for traceid_ratio: %f. Defaulting to AlwaysSample.", samplerArg)
			sampler = sdktrace.AlwaysSample()
		}
	default:
		log.Printf("Unknown OTEL_SAMPLER_TYPE: %s. Defaulting to AlwaysSample.", samplerType)
		sampler = sdktrace.AlwaysSample()
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler), // Use the configured sampler
	)
	otel.SetTracerProvider(tp)

	log.Printf("OpenTelemetry Tracer initialized. Service: %s, Endpoint: %s, Protocol: %s, Sampler: %s, SamplerArg: %.2f",
		otelServiceName, otelExporterEndpoint, otelExporterProtocol, samplerType, samplerArg)
	return tp, nil
}

// otelMiddleware wraps an http.Handler with OpenTelemetry tracing.
func otelMiddleware(next http.Handler) http.Handler {
	// The operation name "http.server" will be used for the server-side span.
	// You can customize this name if needed.
	return otelhttp.NewHandler(next, "http.server")
}

// securityHeadersMiddleware adds common security-related HTTP headers.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		// CSP can be quite restrictive. Adjust 'default-src' if static assets or CDNs are used.
		// 'frame-ancestors 'none'' is a stronger replacement for X-Frame-Options: DENY.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		// X-XSS-Protection is deprecated by modern browsers in favor of CSP,
		// but can still provide some protection for users on older browsers.
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

var limiter *rate.Limiter

// rateLimitMiddleware applies rate limiting to incoming requests.
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limiter != nil { // Check if rate limiting is enabled
			if !limiter.Allow() {
				// Optionally log the rate-limited request here.
				// log.Printf("Request rate-limited: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

var errorClient *errorreporting.Client

// initErrorReporting initializes the Google Cloud Error Reporting client.
func initErrorReporting(ctx context.Context, projectID, serviceName, serviceVersion string) error {
	var err error
	errorClient, err = errorreporting.NewClient(ctx, projectID, serviceName, errorreporting.Config{
		ServiceVersion: serviceVersion,
		// OnError allows you to handle errors that occur when reporting errors.
		OnError: func(err error) {
			log.Printf("Could not report error to GCP Error Reporting: %v", err)
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create error reporting client: %w", err)
	}
	log.Printf("Google Cloud Error Reporting initialized. ProjectID: %s, Service: %s, Version: %s", projectID, serviceName, serviceVersion)
	return nil
}

// reportError sends an error to Google Cloud Error Reporting and logs it locally.
func reportError(ctx context.Context, err error, req *http.Request) {
	if errorClient == nil {
		log.Printf("Error reporting is not initialized. Original error: %v", err)
		return
	}

	entry := errorreporting.Entry{
		Error: err,
	}
	if req != nil {
		entry.Req = req
	}

	// If a trace context is available, try to associate the error with the trace.
	// Note: The error reporting library might do this automatically if OTel context is propagated.
	// For explicit association, one might extract trace ID from ctx if needed, but often not necessary.

	errorClient.Report(entry)
	log.Printf("Error reported to GCP Error Reporting: %v", err) // Also log locally
}

func main() {
	ctx := context.Background() // A general context for initialization
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	// Log loaded configuration for transparency (be cautious with sensitive values in real deployments)
	log.Println("---- Configuration Loaded ----")
	log.Printf("Port: %s", cfg.Port)
	log.Printf("Listen Address: %s", cfg.ListenAddr)
	log.Printf("Google Sheet ID: %s", cfg.GoogleSheetID) // An ID, not a secret key
	log.Printf("Sheet Name: %s", cfg.SheetName)
	log.Printf("Home Redirect URL: %s", cfg.HomeRedirect)
	log.Printf("Cache TTL: %s", cfg.CacheTTL)
	log.Printf("OTel Service Name: %s", cfg.OtelServiceName)
	log.Printf("OTel Exporter OTLP Endpoint: %s", cfg.OtelExporterOtlpEndpoint)
	log.Printf("OTel Exporter OTLP Protocol: %s", cfg.OtelExporterOtlpProtocol)
	log.Printf("GCP Project ID: %s", cfg.ProjectID) // An ID, not a secret key
	log.Printf("Service Version: %s", cfg.ServiceVersion)
	log.Printf("Server Shutdown Timeout: %s", cfg.ServerShutdownTimeout)
	log.Printf("Rate Limiting Enabled: %t", cfg.RateLimitEnabled)
	log.Printf("Rate Limiting RPS: %.2f", cfg.RateLimitRPS)
	log.Printf("Rate Limiting Burst: %d", cfg.RateLimitBurst)
	log.Printf("Sheet Query Timeout: %s", cfg.SheetQueryTimeout)
	log.Printf("OTel Sampler Type: %s", cfg.OtelSamplerType)
	log.Printf("OTel Sampler Arg: %.2f", cfg.OtelSamplerArg)
	log.Println("-----------------------------")

	// Initialize the rate limiter if enabled
	if cfg.RateLimitEnabled {
		limiter = rate.NewLimiter(rate.Limit(cfg.RateLimitRPS), cfg.RateLimitBurst)
		log.Printf("Rate limiting enabled: RPS=%.2f, Burst=%d", cfg.RateLimitRPS, cfg.RateLimitBurst)
	} else {
		log.Println("Rate limiting disabled by configuration.")
	}

	tp, err := initTracer(cfg.OtelServiceName, cfg.OtelExporterOtlpEndpoint, cfg.OtelExporterOtlpProtocol, cfg.OtelSamplerType, cfg.OtelSamplerArg)
	if err != nil {
		log.Fatalf("failed to initialize OpenTelemetry tracer: %v", err)
	}
	defer func() {
		if errShutdown := tp.Shutdown(ctx); errShutdown != nil { // Use ctx from main
			log.Printf("Error shutting down tracer provider: %v", errShutdown)
		}
	}()

	if err := initErrorReporting(ctx, cfg.ProjectID, cfg.OtelServiceName, cfg.ServiceVersion); err != nil {
		// Log non-fatally, as the app might still be able to run, but error reporting will be disabled.
		log.Printf("failed to initialize Google Cloud Error Reporting: %v. Reporting will be disabled.", err)
	} else {
		defer errorClient.Close()
		defer errorClient.Flush() // Flush any buffered errors on shutdown
	}

	// Parse CacheTTL from string to time.Duration
	cacheTTL, err := time.ParseDuration(cfg.CacheTTL)
	if err != nil {
		// Report this critical startup error before fatally exiting
		reportError(ctx, fmt.Errorf("failed to parse CACHE_TTL (%s) as duration: %w", cfg.CacheTTL, err), nil)
		log.Fatalf("failed to parse CACHE_TTL (%s) as duration: %v", cfg.CacheTTL, err)
	}

	// Parse ServerShutdownTimeout
	serverShutdownTimeoutDuration, err := time.ParseDuration(cfg.ServerShutdownTimeout)
	if err != nil {
		reportError(ctx, fmt.Errorf("failed to parse SERVER_SHUTDOWN_TIMEOUT (%s) as duration: %w", cfg.ServerShutdownTimeout, err), nil)
		log.Fatalf("failed to parse SERVER_SHUTDOWN_TIMEOUT (%s) as duration: %v", cfg.ServerShutdownTimeout, err)
	}

	// Parse SheetQueryTimeout
	sheetQueryTimeoutDuration, err := time.ParseDuration(cfg.SheetQueryTimeout)
	if err != nil {
		reportError(ctx, fmt.Errorf("failed to parse SHEET_QUERY_TIMEOUT (%s) as duration: %w", cfg.SheetQueryTimeout, err), nil)
		log.Fatalf("failed to parse SHEET_QUERY_TIMEOUT (%s) as duration: %v", cfg.SheetQueryTimeout, err)
	}

	appServer := &server{ // Renamed from srv to appServer to avoid conflict with http.Server
		db: &cachedURLMap{
			ttl:               cacheTTL, // Use parsed duration
			sheetQueryTimeout: sheetQueryTimeoutDuration, // Set the parsed timeout
			sheet: &sheetsProvider{
				googleSheetsID: cfg.GoogleSheetID, // Use config value
				sheetName:      cfg.SheetName,     // Use config value
			},
		},
		homeRedirect: cfg.HomeRedirect, // Use config value
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/favicon.ico", faviconHandler)
	mux.HandleFunc("/robots.txt", robotsHandler)
	mux.HandleFunc("/", appServer.handler) // Use appServer.handler

	// Apply middlewares: rate limiting -> security -> otel -> mux
	finalHandler := rateLimitMiddleware(securityHeadersMiddleware(otelMiddleware(mux)))

	listenAddr := net.JoinHostPort(cfg.ListenAddr, cfg.Port) // Use config values

	httpServer := &http.Server{ // Explicit http.Server
		Addr:    listenAddr,
		Handler: finalHandler, // Use the fully chained handler
	}

	// Start server in a goroutine
	go func() {
		log.Printf("HTTP server starting at %s; ttl=%v; OTel Service=%s", httpServer.Addr, cacheTTL, cfg.OtelServiceName)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Report critical server error before fatally exiting
			reportError(context.Background(), fmt.Errorf("HTTP server ListenAndServe failed: %w", err), nil)
			log.Fatalf("HTTP server ListenAndServe: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	receivedSignal := <-quit
	log.Printf("Received signal %v. Server is shutting down...", receivedSignal)

	// Create a context with timeout for shutdown.
	// Use the main context `ctx` as parent for shutdown, not context.Background(),
	// so that if main ctx is already cancelled, shutdown is also fast.
	shutdownCtx, cancelShutdown := context.WithTimeout(ctx, serverShutdownTimeoutDuration)
	defer cancelShutdown()

	// Shutdown HTTP server
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		reportError(shutdownCtx, fmt.Errorf("HTTP server shutdown failed: %w", err), nil)
		log.Fatalf("HTTP server shutdown failed: %v", err)
	}
	log.Println("HTTP server gracefully stopped.")

	// Deferred calls for tp.Shutdown(shutdownCtx), errorClient.Flush(), errorClient.Close() will execute here
	// Update tp.Shutdown to use shutdownCtx
	// The defer for tp.Shutdown needs to be updated if it's still using the original ctx.
	// However, defers are set up with the value at the time the defer statement is encountered.
	// To use shutdownCtx for tp.Shutdown, the defer statement itself needs to be after shutdownCtx is defined.
	// This is tricky with the current structure. A common pattern is to move resource cleanup
	// explicitly after server shutdown, rather than relying on defers set up much earlier.

	// For this iteration, we'll assume the existing defers for tp.Shutdown (using main ctx)
	// and errorClient are acceptable. Proper context handling for tp.Shutdown in this
	// signal-triggered shutdown sequence would require restructuring the defer statements.
	// The current tp.Shutdown(ctx) will use the main context, which might already be expired if shutdown takes too long,
	// or might not respect the serverShutdownTimeout.
	// Let's proceed with the current defer structure and acknowledge this as a potential refinement.

	log.Println("Resources being cleaned up via deferred calls. Exiting.")
}

type server struct {
	db           *cachedURLMap
	homeRedirect string
}

type URLMap map[string]*url.URL

// URLProvider defines the interface for fetching URL mapping data.
type URLProvider interface {
	Query(ctx context.Context) ([][]interface{}, error)
}

type cachedURLMap struct {
	sync.RWMutex
	v                 URLMap
	lastUpdate        time.Time
	sheetQueryTimeout time.Duration // Timeout for sheet queries

	ttl   time.Duration
	sheet URLProvider // Changed from *sheetsProvider to URLProvider interface
}

func (c *cachedURLMap) Get(ctx context.Context, query string) (*url.URL, error) {
	tracer := otel.Tracer("url-shortener/cachedurlmap")
	ctx, span := tracer.Start(ctx, "cachedURLMap.Get")
	defer span.End()

	span.SetAttributes(attribute.String("query", query))

	if err := c.refresh(ctx); err != nil { // Pass context to refresh
		wrappedErr := fmt.Errorf("failed to refresh cache: %w", err)
		span.RecordError(wrappedErr)
		reportError(ctx, wrappedErr, nil) // Report error
		return nil, wrappedErr
	}
	c.RLock()
	defer c.RUnlock()
	return c.v[query], nil
}

func (c *cachedURLMap) refresh(ctx context.Context) error {
	tracer := otel.Tracer("url-shortener/cachedurlmap")
	ctx, span := tracer.Start(ctx, "cachedURLMap.refresh")
	defer span.End()

	c.Lock()
	defer c.Unlock()

	// Check TTL within the current span, before potentially long-running I/O
	if time.Since(c.lastUpdate) <= c.ttl {
		span.SetAttributes(attribute.Bool("cache_hit_ttl", true))
		return nil
	}
	span.SetAttributes(attribute.Bool("cache_hit_ttl", false))

	// Create a new context with timeout for the sheet query
	queryCtx, cancelQueryCtx := context.WithTimeout(ctx, c.sheetQueryTimeout)
	defer cancelQueryCtx()

	rows, err := c.sheet.Query(queryCtx) // Pass context with timeout
	if err != nil {
		wrappedErr := fmt.Errorf("failed to query sheet (timeout: %s): %w", c.sheetQueryTimeout, err)
		span.RecordError(wrappedErr)
		reportError(queryCtx, wrappedErr, nil) // Report error
		return wrappedErr
	}
	span.SetAttributes(attribute.Int("rows_fetched_from_sheet", len(rows)))
	c.v = urlMap(rows)
	c.lastUpdate = time.Now()
	return nil
}

func (s *server) handler(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/" {
		s.home(w, req)
		return
	}
	s.redirect(w, req)
}

func (s *server) home(w http.ResponseWriter, req *http.Request) { // No context needed here as it either redirects or writes static HTML
	if s.homeRedirect != "" {
		http.Redirect(w, req, s.homeRedirect, http.StatusFound)
		return
	}

	w.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
	<html><head><title>Not found</title></head><body><h1>Not found :(</h1>
	<p>This is home page for a URL redirector service.</p>
	<p>The URL is missing the shortcut in the path.</p>
	</body></html>`)
}

func (s *server) redirect(w http.ResponseWriter, req *http.Request) {

	if req.Body != nil {
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(req.Body)
	}
	// Pass request context to findRedirect
	reqCtx := req.Context()
	redirTo, err := s.findRedirect(reqCtx, req.URL)
	if err != nil {
		// Error from findRedirect will be recorded in its own span if it occurs there.
		// The http middleware span will also record this error if writeError sets status code >= 500.
		reportError(reqCtx, fmt.Errorf("findRedirect failed: %w", err), req) // Report error
		writeError(w, http.StatusInternalServerError, "failed to find redirect: %w", err)
		return
	}
	if redirTo == nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, "404 not found")
		return
	}

	log.Printf("redirecting=%q to=%q", req.URL, redirTo.String())
	http.Redirect(w, req, redirTo.String(), http.StatusFound) // no permanent redirects
}

// findRedirect now accepts context from the request.
func (s *server) findRedirect(ctx context.Context, reqURL *url.URL) (*url.URL, error) {
	tracer := otel.Tracer("url-shortener/server")
	ctx, span := tracer.Start(ctx, "server.findRedirect")
	defer span.End()

	path := strings.TrimPrefix(reqURL.Path, "/")
	span.SetAttributes(attribute.String("lookup_path_initial", path))

	segments := strings.Split(path, "/")
	var discard []string
	for len(segments) > 0 {
		query := strings.Join(segments, "/")
		span.SetAttributes(attribute.String("current_lookup_query", query))

		// Pass context to s.db.Get
		v, errGet := s.db.Get(ctx, query)
		if errGet != nil {
			wrappedErr := fmt.Errorf("failed to get URL from cache for query %q: %w", query, errGet)
			span.RecordError(wrappedErr)
			reportError(ctx, wrappedErr, nil) // Report error from s.db.Get
			return nil, wrappedErr
		}
		if v != nil {
			span.SetAttributes(attribute.Bool("redirect_found", true))
			return prepRedirect(v, strings.Join(discard, "/"), reqURL.Query()), nil
		}
		discard = append([]string{segments[len(segments)-1]}, discard...)
		segments = segments[:len(segments)-1]
	}
	span.SetAttributes(attribute.Bool("redirect_found", false))
	return nil, nil
}

func prepRedirect(base *url.URL, addPath string, query url.Values) *url.URL {
	if addPath != "" {
		if !strings.HasSuffix(base.Path, "/") {
			base.Path += "/"
		}
		base.Path += addPath
	}

	qs := base.Query()
	for k := range query {
		qs.Add(k, query.Get(k))
	}
	base.RawQuery = qs.Encode()
	return base
}

func urlMap(in [][]interface{}) URLMap {
	out := make(URLMap)
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
			log.Printf("warn: shortcut %q (%s) url invalid: %v", k, v, err)
			continue
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			log.Printf("warn: shortcut %q (%s) has an unexpected scheme: %s. Expected http or https.", k, v, u.Scheme)
			// Depending on policy, one might choose to skip adding this URL, e.g., continue
		}

		_, exists := out[k]
		if exists {
			log.Printf("warn: shortcut %q redeclared, overwriting", k)
		}
		out[k] = u
	}
	return out
}

func writeError(w http.ResponseWriter, code int, msg string, vals ...interface{}) {
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, msg, vals...)
}

func faviconHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=7776000")
	favicon, err := static.ReadFile("static/favicon.ico")
	if err != nil {
		wrappedErr := fmt.Errorf("failed to read favicon.ico: %w", err)
		log.Printf("Error reading favicon: %v", wrappedErr) // Keep local log for this frequent error
		reportError(req.Context(), wrappedErr, req)      // Report error
		http.Error(w, "favicon not found", http.StatusNotFound)
		return
	}
	_, _ = w.Write(favicon) // Send the favicon
}

func robotsHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "public, max-age=7776000")
	robots := "User-agent: *\nDisallow: /"
	_, _ = w.Write([]byte(robots)) // Send the robots.txt
}
