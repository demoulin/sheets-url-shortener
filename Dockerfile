FROM docker.io/golang:1.23.1 AS compiler
WORKDIR /src/app
COPY go.mod go.sum ./
COPY main.go sheetsprovider.go ./
COPY static/ ./static/
RUN go mod download
RUN CGO_ENABLED=0 go build -mod=vendor -o ./a.out .

FROM docker.io/alpine:latest
RUN apk add --no-cache ca-certificates tzdata && \
  update-ca-certificates && \
  addgroup -S appgroup && adduser -S appuser -G appgroup

# --- OpenTelemetry Configuration ---
# While the OpenTelemetry SDK defines standard environment variables for configuration,
# this application uses the following for more direct control via its Viper config:
#
# ENV OTEL_SERVICE_NAME="url-shortener" (Set via Viper: OTEL_SERVICE_NAME)
# ENV OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4318" (Set via Viper: OTEL_EXPORTER_OTLP_ENDPOINT)
# ENV OTEL_EXPORTER_OTLP_PROTOCOL="http/protobuf" (Set via Viper: OTEL_EXPORTER_OTLP_PROTOCOL)
#
# For SAMPLING, this application uses specific settings configured via Viper:
# ENV OTEL_SAMPLER_TYPE="always_on" (Options: "always_on", "always_off", "traceid_ratio")
# ENV OTEL_SAMPLER_ARG="1.0" (Argument for sampler, e.g., ratio for "traceid_ratio")
#
# The standard OTEL_TRACES_SAMPLER and OTEL_TRACES_SAMPLER_ARG environment variables
# might still be respected by some SDK auto-instrumentation layers if not overridden
# by this application's programmatic setup, but the application's Viper configuration
# for OTEL_SAMPLER_TYPE and OTEL_SAMPLER_ARG takes precedence for the main tracer provider.
# For more details on standard OTel env vars:
# https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/

COPY --chown=appuser:appgroup --from=compiler /src/app/a.out /server
USER appuser
ENTRYPOINT ["/server"]
