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

# OpenTelemetry Environment Variable Examples:
# These are typically injected by the runtime environment (e.g., Cloud Run),
# but are listed here for reference.
#
# ENV OTEL_SERVICE_NAME="url-shortener"
#
# # OTLP Exporter Configuration (choose one protocol)
# # For OTLP/HTTP (protobuf) - typically on port 4318
# ENV OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4318"
# ENV OTEL_EXPORTER_OTLP_PROTOCOL="http/protobuf"
# # ENV OTEL_EXPORTER_OTLP_HEADERS="key1=value1,key2=value2" # Optional custom headers
# # ENV OTEL_EXPORTER_OTLP_TIMEOUT="10000" # Optional timeout in milliseconds
# # ENV OTEL_EXPORTER_OTLP_COMPRESSION="gzip" # Optional compression: "gzip" or "none"
#
# # For OTLP/gRPC - typically on port 4317
# # ENV OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4317" # Note: some SDKs might expect just "localhost:4317"
# # ENV OTEL_EXPORTER_OTLP_PROTOCOL="grpc"
# # ENV OTEL_EXPORTER_OTLP_INSECURE="true" # For local testing without TLS for gRPC
#
# # Sampler Configuration (example: trace 10% of requests)
# # ENV OTEL_TRACES_SAMPLER="traceidratio"
# # ENV OTEL_TRACES_SAMPLER_ARG="0.10"
#
# # For more details on standard OpenTelemetry environment variables, see:
# # https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/sdk-environment-variables.md

COPY --chown=appuser:appgroup --from=compiler /src/app/a.out /server
USER appuser
ENTRYPOINT ["/server"]
