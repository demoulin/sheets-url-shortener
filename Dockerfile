FROM docker.io/golang:1.26.3 AS compiler
WORKDIR /src/app
COPY go.mod go.sum ./
COPY main.go sheetsprovider.go ./
COPY static/ ./static/
RUN go mod download
RUN CGO_ENABLED=0 go build -o ./a.out .

FROM docker.io/alpine:3.23.4
RUN apk add --no-cache ca-certificates tzdata && \
  update-ca-certificates
COPY --from=compiler /src/app/a.out /server
USER nobody
ENTRYPOINT ["/server"]
