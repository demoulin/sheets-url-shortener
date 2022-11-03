FROM docker.io/golang:1.19 AS compiler
WORKDIR /src/app
COPY go.mod go.sum ./
COPY main.go sheetsprovider.go ./
COPY static/ ./static/
RUN go mod download
RUN CGO_ENABLED=0 go build -o ./a.out .

FROM docker.io/alpine:latest as tailscale
WORKDIR /ts/app
RUN mkdir -p /tailscale /var/run/tailscale /var/cache/tailscale /var/lib/tailscale
ENV TSFILE=tailscale_1.32.2_amd64.tgz
RUN wget https://pkgs.tailscale.com/stable/${TSFILE} && \
  tar xzf ${TSFILE} --strip-components=1

FROM docker.io/alpine:latest
RUN apk add --no-cache ca-certificates tzdata && \
  update-ca-certificates
COPY --from=compiler /src/app/a.out /server
COPY --from=tailscale /tailscale /tailscale
COPY --from=tailscale /var/run/tailscale /var/run/tailscale
COPY --from=tailscale /var/cache/tailscale /var/cache/tailscale
COPY --from=tailscale /var/lib/tailscale /var/lib/tailscale
COPY --from=tailscale /ts/app/tailscaled /tailscale/tailscaled
COPY --from=tailscale /ts/app/tailscale /tailscale/tailscale
COPY --chown=0:0 start.sh .
RUN chmod +x start.sh
ENTRYPOINT ["/start.sh"]
