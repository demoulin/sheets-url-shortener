FROM golang:1.19 AS compiler
WORKDIR /src/app
COPY go.mod go.sum ./
RUN go mod download
RUN go vet -v
# RUN go test -v
COPY . ./
RUN CGO_ENABLED=0 go build -o ./a.out .

FROM alpine:latest as tailscale
WORKDIR /ts/app
# COPY . ./
ENV TSFILE=tailscale_1.30.0_amd64.tgz
RUN wget https://pkgs.tailscale.com/stable/${TSFILE} && \
  tar xzf ${TSFILE} --strip-components=1
# COPY . ./

FROM gcr.io/distroless/static
COPY --from=compiler /src/app/a.out /server
COPY --from=tailscale /ts/app/tailscaled /server/tailscaled
COPY --from=tailscale /ts/app/tailscale /server/tailscale
RUN mkdir -p /var/run/tailscale /var/cache/tailscale /var/lib/tailscale
# ENTRYPOINT ["/server"]
CMD ["/server/start.sh"]
