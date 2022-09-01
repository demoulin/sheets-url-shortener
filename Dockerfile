FROM golang:1.19 AS compiler
WORKDIR /src/app
COPY go.mod go.sum ./
RUN go mod download
# RUN go vet -v
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
# FROM alpine:latest
# RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
COPY --from=compiler /src/app/a.out /server
RUN mkdir -p /tailscale /var/run/tailscale /var/cache/tailscale /var/lib/tailscale
COPY --from=tailscale /ts/app/tailscaled /tailscale/tailscaled
COPY --from=tailscale /ts/app/tailscale /tailscale/tailscale

ENTRYPOINT ["/server"]
# CMD ["/start.sh"]
