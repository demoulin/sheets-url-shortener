#!/bin/sh

/tailscale/tailscaled --tun=userspace-networking --socks5-server=localhost:1055 &
/tailscale/tailscale up --authkey=${TAILSCALE_AUTHKEY} --hostname=${TAILSCALE_HOSTNAME} --ssh
echo Tailscale started
ALL_PROXY=socks5://localhost:1055/ /server