# p2p container image. Native cross-compile: the build stage runs on the
# builder's architecture (BUILDPLATFORM) and produces a TARGETOS/TARGETARCH
# binary, so CI does not pay for QEMU-emulated Go compilation -- only the
# lightweight alpine runtime stage runs under QEMU.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine3.23 AS build
# No defaults: BuildKit populates these from the target platform (both for
# `buildx --platform` and plain `docker build`). A default SHADOWS that value --
# `ARG TARGETARCH=amd64` silently put an amd64 binary inside the arm64 image,
# which then failed at startup with "exec format error".
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -ldflags="-s -w" -o /p2p .

# Runtime environment. Non-root (uid 10001) by default.
#
# Device link (--link) tun/tap: iproute2 (`ip tuntap/addr/link`) creates and
# configures the device, iptables/nftables set NAT/forwarding rules. Creating a
# tun/tap, changing rules or addresses all require CAP_NET_ADMIN, and /dev/net/tun
# must be visible in the container, so run as root or with capabilities for the
# device link, e.g.:
#   docker run --cap-add=NET_ADMIN --device /dev/net/tun --user 0 ...
# (stub/DERP modes need none of this and keep the non-root default.)
FROM alpine:3.23
RUN apk add --no-cache ca-certificates iproute2 iptables nftables \
 && adduser -D -u 10001 p2p
COPY --from=build /p2p /usr/local/bin/p2p
USER p2p
# gRPC control plane (stub mode). DERP mode is outbound, no port to expose.
EXPOSE 8003
ENTRYPOINT ["/usr/local/bin/p2p"]
