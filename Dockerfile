# p2p 容器镜像。交叉编译原生：build 阶段跑在 builder 的架构
# (BUILDPLATFORM) 上，产出 TARGETOS/TARGETARCH 二进制，CI 不支付 QEMU 模拟的
# Go 编译，只有轻量的 alpine 运行阶段在 QEMU 下跑。
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -ldflags="-s -w" -o /p2p .

# 最小运行环境，非 root（uid 10001）。
FROM alpine:3.23
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 10001 p2p
COPY --from=build /p2p /usr/local/bin/p2p
USER p2p
# gRPC 控制平面（stub 模式）。DERP 模式是出站连接，无需暴露端口。
EXPOSE 8003
ENTRYPOINT ["/usr/local/bin/p2p"]
