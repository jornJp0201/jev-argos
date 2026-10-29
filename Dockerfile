# jev-argos コアサーバー (gRPC Signal Receiver + 管理 HTTP API)
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY gen ./gen
COPY pkg ./pkg
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/jev-argos-server ./cmd/jev-argos-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/jev-argos-server /jev-argos-server
# コンテナ内では全インターフェースで待ち受ける (公開範囲はポート公開側で制御する)
ENV JEV_ARGOS_GRPC_ADDR=:50051 \
    JEV_ARGOS_API_ADDR=:8080
EXPOSE 50051 8080
USER nonroot:nonroot
# distroless にはシェルも curl も無いため、バイナリ自身でヘルスチェックする
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 CMD ["/jev-argos-server", "-healthcheck"]
ENTRYPOINT ["/jev-argos-server"]
