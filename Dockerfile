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
EXPOSE 50051 8080
USER nonroot:nonroot
ENTRYPOINT ["/jev-argos-server"]
CMD ["-addr", ":50051", "-api-addr", ":8080"]
