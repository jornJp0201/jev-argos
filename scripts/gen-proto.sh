#!/usr/bin/env bash
# proto/*.proto から Go コード (gen/v1/) を生成する。
# 必要: protoc。プラグインは go.mod の tool ディレクティブで固定したバージョンをビルドして使う。
set -euo pipefail

cd "$(dirname "$0")/.."

bin_dir="$(mktemp -d)"
trap 'rm -rf "$bin_dir"' EXIT

go build -o "$bin_dir/" \
  google.golang.org/protobuf/cmd/protoc-gen-go \
  google.golang.org/grpc/cmd/protoc-gen-go-grpc

protoc \
  --plugin=protoc-gen-go="$bin_dir/protoc-gen-go" \
  --plugin=protoc-gen-go-grpc="$bin_dir/protoc-gen-go-grpc" \
  --proto_path=proto \
  --go_out=. --go_opt=module=github.com/jornJp0201/jev-argos \
  --go-grpc_out=. --go-grpc_opt=module=github.com/jornJp0201/jev-argos \
  proto/*.proto
