#!/usr/bin/env bash

GRPC_GW_PATH=`go list -f '{{ .Dir }}' github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway`
GRPC_GW_PATH="${GRPC_GW_PATH}/../third_party/googleapis"

LS_PATH=`go list -f '{{ .Dir }}' github.com/iegomez/mosquitto-go-auth/grpc`
LS_PATH="${LS_PATH}/../.."

# generate the gRPC code
protoc -I. -I${LS_PATH} -I${GRPC_GW_PATH} --go_out=plugins=grpc:. \
    auth.proto