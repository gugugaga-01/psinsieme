#!/bin/bash
# Generate Python protobuf/gRPC stubs from proto files.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROTO_DIR="$SCRIPT_DIR/../../proto"
OUT_DIR="$SCRIPT_DIR/mpsi_client/generated"

mkdir -p "$OUT_DIR"

python3 -m grpc_tools.protoc \
    --proto_path="$PROTO_DIR" \
    --python_out="$OUT_DIR" \
    --grpc_python_out="$OUT_DIR" \
    "$PROTO_DIR/common.proto" \
    "$PROTO_DIR/psi_service.proto"

# Fix imports to use relative imports within the package
for f in "$OUT_DIR"/*_pb2*.py; do
    sed -i 's/^import \([a-z_]*_pb2\)/from . import \1/' "$f"
done

# Create __init__.py
touch "$OUT_DIR/__init__.py"

echo "Generated Python stubs in $OUT_DIR"
