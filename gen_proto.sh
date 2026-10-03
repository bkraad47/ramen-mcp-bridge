#!/usr/bin/env bash
# Regenerate src/ramen_proto/* from proto/ramen/v1/mcp.proto. Run from the repo root: ./gen_proto.sh
# Uses grpcio-tools (bundled protoc) so no system protoc is required.
set -euo pipefail
cd "$(dirname "$0")"
OUT=src/ramen_proto
uv run --group dev python -m grpc_tools.protoc -I proto/ramen/v1 --python_out="$OUT/ramen/v1" --pyi_out="$OUT/ramen/v1" --grpc_python_out="$OUT/ramen/v1" proto/ramen/v1/mcp.proto
sed -i.bak -E 's/^import mcp_pb2 as /from . import mcp_pb2 as /' "$OUT/ramen/v1/mcp_pb2_grpc.py" && rm -f "$OUT/ramen/v1/mcp_pb2_grpc.py.bak"
cat > "$OUT/__init__.py" <<'PY'
"""Generated gRPC stubs for ramen.v1.Mcp (proto/ramen/v1/mcp.proto). Do not edit; run ./gen_proto.sh."""

from . import ramen

__all__ = ["ramen"]
PY
cat > "$OUT/ramen/__init__.py" <<'PY'
PY
cat > "$OUT/ramen/v1/__init__.py" <<'PY'
"""Generated gRPC stubs for ramen.v1.Mcp."""

from . import mcp_pb2, mcp_pb2_grpc

__all__ = ["mcp_pb2", "mcp_pb2_grpc"]
PY
echo "regenerated $OUT"
