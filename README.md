# ramen-mcp-bridge

A stdio MCP server that forwards every JSON-RPC message to a [Ramen](https://github.com/bkraad47/ramen)
worker's `ramen.v1.Mcp/Call` over gRPC. It exists for MCP clients that can only start a local process
(stdio) — Claude Desktop, Cursor, and the reference `mcp` SDK all speak Streamable HTTP directly against
Ramen's edge and don't need it; see [Get started](https://bkraad47.github.io/ramen/get-started/)
for that path instead.

## Install

```sh
pip install ramen-mcp-bridge        # → ramen-mcp-bridge on PATH
# or: uv tool install ramen-mcp-bridge
```

## Use

Against a **local** worker (plaintext, no TLS):
```sh
RAMEN_MCP_KEY="$KEY" ramen-mcp-bridge --target localhost:8080 --insecure --group demo --zone local
```

Against a **cloud** deployment (GCP GKE or AWS EKS) fronted by a load balancer with a publicly-trusted
certificate (the default since Ramen v0.5.5 — see [deploy/README.md](https://github.com/bkraad47/ramen/blob/main/deploy/README.md)):
```sh
ramen-mcp-bridge --target <public-hostname>:443 --tls --key rmk_… --group demo --zone a
```
`--tls` alone verifies against your system's CA trust store — nothing to download, no `kubectl` command.
An older cluster still using the self-signed fallback needs its CA pulled once (`kubectl -n ramen-system
get secret ramen-console-tls -o jsonpath='{.data.tls\.crt}' | base64 -d > ramen-lb.pem`) and a `--ca
ramen-lb.pem` flag.

## Sign in as yourself (0.2.0)

Instead of a shared `rmk_` group key, the bridge can sign **you** in through the console — with your password, a
magic link, or the identity provider the console is configured with (Microsoft Entra ID, Google Workspace, any OIDC
issuer). A super admin registers an OAuth client on the console's Config page with the redirect URI
`http://127.0.0.1/callback` (any port) and gives you its client id; your account needs a role in the group (an
*MCP User* is enough):

```sh
ramen-mcp-bridge --target <public-hostname>:443 --tls --oauth https://<public-hostname> --client-id <client id> \
  --group demo --zone a
```

The first run opens your browser on the console's sign-in page (`--no-browser` prints the URL instead); after you
approve, the refresh token is kept in `~/.config/ramen-mcp-bridge/tokens-*.json` (mode 0600, `--token-file` to move
it) and later runs need no browser until it expires or is revoked. Access tokens are scoped to `mcp:<group>:<zone>`,
refreshed before they expire and after the worker answers UNAUTHENTICATED; every call the worker logs then names
your account (`user:<id>`), not a key. Environment: `RAMEN_BRIDGE_OAUTH`, `RAMEN_BRIDGE_CLIENT_ID`,
`RAMEN_BRIDGE_TOKEN_FILE`.

Point an MCP client at it directly:
```json
{"mcpServers": {"ramen-stdio": {"command": "ramen-mcp-bridge",
  "env": {"RAMEN_BRIDGE_TARGET": "<public-hostname>:443", "RAMEN_BRIDGE_TLS": "1",
          "RAMEN_MCP_KEY": "rmk_…", "RAMEN_BRIDGE_GROUP": "demo", "RAMEN_BRIDGE_ZONE": "a"}}}}
```

Every flag has a `RAMEN_BRIDGE_*` environment variable equivalent (`--target` → `RAMEN_BRIDGE_TARGET`,
`--tls` → `RAMEN_BRIDGE_TLS=1`, `--group` → `RAMEN_BRIDGE_GROUP`, `--zone` → `RAMEN_BRIDGE_ZONE`) so the key
never has to sit in a client's config file — `RAMEN_MCP_KEY` (or `RAMEN_BRIDGE_KEY`) is enough.
`--health [SERVICE]` checks `grpc.health.v1` and exits 0 when SERVING, for a liveness probe.

## Develop

```sh
uv sync --group dev
uv run pytest
./gen_proto.sh   # regenerate src/ramen_proto from proto/ramen/v1/mcp.proto after a proto change
```

License: BSD-3-Clause, same as [ramen](https://github.com/bkraad47/ramen).
