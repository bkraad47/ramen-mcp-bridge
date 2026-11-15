# ramen-mcp-bridge

<!-- mcp-name: io.github.bkraad47/ramen-mcp-bridge -->

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

The first run opens your browser on the console's sign-in page (`--no-browser` prints the URL instead). Access
tokens are scoped to `mcp:<group>:<zone>`, refreshed before they expire and after the worker answers
UNAUTHENTICATED; every call the worker logs then names your account (`user:<id>`), not a key.

**Where the tokens live (0.3.0).** In the bridge's memory, nowhere else, unless you ask: `--keychain` keeps them in the
operating system's secret store (macOS Keychain through `security`, a Secret Service such as GNOME Keyring through
`secret-tool`), behind its own access control; `--token-file <path>` keeps them in a plain file with mode 0600, meant
for automation only. **Thirty minutes after the last call the bridge forgets its tokens** (`--idle-timeout`, seconds,
`0` disables), and the next call needs a fresh sign-in. When a sign-in is needed while an MCP client is connected
the bridge does not block: it starts the browser flow and answers the call with error `-32001` whose message carries
the sign-in link (`data.sign_in_url` too), so an AI client can show it to you; once you approve, the next call goes
through. Environment: `RAMEN_BRIDGE_OAUTH`, `RAMEN_BRIDGE_CLIENT_ID`, `RAMEN_BRIDGE_KEYCHAIN=1`,
`RAMEN_BRIDGE_TOKEN_FILE`, `RAMEN_BRIDGE_IDLE_TIMEOUT`.

**Expiry mid-task is invisible and safe.** When the access token runs out while a client is working, the worker
answers UNAUTHENTICATED *before* the call reaches any tool code; the bridge refreshes the token and repeats that one
call. A tool is never run twice by the bridge: a call that reached the runtime either returns a result or an error,
and neither is retried. The browser only reappears when the bridge has forgotten its tokens (thirty minutes idle, or
a new bridge process without `--keychain`/`--token-file`), when the refresh token itself has expired on the console
(thirty days unused), or when it was revoked because your role, password or account changed. The MCP session the client holds is bound to your
account, not to the token, so it survives the refresh.

## Telemetry through Ramen (0.4.0)

A Ramen group can require telemetry about what its clients do (Ramen 1.0.0a, CONTRACTS §26.3): tool name, timing,
outcome and the model's reasoning — never arguments or results. The bridge is such a client:

- At sign-in the token answer's `telemetry` object (collector endpoint, headers, config `version`) is kept **encrypted
  in the bridge's memory** under a key drawn for this process; it is never written to disk (not even with
  `--keychain`/`--token-file`) and never logged.
- Every call the bridge forwards is recorded (`kind: "mcp"`, the method or `tools/call <tool>`, duration, outcome).
  The bridge adds a tool **`ramen_report(kind, name, ms, ok, reasoning)`** to the server's `tools/list`; its
  description tells the model to report its own model calls and non-MCP tool calls, with its reasoning (4 KiB kept),
  before the next Ramen call. The bridge records those locally and never forwards the call.
- Every `tools/call`, `prompts/get` and `resources/read` it forwards carries everything recorded since the last report
  under `params._meta["io.ramen/telemetry"]` (`version`, `seq`, `events`; at most 200 events / 64 KiB per report, the
  rest goes with the next one). The body is forwarded in the MCP era the host spoke; a host on 2025-06-18 stays legacy.
- `-32025 telemetry config changed` → the bridge signs in again (refresh grant, else the browser flow, reported as
  `-32001` with the link while serving) and retries that one call. `-32024 telemetry report required` when the bridge
  holds no config → it signs in again; with a static `rmk_` key it adopts the version the worker named. The consent
  checkbox on the sign-in page is unchanged: declining ends the sign-in.

## The policy bundle and your editors (0.5.0)

A Ramen group's **policy** for its clients is what the token answer carries at sign-in: the `telemetry` object above
and, when the group repo has `mcp/evals/promptfooconfig.yaml`, an `evals` object (`version`, `required`, and the
config text) — Ramen 1.0.0c, CONTRACTS §29.3. The bridge keeps and enforces it:

- **Bundle on disk.** `~/.ramen/policy/<host>/<group>-<zone>.json` (mode 0600, directories 0700) holds `telemetry`
  (without the collector headers, which stay in memory only) and `evals` (`version`, `required`), plus the target,
  group, zone and console it belongs to; the evals config text goes to
  `~/.ramen/evals/<host>/<group>/promptfooconfig.yaml`. Every sign-in and refresh rewrites both. With a static `rmk_`
  key there is no sign-in and nothing is written.
- **On every call.** Each forwarded `tools/call`, `prompts/get` and `resources/read` carries
  `params._meta["io.ramen/evals"] = {"version": "<v>"}` next to the telemetry report. A worker whose group requires
  evals answers `-32026 evals config required` / `evals config changed: sign in again` (HTTP 428) when the version is
  missing or old; the bridge then signs in again once (refresh grant, else the browser flow as `-32001` with the link)
  and retries that one call — exactly as for `-32025`. With a static key it adopts the version the worker named.
- **At start.** The bridge loads the bundle from the last sign-in and signs in. Without a bundle and with no way to
  sign in (no refresh token, `--no-browser`, and no terminal to read the URL from) it prints
  `Ramen policy missing: reconnect (sign in) — Ramen cannot be used without it` to stderr and exits **3**; a sign-in
  that fails for another reason exits 2 when a bundle exists, 3 when none does.
- **Client config files** (default on; `--no-client-config` / `RAMEN_BRIDGE_NO_CLIENT_CONFIG=1` skips them). At
  sign-in the bridge tells the editors installed on this machine about the policy, writing only where the editor's
  directory already exists, merging idempotently (your other keys survive, nothing is written twice) and marking its
  entries `"_ramen": true`:
  - **Claude Code** `~/.claude/settings.json` → a `hooks.SessionStart` entry running
    `ramen-mcp-bridge policy check --target <host> --group <g> --zone <z>`, so every session starts with a check
    against the console's current policy (non-zero exit = stale or missing, the reconnect message on stderr);
  - **Cursor** `~/.cursor/rules/ramen-<g>-<z>.mdc` (`alwaysApply: true`, a `# ramen` line) stating whether telemetry
    and evals are required, their versions, and the command to sign in again;
  - **VS Code** user `settings.json` (`~/Library/Application Support/Code/User` on macOS, `~/.config/Code/User` on
    Linux, `%APPDATA%\Code\User` on Windows) → `mcp.servers["ramen-<g>-<z>"]` = `uvx ramen-mcp-bridge@latest
    --target … --tls --oauth … --client-id … --group … --zone …`.
  A settings file the bridge cannot parse as plain JSON (comments, trailing commas) is left untouched with a warning.
  A ledger `~/.ramen/clients.json` lists every file and key written.
- **`ramen-mcp-bridge policy show|check|remove [--target --group --zone]`** (the flags may be omitted when there is one
  bundle): `show` prints the bundle (never headers); `check` fetches
  `https://<console>/.well-known/ramen-policy?group=&zone=` and exits 0 when the versions and `required` flags match,
  2 when stale or missing (with the reconnect message), 1 when the console cannot be reached; `remove` reverts every
  ledger entry for that (host, group, zone) and deletes the bundle and the evals config.

### SkillSpector scans (0.6.0)

When a group turns on [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) (Ramen 1.0.0c Phase 2, CONTRACTS
§30.3) the token answer also carries a `skillspector` object (`version`, `required`, `llm`, and the group's optional
baseline). The bridge treats it like evals:

- the bundle keeps `skillspector` (`version`, `required`, `llm`); the baseline text goes to
  `~/.ramen/skillspector/<host>/<group>/baseline.yaml`;
- every gated call carries `params._meta["io.ramen/skillspector"] = {"version": "<v>"}`; a worker answering
  `-32027 skillspector policy required` / `skillspector policy changed: sign in again` (HTTP 428) makes the bridge sign
  in again once and retry, exactly as for `-32026`; `policy check` compares `skillspector` too;
- **the local scan.** When `skillspector.required` is set, `policy check` (so the Claude Code `SessionStart` hook) and
  `policy show` run `skillspector scan <dir> --recursive --no-llm --format json` over the skill directories on this
  machine — `~/.claude/skills`, `<cwd>/.claude/skills`, `~/.codex/skills`, those that exist and hold a skill (a
  directory with exactly one skill and a bundle baseline is scanned on its own with `--baseline`). Any skill rated
  `DO_NOT_INSTALL`, a scanner that fails, or no `skillspector` on PATH → the skills are named, then
  `Ramen policy: fix or remove these skills — Ramen cannot be used with them`, exit **3** (missing binary: the hint
  `uv tool install 'git+https://github.com/NVIDIA/SkillSpector.git@v2.13.4'`). `CAUTION` is printed and passes.
  Results are cached per directory content hash in `~/.ramen/scans/<host>/` for 24 hours so hooks stay fast.
  `--no-client-scan` (`RAMEN_BRIDGE_NO_CLIENT_SCAN=1`, on the bridge and on `policy check|show`) turns the local scan
  off; the bundle and the version on every call stay. The Cursor rule and the Claude Code / VS Code entries say when
  the requirement is set.

**The honest limit.** The policy is enforced where Ramen is: the worker refuses a call that does not carry the current
versions, and the bridge, the hook and the rule files make sure a client that goes through them learns it. An LLM
that never uses the bridge or Ramen's workers cannot be forced by any of this; what it can be told is in its editor's
config, which is why the files above exist.

Point an MCP client at it directly:
```json
{"mcpServers": {"ramen-stdio": {"command": "ramen-mcp-bridge",
  "env": {"RAMEN_BRIDGE_TARGET": "<public-hostname>:443", "RAMEN_BRIDGE_TLS": "1",
          "RAMEN_MCP_KEY": "rmk_…", "RAMEN_BRIDGE_GROUP": "demo", "RAMEN_BRIDGE_ZONE": "a"}}}}
```

Every flag has a `RAMEN_BRIDGE_*` environment variable equivalent (`--target` → `RAMEN_BRIDGE_TARGET`,
`--tls` → `RAMEN_BRIDGE_TLS=1`, `--group` → `RAMEN_BRIDGE_GROUP`, `--zone` → `RAMEN_BRIDGE_ZONE`,
`--no-client-config` → `RAMEN_BRIDGE_NO_CLIENT_CONFIG=1`, `--no-client-scan` → `RAMEN_BRIDGE_NO_CLIENT_SCAN=1`) so
the key never has to sit in a client's config file — `RAMEN_MCP_KEY` (or `RAMEN_BRIDGE_KEY`) is enough.
`--health [SERVICE]` checks `grpc.health.v1` and exits 0 when SERVING, for a liveness probe.

## Develop

```sh
uv sync --group dev
uv run pytest
./gen_proto.sh   # regenerate src/ramen_proto from proto/ramen/v1/mcp.proto after a proto change
```

License: BSD-3-Clause, same as [ramen](https://github.com/bkraad47/ramen).
