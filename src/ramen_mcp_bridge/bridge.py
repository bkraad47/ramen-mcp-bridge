"""ramen-mcp-bridge: a stdio MCP server that forwards every JSON-RPC message to `ramen.v1.Mcp/Call` (CONTRACTS §11).

Standard MCP clients (Claude Desktop, Cursor, the `mcp` SDK) speak newline-delimited JSON-RPC on stdin/stdout; the
bridge also accepts `Content-Length:` framing and answers in the framing it was asked in. Metadata sent per call:
`authorization: Bearer <key or token>`, `ramen-group`, `ramen-zone` (the LB routes on the last two). Notifications
produce no output. A gRPC status becomes a JSON-RPC error for requests (never for notifications). `--health [SERVICE]`
checks `grpc.health.v1` instead and exits 0 when SERVING. With `--oauth <console> --client-id <id>` (0.2.0) the bridge
signs the person in through the console instead of presenting a group key — see `oauth.py`.
"""

import argparse
import json
import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO, ClassVar

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc

from ramen_proto.ramen.v1 import mcp_pb2, mcp_pb2_grpc

from . import clients, configs, oauth, policy, rails, scan, skills
from . import telemetry as tel

CODES = {
    grpc.StatusCode.UNAUTHENTICATED: -32001,
    grpc.StatusCode.PERMISSION_DENIED: -32000,
    grpc.StatusCode.RESOURCE_EXHAUSTED: -32000,
    grpc.StatusCode.OUT_OF_RANGE: -32000,
    grpc.StatusCode.UNAVAILABLE: -32000,
    grpc.StatusCode.DEADLINE_EXCEEDED: -32000,
}


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(f"RAMEN_BRIDGE_{name}", default)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="ramen-mcp-bridge", description=__doc__.split("\n")[0])
    ap.add_argument("--target", default=_env("TARGET"), help="host:port of a worker or its LB (RAMEN_BRIDGE_TARGET)")
    # §16.4: the key may live in the environment so it never has to sit in a client's config file.
    ap.add_argument(
        "--key",
        default=_env("KEY") or os.environ.get("RAMEN_MCP_KEY"),
        help="rmk_ MCP key (RAMEN_BRIDGE_KEY, else RAMEN_MCP_KEY)",
    )
    ap.add_argument("--group", default=_env("GROUP", ""), help="ramen-group metadata (RAMEN_BRIDGE_GROUP)")
    ap.add_argument("--zone", default=_env("ZONE", ""), help="ramen-zone metadata (RAMEN_BRIDGE_ZONE)")
    # D86 (Ramen §39.3): TLS is the default. `--tls` (and RAMEN_BRIDGE_TLS) is kept so old configs still start.
    ap.add_argument("--tls", action="store_true", help="TLS — the default since 0.6.0; accepted for old configs")
    ap.add_argument(
        "--insecure",
        action="store_true",
        default=_env("INSECURE") in ("1", "true"),
        help="plaintext h2c, local development only; an error next to --tls or --ca (RAMEN_BRIDGE_INSECURE=1)",
    )
    ap.add_argument(
        "--ca", default=_env("CA"), help="PEM CA bundle that replaces the system trust store (RAMEN_BRIDGE_CA)"
    )
    ap.add_argument("--timeout", type=float, default=float(_env("TIMEOUT", "120")), help="per-call deadline, seconds")
    ap.add_argument("--health", nargs="?", const="", metavar="SERVICE", help="check grpc.health.v1 and exit")
    ap.add_argument(
        "--oauth",
        default=_env("OAUTH"),
        metavar="CONSOLE_URL",
        help="sign in as a person through this Ramen console instead of --key (RAMEN_BRIDGE_OAUTH)",
    )
    ap.add_argument(
        "--client-id",
        default=_env("CLIENT_ID"),
        help="OAuth client id a super admin registered (RAMEN_BRIDGE_CLIENT_ID)",
    )
    ap.add_argument(
        "--token-file",
        default=_env("TOKEN_FILE"),
        help="keep the tokens in this plain 0600 file (automation only; by default nothing is written to disk) "
        "(RAMEN_BRIDGE_TOKEN_FILE)",
    )
    ap.add_argument(
        "--keychain",
        action="store_true",
        default=_env("KEYCHAIN") == "1",
        help="keep the tokens in the operating system's secret store (macOS Keychain / Secret Service) "
        "(RAMEN_BRIDGE_KEYCHAIN=1)",
    )
    ap.add_argument(
        "--idle-timeout",
        type=float,
        default=float(_env("IDLE_TIMEOUT") or 1800),
        help="forget the tokens this many seconds after the last call; the next call needs a fresh sign-in "
        "(default 1800 = 30 minutes; 0 disables) (RAMEN_BRIDGE_IDLE_TIMEOUT)",
    )
    ap.add_argument("--no-browser", action="store_true", help="print the sign-in URL instead of opening a browser")
    ap.add_argument(
        "--no-client-config",
        action="store_true",
        default=_env("NO_CLIENT_CONFIG") in ("1", "true"),
        help="do not write the policy into Claude Code / Cursor / VS Code config files at sign-in "
        "(RAMEN_BRIDGE_NO_CLIENT_CONFIG=1)",
    )
    ap.add_argument(
        "--no-client-scan",
        action="store_true",
        default=_env("NO_CLIENT_SCAN") in ("1", "true"),
        help="the policy check does not run SkillSpector over the skills on this machine; the bundle and the version "
        "on every call stay (RAMEN_BRIDGE_NO_CLIENT_SCAN=1)",
    )
    ap.add_argument(
        "--no-shell-rc",
        action="store_true",
        default=_env("NO_SHELL_RC") in ("1", "true"),
        help="do not add the `. ~/.ramen/env.sh` block to ~/.zshrc / ~/.bashrc when the group requires telemetry "
        "(RAMEN_BRIDGE_NO_SHELL_RC=1)",
    )
    a = ap.parse_args(argv)
    if not a.target:
        ap.error("--target (or RAMEN_BRIDGE_TARGET) is required")
    if a.oauth:
        a.oauth = a.oauth.rstrip("/")
        if not a.client_id:
            ap.error(
                "--oauth needs --client-id (RAMEN_BRIDGE_CLIENT_ID): the client a super admin registered on the console"
            )
        if not (a.group and a.zone):
            ap.error("--oauth needs --group and --zone: the token is scoped to mcp:<group>:<zone>")
        a.scope = f"mcp:{a.group}:{a.zone}"
        if a.keychain and a.token_file:
            ap.error("--keychain and --token-file exclude each other")
        if a.keychain and not oauth.KeychainStore.available():
            ap.error("--keychain: no `security` (macOS) or `secret-tool` (Secret Service) on this machine")
    elif a.health is None and not a.key:
        ap.error("--key (or RAMEN_BRIDGE_KEY / RAMEN_MCP_KEY) or --oauth is required")
    if a.insecure:
        for flag, given in (("--tls", a.tls), ("--ca", a.ca)):
            if given:
                ap.error(f"--insecure and {flag} exclude each other: drop --insecure to use TLS (the default)")
        print("ramen-mcp-bridge: plaintext h2c: local development only", file=sys.stderr)
    a.use_tls = not a.insecure
    return a


def channel(a: argparse.Namespace) -> grpc.Channel:
    if not a.use_tls:
        return grpc.insecure_channel(a.target)
    roots = None
    if a.ca:
        with open(a.ca, "rb") as f:
            roots = f.read()
    return grpc.secure_channel(a.target, grpc.ssl_channel_credentials(root_certificates=roots))


def read_messages(inp: BinaryIO) -> Iterator[tuple[bytes, bool]]:
    """Yield `(raw_json, content_length_framed)` for newline-delimited or `Content-Length:` framed input."""
    while line := inp.readline():
        if line.lower().startswith(b"content-length:"):
            n = int(line.split(b":", 1)[1])
            while (h := inp.readline()) and h not in (b"\r\n", b"\n"):
                pass
            yield inp.read(n), True
        elif line.strip():
            yield line.strip(), False


def write_message(out: BinaryIO, raw: bytes, framed: bool) -> None:
    out.write(b"Content-Length: %d\r\n\r\n%s" % (len(raw), raw) if framed else raw + b"\n")
    out.flush()


def _parse(raw: bytes | None) -> dict | None:
    try:
        msg = json.loads(raw) if raw else None
    except ValueError:
        return None
    return msg if isinstance(msg, dict) else None


def _error_code(reply: dict | None) -> int | None:
    err = (reply or {}).get("error")
    return err.get("code") if isinstance(err, dict) else None


def _policy_code(reply: dict | None) -> int | None:
    """The error code as the policy gates mean it: `-32003 … requires telemetry` (a legacy body without the report,
    or without consent) counts as -32024 — one re-sign-in brings the telemetry object, then the retry carries it."""
    err = (reply or {}).get("error")
    code = err.get("code") if isinstance(err, dict) else None
    if code == tel.FORBIDDEN and tel.FORBIDDEN_TEXT in str(err.get("message", "")):
        return tel.REPORT_REQUIRED
    return code


class Bridge:
    def __init__(
        self,
        stub: mcp_pb2_grpc.McpStub,
        metadata: list[tuple[str, str]],
        timeout: float,
        bearer=None,
        telemetry=None,
        pol: "policy.Policy | None" = None,
    ):
        """`bearer` (0.2.0): a callable giving the current access token — `bearer(force=True)` after the worker
        said UNAUTHENTICATED, once per call; without it `metadata` carries the static key. `telemetry` (0.4.0): the
        vault holding the token answer's `telemetry` object plus the recorder of what the host did (§26.3). `pol`
        (0.5.0): the policy bundle whose evals (§29.3), skillspector, configs and guardrails (0.6.0, §30.3 / §31.3 /
        §36.3) versions ride on every gated call; its guardrails pack also runs locally (`rails.py`)."""
        self.stub, self.metadata, self.timeout, self.bearer = stub, metadata, timeout, bearer
        self.telemetry = telemetry or tel.Telemetry()
        self.policy = pol or policy.Policy()
        self.rails = rails.Rails(self.policy, bearer)  # §38.1: the console's LLM proxy is called as the person

    def _metadata(self, force: bool = False) -> list[tuple[str, str]]:
        if self.bearer is None:
            return self.metadata
        return [("authorization", f"Bearer {self.bearer(force=force)}"), *self.metadata]

    def forward(self, raw: bytes) -> bytes | None:
        msg = _parse(raw)
        if msg is None:
            return self._exchange(raw)[0]
        method, params = msg.get("method"), msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if method == "tools/call" and params.get("name") == tel.TOOL["name"]:
            return self._local_report(msg, params)
        start = time.time()
        reply = self._gated(raw, msg) if method in tel.GATED else self._exchange(raw)[0]
        if msg.get("id") is not None and isinstance(method, str):
            name = f"{method} {params.get('name')}" if method == "tools/call" else method
            ms = int((time.time() - start) * 1000)
            self.telemetry.recorder.record("mcp", name, ms, _error_code(_parse(reply)) is None, start=start)
        return self._merge_tools(reply) if method == "tools/list" else reply

    def _exchange(self, raw: bytes) -> tuple[bytes | None, bool]:
        """One round trip (a second with a fresh token after UNAUTHENTICATED). The flag says whether the worker
        answered, as opposed to the bridge making the error up."""
        try:
            return self._call(raw, self._metadata()), True
        except oauth.SignInRequired as e:  # 0.3.0: tell the client (and through it the person) where to sign in
            return self.sign_in_error(raw, e), False
        except grpc.RpcError as e:
            if self.bearer is not None and e.code() == grpc.StatusCode.UNAUTHENTICATED:
                try:
                    return self._call(raw, self._metadata(force=True)), True
                except oauth.SignInRequired as again:
                    return self.sign_in_error(raw, again), False
                except grpc.RpcError as again:
                    return self.error_for(raw, again), False
            return self.error_for(raw, e), False

    # --- 0.4.0: telemetry through Ramen (§26.3) ----------------------------------------------------------------
    RETRY_CODES = (
        tel.REPORT_REQUIRED,
        tel.CONFIG_STALE,
        policy.EVALS_STALE,
        policy.SKILLSPECTOR_STALE,
        policy.CONFIGS_STALE,
        policy.GUARDRAILS_STALE,
    )
    POLICY_KEY: ClassVar[dict] = {
        policy.EVALS_STALE: "evals",
        policy.SKILLSPECTOR_STALE: "skillspector",
        policy.CONFIGS_STALE: "configs",
        policy.GUARDRAILS_STALE: "guardrails",
    }
    WHY: ClassVar[dict] = {
        tel.CONFIG_STALE: "telemetry config changed",
        tel.REPORT_REQUIRED: "telemetry report required",
        policy.EVALS_STALE: "evals config required or changed",
        policy.SKILLSPECTOR_STALE: "skillspector policy required or changed",
        policy.CONFIGS_STALE: "configs required or changed",
        policy.GUARDRAILS_STALE: "guardrails policy required or changed",
    }

    def _attach(self, raw: bytes, msg: dict) -> bytes:
        """The gated call with the report since the last one under `params._meta["io.ramen/telemetry"]` and the
        evals (0.5.0), skillspector, configs and guardrails (0.6.0) versions under `params._meta["io.ramen/<key>"]` —
        each when the bridge holds one; the body is forwarded in the era the host spoke (the bridge does not upgrade
        eras)."""
        version = self.telemetry.version()
        versions = {
            policy.META: self.policy.evals_version(),
            policy.SKILLSPECTOR_META: self.policy.skillspector_version(),
            policy.CONFIGS_META: self.policy.configs_version(),
            policy.GUARDRAILS_META: self.policy.guardrails_version(),
        }
        if version is None and not any(versions.values()):
            return raw
        out = dict(msg)
        params = dict(out.get("params") or {})
        meta = dict(params.get("_meta") or {})
        if version is not None:
            meta[tel.META] = self.telemetry.recorder.take(version)
        for key, v in versions.items():
            if v is not None:
                meta[key] = {"version": v}
        params["_meta"] = meta
        out["params"] = params
        return json.dumps(out).encode()

    def _configs_in_place(self, raw: bytes) -> tuple[bool, bytes | None]:
        """§31.3 / §36.3: a recorded configs or telemetry target, or the unpacked guardrails pack, that was removed or
        changed stops every gated call — after one re-sign-in, which writes the files again — until it is back; the
        refusal names the files."""
        broken = configs.verify(self.policy) + self.policy.verify_guardrails()
        if broken and self.bearer is not None:
            try:
                self.bearer(force=True)
            except oauth.OAuthError:
                pass
            broken = configs.verify(self.policy) + self.policy.verify_guardrails()
        if not broken:
            return False, None
        line = {"level": "warn", "msg": configs.REMOVED, "paths": broken}
        print(json.dumps(line, ensure_ascii=False), file=sys.stderr)
        rid = (_parse(raw) or {}).get("id")
        if rid is None:
            return True, None
        err = {"code": policy.CONFIGS_STALE, "message": configs.REMOVED, "data": {"paths": broken}}
        return True, json.dumps({"jsonrpc": "2.0", "id": rid, "error": err}).encode()

    def _local_block(self, msg: dict, result: dict) -> bytes | None:
        """A rail on this machine stopped the call (or its result): the host gets the worker's shape of a block."""
        rid = msg.get("id")
        return None if rid is None else json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}).encode()

    def _rails_pre(self, msg: dict) -> bytes | None:
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if msg.get("method") != "tools/call":
            return None
        block = self.rails.pre(params)
        return None if block is None else (self._local_block(msg, block) or b"")

    def _rails_post(self, msg: dict, reply: bytes | None) -> bytes | None:
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        out = _parse(reply)
        if msg.get("method") != "tools/call" or out is None or not isinstance(out.get("result"), dict):
            return reply
        block = self.rails.post(params, out["result"])
        return reply if block is None else self._local_block(msg, block)

    def _telemetry_in_hand(self, raw: bytes) -> bytes | None:
        """P4-B3: the bundle says the group requires telemetry but no telemetry object is held (a still-valid
        `--token-file` made no token request at start): one token request before the first gated call, so the call
        carries the report instead of being refused."""
        if self.bearer is None or not self.policy.telemetry_required() or self.telemetry.version() is not None:
            return None
        line = {"level": "info", "msg": "telemetry required; requesting the token answer's telemetry config"}
        print(json.dumps(line), file=sys.stderr)
        try:
            self.bearer(force=True)
        except oauth.SignInRequired as e:
            return self.sign_in_error(raw, e)
        except oauth.OAuthError:
            pass
        return None

    def _gated(self, raw: bytes, msg: dict) -> bytes | None:
        rec = self.telemetry.recorder
        if self.policy.target is not None:
            refused, reply = self._configs_in_place(raw)
            if refused:
                return reply
        if (reply := self._telemetry_in_hand(raw)) is not None:
            return reply
        if (blocked := self._rails_pre(msg)) is not None:  # §36.3: the input rails, before the call leaves
            return blocked or None
        reply, delivered = self._exchange(self._attach(raw, msg))
        code = _policy_code(_parse(reply)) if delivered else None
        if not delivered:
            rec.restore()
            return reply
        if code not in self.RETRY_CODES:
            rec.commit()
            return self._rails_post(msg, reply)
        rec.restore()
        why = self.WHY[code]
        print(json.dumps({"level": "info", "msg": f"{why}; signing in again and retrying once"}), file=sys.stderr)
        if self.bearer is not None:
            try:
                self.bearer(force=True)  # the refresh grant brings the current policy; else the browser
            except oauth.SignInRequired as e:
                return self.sign_in_error(raw, e)
            except oauth.OAuthError:
                return reply
        named = ((_parse(reply) or {}).get("error", {}).get("data") or {}).get("version")
        if isinstance(named, str) and named:
            # a static key cannot sign in: go on under the version the worker named
            key = self.POLICY_KEY.get(code)
            if key is not None and (self.bearer is None or self.policy.version_of(key) is None):
                self.policy.adopt(key, named)
            elif key is None and (self.bearer is None or self.telemetry.version() is None):
                self.telemetry.adopt(named)
        reply, delivered = self._exchange(self._attach(raw, msg))
        if delivered and _policy_code(_parse(reply)) not in self.RETRY_CODES:
            rec.commit()
            return self._rails_post(msg, reply)
        rec.restore()
        return reply

    def _local_report(self, msg: dict, params: dict) -> bytes | None:
        """`tools/call ramen_report`: recorded here, never forwarded."""
        rid = msg.get("id")
        if rid is None:
            return None
        text = self.telemetry.handle_report(params.get("arguments"))
        if text is None:
            err = {
                "code": -32602,
                "message": "ramen_report: kind (llm|tool|other), name, ms (int ≥ 0), ok (bool), reasoning?",
            }
            return json.dumps({"jsonrpc": "2.0", "id": rid, "error": err}).encode()
        result: dict = {"content": [{"type": "text", "text": text}], "isError": False}
        if "io.modelcontextprotocol/protocolVersion" in (params.get("_meta") or {}):
            result["resultType"] = "complete"
        return json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}).encode()

    @staticmethod
    def _merge_tools(reply: bytes | None) -> bytes | None:
        """`ramen_report` joins the server's tools on the last page of `tools/list`."""
        msg = _parse(reply)
        result = (msg or {}).get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list) or result.get("nextCursor"):
            return reply
        result["tools"] = [*result["tools"], tel.TOOL]
        return json.dumps(msg).encode()

    @staticmethod
    def sign_in_error(raw: bytes, e: "oauth.SignInRequired") -> bytes | None:
        print(json.dumps({"level": "warn", "msg": "sign-in required", "url": e.url}), file=sys.stderr)
        try:
            rid = json.loads(raw).get("id")
        except (ValueError, AttributeError):
            rid = None
        if rid is None:
            return None
        msg = (
            "Ramen sign-in required. Ask the person to open this link in a browser and approve, then retry the call: "
            f"{e.url}"
        )
        err = {"code": -32001, "message": msg, "data": {"sign_in_url": e.url}}
        return json.dumps({"jsonrpc": "2.0", "id": rid, "error": err}).encode()

    def _call(self, raw: bytes, md) -> bytes | None:
        return self.stub.Call(mcp_pb2.JsonRpc(body=raw), metadata=md, timeout=self.timeout).body or None

    @staticmethod
    def error_for(raw: bytes, e: grpc.RpcError) -> bytes | None:
        code, details = e.code(), e.details()
        line = {"level": "warn", "msg": "grpc error", "code": code.name, "details": details}
        print(json.dumps(line), file=sys.stderr)
        try:
            rid = json.loads(raw).get("id")
        except (ValueError, AttributeError):
            rid = None
        if rid is None:
            return None
        err = {"code": CODES.get(code, -32603), "message": f"{code.name}: {details}"}
        return json.dumps({"jsonrpc": "2.0", "id": rid, "error": err}).encode()


def serve(bridge: Bridge, inp: BinaryIO, out: BinaryIO) -> int:
    for raw, framed in read_messages(inp):
        if (reply := bridge.forward(raw)) is not None:
            write_message(out, reply, framed)
    return 0


def health(ch: grpc.Channel, service: str, timeout: float) -> int:
    try:
        req = health_pb2.HealthCheckRequest(service=service)
        st = health_pb2_grpc.HealthStub(ch).Check(req, timeout=timeout).status
    except grpc.RpcError as e:
        print(f"health {service!r}: {e.code().name}", file=sys.stderr)
        return 1
    print(health_pb2.HealthCheckResponse.ServingStatus.Name(st))
    return 0 if st == health_pb2.HealthCheckResponse.SERVING else 1


def bridge_args(a: argparse.Namespace) -> list[str]:
    """The `uvx` arguments a client config needs to start this very bridge (the sign-in guide's shape)."""
    args = ["ramen-mcp-bridge@latest", "--target", a.target]
    if a.ca:
        args += ["--ca", a.ca]
    elif a.insecure:
        args.append("--insecure")
    args += ["--oauth", a.oauth, "--client-id", a.client_id, "--group", a.group, "--zone", a.zone]
    return args


def can_sign_in(client: oauth.Client, a: argparse.Namespace) -> bool:
    """False when nothing could complete a sign-in: no refresh token, no browser to open (`--no-browser`) and no
    terminal where someone would read the printed URL."""
    if (getattr(client, "tokens", None) or {}).get("refresh_token"):
        return True
    if not a.no_browser:
        return True
    try:
        return sys.stderr.isatty()
    except (AttributeError, ValueError):
        return False


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv[:1] == ["policy"]:
        return policy_main(argv[1:])
    if argv[:1] == ["skills"]:
        return skills_main(argv[1:])
    a = parse_args(argv)
    ch = channel(a)
    if a.health is not None:
        return health(ch, a.health, a.timeout)
    b = connect(a, ch)
    return b if isinstance(b, int) else serve(b, sys.stdin.buffer, sys.stdout.buffer)


def connect(a: argparse.Namespace, ch: grpc.Channel) -> "Bridge | int":
    """The bridge for these flags, signed in when `--oauth`; an exit code when the sign-in cannot happen."""
    md = [(k, v) for k, v in (("ramen-group", a.group), ("ramen-zone", a.zone)) if v]
    if a.oauth:
        opener = (lambda url: None) if a.no_browser else None
        # 0.3.0: memory by default (nothing on disk); --keychain → the OS secret store; --token-file → a plain file
        if a.keychain:
            store = oauth.KeychainStore(f"{a.oauth}|{a.client_id}|{a.scope}")
        elif a.token_file:
            store = oauth.TokenFile(a.token_file)
        else:
            store = oauth.MemoryStore()
        client = oauth.Client(
            a.oauth, a.client_id, a.scope, store, opener=opener, ca=a.ca, idle_secs=max(0.0, a.idle_timeout)
        )
        # 0.5.0: the policy bundle — loaded from the last sign-in, rewritten by every token answer (§29.3)
        pol = policy.Policy(a.target, a.group, a.zone, a.oauth)
        pol.load()
        if not a.no_client_config:
            uvx = bridge_args(a)

            def on_update(p: policy.Policy) -> None:
                clients.install(p, uvx, client_scan=not a.no_client_scan)
                configs.apply(p, shell_rc=not a.no_shell_rc)  # §31.3: the group's configs and telemetry targets

            pol.on_update = on_update
        client.policy = pol
        if pol.bundle is None and not can_sign_in(client, a):
            print(policy.MISSING, file=sys.stderr)
            return policy.EXIT_MISSING
        try:
            client.bearer()  # sign in before the first message, so the client's first request does not wait on a browser
        except oauth.OAuthError as e:
            print(f"ramen-mcp-bridge: {e}", file=sys.stderr)
            if pol.bundle is None:
                print(policy.MISSING, file=sys.stderr)
                return policy.EXIT_MISSING
            return 2
        # while serving, a needed sign-in is reported to the client as an error carrying the URL, never a hang

        def bearer(force: bool = False) -> str:
            return client.bearer(force=force, nonblocking=True)

        b = Bridge(
            mcp_pb2_grpc.McpStub(ch), md, a.timeout, bearer=bearer, telemetry=tel.Telemetry(client.vault), pol=pol
        )
        b.rails.announce()  # §36.3: one line when the pack is here and the nemo extra is not
        return b
    md = [("authorization", f"Bearer {a.key}"), *md]
    return Bridge(mcp_pb2_grpc.McpStub(ch), md, a.timeout)


# --- 0.6.0: `ramen-mcp-bridge skills list|install <name>` (§33.2) --------------------------------------------------
def skills_main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="ramen-mcp-bridge skills",
        description="list the group's skills (skills/list) or install one under your skills directory; "
        "the connection flags are the bridge's (--target, --key or --oauth …)",
    )
    ap.add_argument("action", choices=["list", "install"], help="list, or install <name>")
    ap.add_argument("--dir", default=None, help="skills directory (default ~/.claude/skills)")
    # the leading words are ours (`install <name>`); every option but --dir is the bridge's
    words, rest = [], list(argv)
    while rest and not rest[0].startswith("-") and len(words) < 2:
        words.append(rest.pop(0))
    s, rest = ap.parse_known_args([words[0]] + rest if words else rest)
    s.name = words[1] if len(words) > 1 else None
    if s.action == "install" and not s.name:
        ap.error("install needs the skill's name")
    a = parse_args(rest)
    b = connect(a, channel(a))
    if isinstance(b, int):
        return b
    try:
        if s.action == "list":
            for sk in skills.list_skills(b):
                files = sk.get("files") if isinstance(sk.get("files"), list) else []
                print(f"{sk['name']}\t{sk.get('version') or '-'}\t{len(files)} files\t{sk.get('description') or ''}")
            return 0
        dest = Path(s.dir).expanduser() if s.dir else skills.default_dir()
        for p in skills.install(b, b.policy, s.name, dest, a.target, a.group, a.zone):
            print(f"wrote {p}", file=sys.stderr)
        print(f"installed skill {s.name} under {dest / s.name}", file=sys.stderr)
        return 0
    except skills.SkillError as e:
        print(f"ramen-mcp-bridge skills {s.action}: {e}", file=sys.stderr)
        if e.code == skills.EXIT_BLOCK:
            print(scan.BLOCK, file=sys.stderr)
        return e.code


# --- 0.5.0: `ramen-mcp-bridge policy show|check|remove` (§29.3; the local scan of §30.3 since 0.6.0) ------------
def policy_main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="ramen-mcp-bridge policy", description="the policy bundle kept at sign-in")
    ap.add_argument("action", choices=["show", "check", "remove", "rails"])
    ap.add_argument("switch", nargs="?", choices=["on", "off"], help="rails: run the group's guardrails locally")
    ap.add_argument("--target", default=_env("TARGET"), help="host:port the bundle was made for")
    ap.add_argument("--group", default=_env("GROUP"))
    ap.add_argument("--zone", default=_env("ZONE"))
    ap.add_argument("--ca", default=_env("CA"), help="PEM CA bundle for the console (check)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument(
        "--no-client-scan",
        action="store_true",
        default=_env("NO_CLIENT_SCAN") in ("1", "true"),
        help="skip the SkillSpector scan of this machine's skills (show, check)",
    )
    a = ap.parse_args(argv)
    pol = policy.find(a.target, a.group, a.zone)
    if pol is None:
        n = len(policy.list_bundles())
        if n > 1 and not (a.target and a.group and a.zone):
            print(f"ramen-mcp-bridge policy: {n} bundles; name one with --target --group --zone", file=sys.stderr)
            return 1
        print(policy.MISSING, file=sys.stderr)
        return 2
    if a.action == "rails":  # §36.3: the local rails switch, kept in the bundle
        if a.switch is None:
            print("on" if pol.rails_enabled() else "off")
            return 0
        pol.set_rails(a.switch == "on")
        print(f"local guardrails {a.switch} for {pol.group}/{pol.zone} on {pol.target}", file=sys.stderr)
        return 0
    if a.action == "show":
        print(json.dumps(pol.bundle, indent=1))
        for line in configs.show(pol):  # §31.3: every configs / telemetry target and whether it is still in place
            print(line)
        for line in rails_show(pol):
            print(line)
        return 0 if a.no_client_scan else scan.check(pol)
    if a.action == "remove":
        reverted = clients.remove(pol.target or "", pol.group, pol.zone)
        pol.remove_files()
        for e in reverted:
            where = e.get("file") or e.get("path", "")
            print(f"reverted {e['kind']}: {where}" + (f" [{e['key']}]" if e.get("key") else ""), file=sys.stderr)
        print(f"removed the policy bundle for {pol.group}/{pol.zone} on {pol.target}", file=sys.stderr)
        return 0
    if (rc := configs.check(pol)) != 0:  # §31.3: the files first — offline, and the reason the hook exists
        return rc
    if broken := pol.verify_guardrails():  # §36.3: the unpacked pack, the same way
        for p in broken:
            print(f"ramen guardrails: {p}: removed or changed", file=sys.stderr)
        print(configs.REMOVED, file=sys.stderr)
        return configs.EXIT_REMOVED
    import ssl

    try:
        current = pol.fetch_current(a.timeout, ssl.create_default_context(cafile=a.ca) if a.ca else None)
    except RuntimeError as e:
        print(f"ramen-mcp-bridge policy check: {e}", file=sys.stderr)
        return 1
    diff = pol.compare(current)
    if diff:
        print(policy.STALE + " (" + "; ".join(diff) + ")", file=sys.stderr)
        return 2
    print(f"Ramen policy up to date for {pol.group}/{pol.zone} on {pol.target}")
    return 0 if a.no_client_scan else scan.check(pol)


def rails_show(pol: policy.Policy) -> list[str]:
    """`policy show`: the guardrails pack's state and whether the local rails run."""
    if pol.guardrails_sha() is None:
        return []
    ok = not pol.verify_guardrails()
    state = "on" if pol.rails_enabled() else "off"
    if pol.rails_enabled() and not rails.available():
        state = "on but inactive: install ramen-mcp-bridge[nemo]"
    return [f"{'ok     ' if ok else 'CHANGED'} {pol.guardrails_dir} (guardrails pack, local rails {state})"]


if __name__ == "__main__":
    sys.exit(main())
