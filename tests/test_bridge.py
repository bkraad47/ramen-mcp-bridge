"""ramen-mcp-bridge against an in-process grpcio fake of ramen.v1.Mcp (+ grpc.health.v1)."""

import io
import json
import os
import subprocess
import sys
from concurrent import futures

import grpc
import pytest
from grpc_health.v1 import health, health_pb2, health_pb2_grpc

from ramen_mcp_bridge import bridge
from ramen_proto.ramen.v1 import mcp_pb2, mcp_pb2_grpc

SRC = os.path.join(os.path.dirname(__file__), "..", "src")


class FakeMcp(mcp_pb2_grpc.McpServicer):
    """Minimal MCP over gRPC: bearer `good` required, ping/initialize/tools/*; records metadata."""

    def __init__(self):
        self.seen: list[dict] = []
        self.hook = None  # 0.4.0 tests: (msg, md) -> error dict | None, a gate in front of the methods
        self.next_cursor: str | None = None
        self.delay = 0.0
        self.skills: list[dict] | None = None  # §33.2: `skills/list` answer; None = method not found
        self.skill_files: dict[str, dict] = {}  # `skill://…` uri → resources/read content ({"text"} | {"blob"})
        self.tool_results: dict[str, dict] = {}  # §36.3 tests: a tools/call result by tool name (else a+b)

    def Call(self, request, context):
        import time

        md = dict(context.invocation_metadata())
        self.seen.append(md)
        if md.get("authorization") != "Bearer good":
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "unauthorized")
        msg = json.loads(request.body)
        rid, method = msg.get("id"), msg.get("method", "")
        if method.startswith("notifications/"):
            return mcp_pb2.JsonRpc(body=b"")
        if method == "busy":
            context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "busy")
        if method == "slow":
            time.sleep(2)
        if self.delay:
            time.sleep(self.delay)
        if self.hook and (err := self.hook(msg, md)):
            return mcp_pb2.JsonRpc(body=json.dumps({"jsonrpc": "2.0", "id": rid, "error": err}).encode())
        result = {
            "ping": {},
            "initialize": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake", "version": "0"},
            },
            "tools/list": {
                "tools": [
                    {
                        "name": "add",
                        "description": "a+b",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
                            "required": ["a", "b"],
                        },
                    }
                ]
            },
        }.get(method)
        if method == "tools/list" and self.next_cursor:
            result["nextCursor"] = self.next_cursor
        if method in ("prompts/get", "resources/read"):
            result = {"messages": []} if method == "prompts/get" else {"contents": []}
            uri = (msg.get("params") or {}).get("uri")
            if method == "resources/read" and uri in self.skill_files:
                result = {"contents": [{"uri": uri, "mimeType": "text/plain", **self.skill_files[uri]}]}
        if method == "skills/list" and self.skills is not None:
            result = {"skills": self.skills}
        if method == "tools/call" and msg["params"].get("name") in self.tool_results:
            result = self.tool_results[msg["params"]["name"]]
        elif method == "tools/call":
            args = msg["params"]["arguments"]
            result = {"content": [{"type": "text", "text": str(args["a"] + args["b"])}], "isError": False}
        if result is None:
            body = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"method not found: {method}"}}
        else:
            body = {"jsonrpc": "2.0", "id": rid, "result": result}
        return mcp_pb2.JsonRpc(body=json.dumps(body).encode())


@pytest.fixture
def fake():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    svc = FakeMcp()
    mcp_pb2_grpc.add_McpServicer_to_server(svc, server)
    hs = health.HealthServicer()
    hs.set("", health_pb2.HealthCheckResponse.SERVING)
    hs.set("ramen.v1.Mcp", health_pb2.HealthCheckResponse.NOT_SERVING)
    health_pb2_grpc.add_HealthServicer_to_server(hs, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    svc.target = f"127.0.0.1:{port}"
    yield svc
    server.stop(None)


def make_bridge(fake, key="good", timeout=5.0) -> bridge.Bridge:
    stub = mcp_pb2_grpc.McpStub(grpc.insecure_channel(fake.target))
    md = [("authorization", f"Bearer {key}"), ("ramen-group", "demo"), ("ramen-zone", "local")]
    return bridge.Bridge(stub, md, timeout)


def run(b: bridge.Bridge, data: bytes) -> bytes:
    out = io.BytesIO()
    assert bridge.serve(b, io.BytesIO(data), out) == 0
    return out.getvalue()


def test_parse_args_flags_and_env(monkeypatch):
    a = bridge.parse_args(["--target", "h:1", "--key", "k", "--group", "g", "--zone", "z"])
    # D86 (§39.3): TLS is the default
    assert (a.target, a.key, a.group, a.zone, a.use_tls, a.timeout) == ("h:1", "k", "g", "z", True, 120.0)
    assert bridge.parse_args(["--target", "h:1", "--key", "k", "--tls"]).use_tls
    assert bridge.parse_args(["--target", "h:1", "--key", "k", "--ca", "/x.pem"]).use_tls
    monkeypatch.setenv("RAMEN_BRIDGE_TARGET", "e:2")
    monkeypatch.setenv("RAMEN_BRIDGE_KEY", "ek")
    monkeypatch.setenv("RAMEN_BRIDGE_TLS", "1")  # harmless: TLS is the default anyway
    monkeypatch.setenv("RAMEN_BRIDGE_TIMEOUT", "3")
    a = bridge.parse_args([])
    assert (a.target, a.key, a.use_tls, a.timeout, a.health) == ("e:2", "ek", True, 3.0, None)
    assert bridge.parse_args(["--health"]).health == ""
    assert bridge.parse_args(["--health", "ramen.v1.Admin"]).health == "ramen.v1.Admin"
    monkeypatch.delenv("RAMEN_BRIDGE_KEY")
    # §16.4: RAMEN_MCP_KEY is the generic spelling every client config can rely on; the bridge-specific one wins
    monkeypatch.setenv("RAMEN_MCP_KEY", "mk")
    assert bridge.parse_args([]).key == "mk"
    monkeypatch.setenv("RAMEN_BRIDGE_KEY", "bk")
    assert bridge.parse_args([]).key == "bk"
    assert bridge.parse_args(["--key", "ck"]).key == "ck"
    monkeypatch.delenv("RAMEN_BRIDGE_KEY")
    monkeypatch.delenv("RAMEN_MCP_KEY")
    assert bridge.parse_args(["--health"]).key is None
    with pytest.raises(SystemExit):
        bridge.parse_args([])  # key missing for the bridge mode
    monkeypatch.delenv("RAMEN_BRIDGE_TARGET")
    with pytest.raises(SystemExit):
        bridge.parse_args(["--key", "k"])


def test_insecure_is_explicit_and_warns(monkeypatch, capsys):
    """D86: plaintext h2c only on request, with one warning; never silently next to --tls / --ca."""
    for k in ("TLS", "CA", "INSECURE"):
        monkeypatch.delenv(f"RAMEN_BRIDGE_{k}", raising=False)
    a = bridge.parse_args(["--target", "h:1", "--key", "k", "--insecure"])
    assert not a.use_tls and a.insecure
    assert capsys.readouterr().err.count("plaintext h2c: local development only") == 1
    assert bridge.parse_args(["--target", "h:1", "--key", "k"]).use_tls
    assert "plaintext" not in capsys.readouterr().err
    for extra in (["--tls"], ["--ca", "/x.pem"]):
        with pytest.raises(SystemExit) as e:
            bridge.parse_args(["--target", "h:1", "--key", "k", "--insecure", *extra])
        assert e.value.code == 2
        assert f"--insecure and {extra[0]} exclude each other" in capsys.readouterr().err
    monkeypatch.setenv("RAMEN_BRIDGE_INSECURE", "1")  # the env form of --insecure
    assert not bridge.parse_args(["--target", "h:1", "--key", "k"]).use_tls
    monkeypatch.setenv("RAMEN_BRIDGE_CA", "/x.pem")
    with pytest.raises(SystemExit):
        bridge.parse_args(["--target", "h:1", "--key", "k"])
    monkeypatch.setenv("RAMEN_BRIDGE_INSECURE", "0")
    assert bridge.parse_args(["--target", "h:1", "--key", "k"]).use_tls
    monkeypatch.delenv("RAMEN_BRIDGE_CA")
    monkeypatch.setenv("RAMEN_BRIDGE_TLS", "1")  # an old TLS=1 next to --insecure is not a conflict: it is the default
    assert not bridge.parse_args(["--target", "h:1", "--key", "k", "--insecure"]).use_tls


def test_channel_is_secure_by_default(monkeypatch):
    made = {}
    monkeypatch.setattr(bridge.grpc, "secure_channel", lambda t, c: made.setdefault("secure", t))
    monkeypatch.setattr(bridge.grpc, "insecure_channel", lambda t: made.setdefault("insecure", t))
    bridge.channel(bridge.parse_args(["--target", "h:1", "--key", "k"]))
    assert made == {"secure": "h:1"}
    made.clear()
    bridge.channel(bridge.parse_args(["--target", "h:1", "--key", "k", "--insecure"]))
    assert made == {"insecure": "h:1"}


def test_bridge_args_carry_the_transport_the_user_chose():
    """The client config the bridge writes at sign-in: no --tls (the default), --ca or --insecure as given."""
    base = ["--target", "h:443", "--oauth", "https://c", "--client-id", "cid", "--group", "g", "--zone", "z"]
    args = bridge.bridge_args(bridge.parse_args(base))
    assert "--tls" not in args and "--insecure" not in args and "--ca" not in args
    assert bridge.bridge_args(bridge.parse_args([*base, "--tls"])) == args
    assert args[args.index("--target") + 1] == "h:443" and args[0] == "ramen-mcp-bridge@latest"
    with_ca = bridge.bridge_args(bridge.parse_args([*base, "--ca", "/ca.pem"]))
    assert with_ca[with_ca.index("--ca") + 1] == "/ca.pem"
    assert "--insecure" in bridge.bridge_args(bridge.parse_args([*base, "--insecure"]))


def test_channel_tls_and_plain(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n")
    assert bridge.channel(bridge.parse_args(["--target", "h:1", "--key", "k", "--insecure"])) is not None
    assert bridge.channel(bridge.parse_args(["--target", "h:1", "--key", "k", "--tls"])) is not None
    assert bridge.channel(bridge.parse_args(["--target", "h:1", "--key", "k", "--ca", str(ca)])) is not None


def test_framing_newline_and_content_length():
    body = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
    msgs = list(bridge.read_messages(io.BytesIO(body + b"\n\n" + body + b"\r\n")))
    assert msgs == [(body, False), (body, False)]
    framed = b"Content-Length: %d\r\nContent-Type: application/json\r\n\r\n%s" % (len(body), body)
    assert list(bridge.read_messages(io.BytesIO(framed + framed))) == [(body, True), (body, True)]
    out = io.BytesIO()
    bridge.write_message(out, body, False)
    bridge.write_message(out, body, True)
    assert out.getvalue() == body + b"\n" + framed.replace(b"Content-Type: application/json\r\n", b"")


def test_forwards_metadata_and_relays_responses(fake):
    b = make_bridge(fake)
    out = run(
        b,
        b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
        b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
        b'{"jsonrpc":"2.0","id":2,"method":"nope"}\n',
    )
    lines = [json.loads(x) for x in out.splitlines()]
    assert lines[0] == {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert lines[1]["error"]["code"] == -32601 and len(lines) == 2
    md = fake.seen[0]
    assert (md["authorization"], md["ramen-group"], md["ramen-zone"]) == ("Bearer good", "demo", "local")
    # Content-Length in → Content-Length out
    req = b'{"jsonrpc":"2.0","id":3,"method":"ping"}'
    out = run(b, b"Content-Length: %d\r\n\r\n%s" % (len(req), req))
    assert out.startswith(b"Content-Length: ") and out.endswith(b'"result": {}}')


def test_grpc_errors_become_jsonrpc_errors_for_requests_only(fake, capsys):
    bad = make_bridge(fake, key="wrong")
    out = run(bad, b'{"jsonrpc":"2.0","id":7,"method":"ping"}\n{"jsonrpc":"2.0","method":"notifications/x"}\n')
    lines = [json.loads(x) for x in out.splitlines()]
    assert len(lines) == 1 and lines[0]["id"] == 7 and lines[0]["error"]["code"] == -32001
    assert "UNAUTHENTICATED" in lines[0]["error"]["message"]
    assert "grpc error" in capsys.readouterr().err
    busy = json.loads(run(make_bridge(fake), b'{"jsonrpc":"2.0","id":8,"method":"busy"}\n'))
    assert busy["error"]["code"] == -32000 and "RESOURCE_EXHAUSTED" in busy["error"]["message"]
    slow = json.loads(run(make_bridge(fake, timeout=0.2), b'{"jsonrpc":"2.0","id":9,"method":"slow"}\n'))
    assert "DEADLINE_EXCEEDED" in slow["error"]["message"]
    assert run(bad, b"[1,2]\n") == b""  # not an object: no id → nothing to answer
    down = bridge.Bridge(mcp_pb2_grpc.McpStub(grpc.insecure_channel("127.0.0.1:1")), [], 1.0)
    unavailable = json.loads(run(down, b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'))
    assert unavailable["error"]["code"] == -32000


def test_health_probe(fake, capsys):
    ch = grpc.insecure_channel(fake.target)
    assert bridge.health(ch, "", 5) == 0
    assert capsys.readouterr().out.strip() == "SERVING"
    assert bridge.health(ch, "ramen.v1.Mcp", 5) == 1
    assert bridge.health(ch, "unknown", 5) == 1
    assert "NOT_FOUND" in capsys.readouterr().err
    assert bridge.main(["--target", fake.target, "--insecure", "--health"]) == 0
    assert bridge.main(["--target", "127.0.0.1:1", "--insecure", "--health", "--timeout", "1"]) == 1


def test_main_end_to_end_over_stdio(fake, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')))
    out = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(out))
    assert bridge.main(["--target", fake.target, "--insecure", "--key", "good", "--group", "g", "--zone", "z"]) == 0
    assert json.loads(out.getvalue()) == {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert (fake.seen[-1]["ramen-group"], fake.seen[-1]["ramen-zone"]) == ("g", "z")


def test_bridge_as_subprocess_omits_empty_routing_metadata(fake):
    env = os.environ | {"PYTHONPATH": SRC, "RAMEN_BRIDGE_KEY": "good"}
    p = subprocess.run(
        [sys.executable, "-m", "ramen_mcp_bridge.bridge", "--target", fake.target, "--insecure"],
        input=b'{"jsonrpc":"2.0","id":5,"method":"ping"}\n',
        capture_output=True,
        env=env,
        timeout=30,
        check=False,
    )
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["result"] == {}
    assert "ramen-group" not in fake.seen[-1] and "ramen-zone" not in fake.seen[-1]


def test_mcp_sdk_stdio_client_through_the_bridge(fake):
    """The official `mcp` client spawns the bridge as a stdio server: initialize → tools/list → tools/call."""
    import asyncio

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "ramen_mcp_bridge.bridge",
            "--target",
            fake.target,
            "--insecure",
            "--key",
            "good",
            "--group",
            "demo",
        ],
        env=os.environ | {"PYTHONPATH": SRC},
    )

    async def go():
        async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
            await s.initialize()
            tools = await s.list_tools()
            res = await s.call_tool("add", {"a": 2, "b": 3})
            rep = await s.call_tool("ramen_report", {"kind": "llm", "name": "m", "ms": 3, "ok": True, "reasoning": "r"})
            return [t.name for t in tools.tools], res.content[0].text, res.is_error, rep.is_error

    assert asyncio.run(go()) == (["add", "ramen_report"], "5", False, False)
    assert any(m.get("ramen-group") == "demo" for m in fake.seen)
