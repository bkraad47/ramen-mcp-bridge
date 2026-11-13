"""Telemetry through Ramen (bridge 0.4.0, CONTRACTS §26.3 client side): the token answer's `telemetry` object sealed
in memory, every forwarded call recorded, `ramen_report` for the host, the report on gated calls, -32024/-32025."""

import json
import time

import grpc
import pytest
from test_bridge import fake, run  # noqa: F401 - fixture
from test_oauth import FakeAS

from ramen_mcp_bridge import bridge, oauth, telemetry
from ramen_proto.ramen.v1 import mcp_pb2_grpc

CFG = {"otlp_endpoint": "http://collector.example:4318", "headers": {"x-api-key": "hunter2"}, "version": "abc123def456"}
GATED = ("tools/call", "prompts/get", "resources/read")


def req(rid, method, **params) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}).encode() + b"\n"


def meta_of(seen_body: bytes) -> dict | None:
    return (json.loads(seen_body).get("params") or {}).get("_meta", {}).get("io.ramen/telemetry")


def test_vault_holds_ciphertext_only_and_round_trips():
    v = telemetry.Vault()
    assert v.open() is None
    v.seal(CFG)
    blob = v._blob
    assert isinstance(blob, bytes) and v.open() == CFG
    for secret in (b"collector.example", b"hunter2", b"abc123def456", json.dumps(CFG).encode()):
        assert secret not in blob
    assert "hunter2" not in repr(v) and "collector" not in str(v)
    assert telemetry.Vault().open() is None  # keys are per instance: another vault cannot open this blob
    other = telemetry.Vault()
    other._blob = blob
    with pytest.raises(ValueError):
        other.open()
    v.seal(None)
    assert v.open() is None and v._blob is None


def test_sign_in_seals_the_telemetry_object_and_keeps_it_off_the_store(auth_tel, tmp_path, capsys):
    store = oauth.TokenFile(tmp_path / "t.json")
    c = oauth.Client(auth_tel.url, "cid", "mcp:demo:local", store, opener=auth_tel.browser)
    assert c.bearer() == "good"
    assert c.vault.open() == CFG
    saved = (tmp_path / "t.json").read_text()
    assert "telemetry" not in saved and "hunter2" not in saved and "telemetry" not in c.tokens
    err = capsys.readouterr().err
    assert "hunter2" not in err and "collector.example" not in err
    # a refresh answer carries the (possibly new) object too
    auth_tel.telemetry = {**CFG, "version": "fedcba987654"}
    c.refresh()
    assert c.vault.open()["version"] == "fedcba987654"
    auth_tel.telemetry = None  # telemetry switched off on the console: the next answer has none
    c.refresh()
    assert c.vault.open() is None


def test_recorder_seq_limits_and_reasoning_cap():
    r = telemetry.Recorder()
    assert r.take("v1") == {"version": "v1", "seq": 1, "events": []}  # an empty report is valid
    r.record("llm", "claude", 12, True, reasoning="x" * 5000)
    rep = r.take("v1")
    assert rep["seq"] == 2 and len(rep["events"]) == 1
    ev = rep["events"][0]
    assert ev["kind"] == "llm" and ev["name"] == "claude" and ev["ms"] == 12 and ev["ok"] is True
    assert len(ev["reasoning"]) == 4096 and ev["ts"].endswith("Z")
    r.restore()  # the call that carried it failed before the gate: the events come back, oldest first
    r.record("tool", "grep", 1, False)
    rep = r.take("v1")
    assert rep["seq"] == 3 and [e["name"] for e in rep["events"]] == ["claude", "grep"]
    r.commit()
    assert r.take("v1")["events"] == []
    # ≤ 200 events per report, the rest waits for the next one (oldest first)
    for i in range(450):
        r.record("mcp", f"m{i}", 0, True)
    a, b, c = (r.take("v1") for _ in range(3))
    r.commit()
    assert [len(x["events"]) for x in (a, b, c)] == [200, 200, 50]
    assert a["events"][0]["name"] == "m0" and c["events"][-1]["name"] == "m449"
    # ≤ 64 KiB per report
    for i in range(40):
        r.record("llm", f"big{i}", 0, True, reasoning="r" * 4096)
    rep = r.take("v1")
    assert len(json.dumps(rep).encode()) <= telemetry.MAX_BYTES and 0 < len(rep["events"]) < 40
    # a host that never makes a gated call cannot grow the queue without bound
    for i in range(telemetry.MAX_PENDING + 100):
        r.record("other", "x", 0, True)
    assert len(r.pending) == telemetry.MAX_PENDING


class TelFake:
    """A fake worker enforcing §26.3: gated calls need the report with the current version."""

    def __init__(self, fake, version="abc123def456", require=True):  # noqa: F811
        self.inner, self.version, self.require = fake, version, require
        self.bodies: list[bytes] = []
        fake.hook = self.gate

    def gate(self, msg, md):
        self.bodies.append(json.dumps(msg).encode())
        if msg.get("method") not in GATED or not self.require:
            return None
        rep = meta_of(json.dumps(msg).encode())
        if rep is None:
            return {"code": -32024, "message": "telemetry report required", "data": {"version": self.version}}
        if rep["version"] != self.version:
            return {
                "code": -32025,
                "message": "telemetry config changed: sign in again",
                "data": {"version": self.version},
            }
        if len(rep["events"]) > 200 or len(json.dumps(rep).encode()) > 65536:
            return {"code": -32602, "message": "report too large"}
        return None


@pytest.fixture
def auth_tel():
    a = FakeAS()
    a.telemetry = dict(CFG)
    yield a
    a.close()


@pytest.fixture
def tel(fake):  # noqa: F811
    return TelFake(fake)


def make(fake, auth=None, vault=None, bearer=None):  # noqa: F811
    stub = mcp_pb2_grpc.McpStub(grpc.insecure_channel(fake.target))
    md = [("ramen-group", "demo"), ("ramen-zone", "local")]
    if bearer is None:
        md = [("authorization", "Bearer good"), *md]
    return bridge.Bridge(stub, md, 5.0, bearer=bearer, telemetry=telemetry.Telemetry(vault or telemetry.Vault()))


def test_report_rides_on_gated_calls_only_with_seq_and_the_recorded_calls(tel, fake):  # noqa: F811
    v = telemetry.Vault()
    v.seal(CFG)
    b = make(fake, vault=v)
    out = run(b, req(1, "ping") + req(2, "tools/list") + req(3, "tools/call", name="add", arguments={"a": 1, "b": 2}))
    lines = [json.loads(x) for x in out.splitlines()]
    assert lines[2]["result"]["content"][0]["text"] == "3"
    assert meta_of(tel.bodies[0]) is None and meta_of(tel.bodies[1]) is None
    rep = meta_of(tel.bodies[2])
    assert rep["version"] == CFG["version"] and rep["seq"] == 1
    assert [(e["kind"], e["name"], e["ok"]) for e in rep["events"]] == [
        ("mcp", "ping", True),
        ("mcp", "tools/list", True),
    ]
    assert all(isinstance(e["ms"], int) and "ts" in e for e in rep["events"])
    # the tools/call itself is reported on the next gated call; seq grows by one per report; nothing twice
    out = run(b, req(4, "nope") + req(5, "resources/read", uri="x://y") + req(6, "prompts/get", name="p"))
    rep5, rep6 = meta_of(tel.bodies[-2]), meta_of(tel.bodies[-1])
    assert rep5["seq"] == 2 and [(e["name"], e["ok"]) for e in rep5["events"]] == [
        ("tools/call add", True),
        ("nope", False),
    ]
    assert rep6["seq"] == 3 and [e["name"] for e in rep6["events"]] == ["resources/read"]
    # the host's own _meta survives next to the report
    run(b, req(7, "tools/call", name="add", arguments={"a": 1, "b": 2}, _meta={"progressToken": "t"}))
    m = json.loads(tel.bodies[-1])["params"]["_meta"]
    assert m["progressToken"] == "t" and m["io.ramen/telemetry"]["seq"] == 4


def test_ramen_report_is_listed_and_handled_locally(tel, fake):  # noqa: F811
    v = telemetry.Vault()
    v.seal(CFG)
    b = make(fake, vault=v)
    tools = json.loads(run(b, req(1, "tools/list")))["result"]["tools"]
    assert [t["name"] for t in tools] == ["add", "ramen_report"]
    spec = tools[1]
    assert set(spec["inputSchema"]["required"]) == {"kind", "name", "ms", "ok"}
    assert "reasoning" in spec["inputSchema"]["properties"] and "before" in spec["description"]
    args = {"kind": "llm", "name": "claude-opus-4", "ms": 850, "ok": True, "reasoning": "chose add for 1+2"}
    out = json.loads(run(b, req(2, "tools/call", name="ramen_report", arguments=args)))
    assert out["result"]["isError"] is False and "recorded" in out["result"]["content"][0]["text"]
    assert len(tel.bodies) == 1, "ramen_report never reaches the worker"
    bad = json.loads(run(b, req(3, "tools/call", name="ramen_report", arguments={"kind": "nope"})))
    assert bad["error"]["code"] == -32602
    run(b, req(4, "tools/call", name="add", arguments={"a": 1, "b": 2}))
    ev = meta_of(tel.bodies[-1])["events"]
    assert [(e["kind"], e["name"]) for e in ev] == [("mcp", "tools/list"), ("llm", "claude-opus-4")]
    assert ev[1]["ms"] == 850 and ev[1]["ok"] is True and ev[1]["reasoning"] == "chose add for 1+2"
    # modern host: the local answer carries resultType
    era = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
    modern = req(5, "tools/call", name="ramen_report", arguments=args, _meta=era)
    assert json.loads(run(b, modern))["result"]["resultType"] == "complete"
    # a paged list is only extended on its last page
    fake.next_cursor = "more"
    assert [t["name"] for t in json.loads(run(b, req(6, "tools/list")))["result"]["tools"]] == ["add"]


def test_stale_version_signs_in_again_and_retries_once(tel, fake, auth_tel):  # noqa: F811
    c = oauth.Client(auth_tel.url, "cid", "mcp:demo:local", opener=auth_tel.browser)
    c.bearer()
    b = make(fake, vault=c.vault, bearer=lambda force=False: c.bearer(force=force, nonblocking=True))
    tel.version = "fedcba987654"  # the console pushed a new config to the workers
    auth_tel.telemetry = {**CFG, "version": "fedcba987654"}
    out = json.loads(run(b, req(1, "tools/call", name="add", arguments={"a": 2, "b": 2})))
    assert out["result"]["content"][0]["text"] == "4"
    assert auth_tel.token_calls[-1]["grant_type"] == "refresh_token"  # refresh first, no browser
    assert len(auth_tel.authorizes) == 1
    reps = [meta_of(x) for x in tel.bodies]
    assert [r["version"] for r in reps] == ["abc123def456", "fedcba987654"] and [r["seq"] for r in reps] == [1, 2]
    assert c.vault.open()["version"] == "fedcba987654"
    # still stale after the retry → the error goes to the host, once
    tel.version = "000000000000"
    out = json.loads(run(b, req(2, "tools/call", name="add", arguments={"a": 2, "b": 2})))
    assert out["error"]["code"] == -32025 and len(tel.bodies) == 4
    # a dead refresh token → the interactive flow; while serving that is -32001 with the URL
    auth_tel.dead_refresh = True
    tel.version = "111111111111"
    opened = []
    c.opener = opened.append
    out = json.loads(run(b, req(3, "tools/call", name="add", arguments={"a": 2, "b": 2})))
    assert out["error"]["code"] == -32001 and opened and "sign_in_url" in out["error"]["data"]


def test_missing_config_signs_in_then_retries_or_adopts_the_version(tel, fake, auth_tel):  # noqa: F811
    auth_tel.telemetry = None
    c = oauth.Client(auth_tel.url, "cid", "mcp:demo:local", opener=auth_tel.browser)
    c.bearer()
    assert c.vault.open() is None
    b = make(fake, vault=c.vault, bearer=lambda force=False: c.bearer(force=force, nonblocking=True))
    auth_tel.telemetry = dict(CFG)  # telemetry was enabled after the first sign-in
    out = json.loads(run(b, req(1, "tools/call", name="add", arguments={"a": 1, "b": 1})))
    assert out["result"]["content"][0]["text"] == "2"
    assert meta_of(tel.bodies[0]) is None and meta_of(tel.bodies[1])["version"] == CFG["version"]
    assert auth_tel.token_calls[-1]["grant_type"] == "refresh_token"
    # with a static key there is no sign-in: the bridge adopts the version the worker named
    k = make(fake)
    out = json.loads(run(k, req(2, "tools/call", name="add", arguments={"a": 1, "b": 1})))
    assert out["result"]["content"][0]["text"] == "2" and meta_of(tel.bodies[-1])["version"] == tel.version
    assert k.telemetry.vault.open() == {"version": tel.version}


def test_events_survive_a_failed_transport_and_nothing_leaks_to_stderr(tel, fake, capsys):  # noqa: F811
    v = telemetry.Vault()
    v.seal(CFG)
    b = make(fake, vault=v)
    run(b, req(1, "ping"))
    b.timeout = 0.2
    fake.delay = 1.0
    assert json.loads(run(b, req(2, "tools/call", name="add", arguments={"a": 1, "b": 1})))["error"]
    fake.delay = 0
    b.timeout = 5.0
    assert json.loads(run(b, req(3, "tools/call", name="add", arguments={"a": 1, "b": 1})))["result"]
    rep = meta_of(next(x for x in tel.bodies if json.loads(x)["id"] == 3))
    assert [e["name"] for e in rep["events"]] == ["ping", "tools/call add"] and rep["seq"] == 2
    err = capsys.readouterr().err
    assert "hunter2" not in err and "collector.example" not in err and "abc123def456" not in err


def test_recorded_ms_is_wall_time(fake):  # noqa: F811
    b = make(fake)
    fake.delay = 0.3
    t0 = time.time()
    run(b, req(1, "ping"))
    ev = b.telemetry.recorder.pending[-1]
    assert 250 <= ev["ms"] <= int((time.time() - t0) * 1000) + 1
