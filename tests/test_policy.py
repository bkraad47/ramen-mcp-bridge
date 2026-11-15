"""The policy bundle and the client config files (bridge 0.5.0, CONTRACTS §29.3 client side), in a temp HOME."""

import json
import os
import stat
import sys

import grpc
import pytest
from test_bridge import fake, run  # noqa: F401 - fixture
from test_oauth import FakeAS
from test_telemetry import CFG, GATED, meta_of, req

from ramen_mcp_bridge import bridge, clients, oauth, policy, telemetry
from ramen_proto.ramen.v1 import mcp_pb2_grpc

EVALS = {"version": "ev0123456789", "required": True, "config": "providers:\n  - id: mcp\ntests: []\n"}
TARGET = "ramen.example.com:443"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("APPDATA", raising=False)
    return tmp_path


@pytest.fixture
def auth_pol():
    a = FakeAS()
    a.telemetry = dict(CFG)
    a.evals = dict(EVALS)
    yield a
    a.close()


def evals_of(body: bytes) -> dict | None:
    return (json.loads(body).get("params") or {}).get("_meta", {}).get("io.ramen/evals")


class EvalsFake:
    """A fake worker enforcing §29.3: gated calls name the current evals version, else -32026."""

    def __init__(self, fake, version=EVALS["version"]):  # noqa: F811
        self.inner, self.version, self.bodies = fake, version, []
        fake.hook = self.gate

    def gate(self, msg, md):
        self.bodies.append(json.dumps(msg).encode())
        if msg.get("method") not in GATED:
            return None
        ev = evals_of(self.bodies[-1])
        if ev is None:
            return {"code": -32026, "message": "evals config required", "data": {"version": self.version}}
        if ev.get("version") != self.version:
            return {"code": -32026, "message": "evals config changed: sign in again", "data": {"version": self.version}}
        return None


def mode(p) -> str:
    return oct(stat.S_IMODE(os.stat(p).st_mode))


def test_sign_in_persists_the_bundle_without_headers_and_the_evals_config(home, auth_pol, capsys):
    pol = policy.Policy(TARGET, "demo", "local", auth_pol.url)
    assert pol.load() is None and pol.evals_version() is None
    c = oauth.Client(auth_pol.url, "cid", "mcp:demo:local", opener=auth_pol.browser)
    c.policy = pol
    assert c.bearer() == "good"
    path = home / ".ramen" / "policy" / "ramen.example.com" / "demo-local.json"
    saved = json.loads(path.read_text())
    assert saved["telemetry"] == {"otlp_endpoint": CFG["otlp_endpoint"], "version": CFG["version"]}
    assert saved["evals"] == {"version": EVALS["version"], "required": True}
    assert (saved["target"], saved["group"], saved["zone"], saved["console"]) == (TARGET, "demo", "local", auth_pol.url)
    assert "hunter2" not in path.read_text() and "config" not in saved["evals"]
    cfg = home / ".ramen" / "evals" / "ramen.example.com" / "demo" / "promptfooconfig.yaml"
    assert cfg.read_text() == EVALS["config"]
    if os.name == "posix":
        assert mode(path) == "0o600" and mode(cfg) == "0o600"
        assert mode(path.parent) == "0o700" and mode(home / ".ramen" / "policy") == "0o700"
    assert c.vault.open() == CFG and "evals" not in c.tokens and "telemetry" not in c.tokens
    assert "hunter2" not in capsys.readouterr().err
    # a fresh process loads the bundle; a refresh with a new version rewrites it; no evals → the file goes
    again = policy.Policy(TARGET, "demo", "local")
    assert again.load()["evals"]["version"] == EVALS["version"] and again.evals_version() == EVALS["version"]
    auth_pol.evals = {**EVALS, "version": "ev9999999999"}
    c.refresh()
    assert pol.evals_version() == "ev9999999999" and json.loads(path.read_text())["evals"]["version"] == "ev9999999999"
    auth_pol.evals = None
    c.refresh()
    assert pol.evals_version() is None and not cfg.exists() and json.loads(path.read_text())["evals"] is None


def test_host_of_and_paths():
    assert policy.host_of("ramen.example.com:443") == "ramen.example.com"
    assert policy.host_of("localhost:8080") == "localhost"
    assert policy.host_of("10.0.0.1") == "10.0.0.1"
    assert policy.host_of("we/ird:x") == "we_ird_x"
    assert policy.host_of("") == "unknown"


def make(fake, pol=None, vault=None, bearer=None):  # noqa: F811
    stub = mcp_pb2_grpc.McpStub(grpc.insecure_channel(fake.target))
    md = [("ramen-group", "demo"), ("ramen-zone", "local")]
    if bearer is None:
        md = [("authorization", "Bearer good"), *md]
    return bridge.Bridge(stub, md, 5.0, bearer=bearer, telemetry=telemetry.Telemetry(vault), pol=pol)


def test_every_gated_call_carries_the_evals_version_next_to_the_report(home, fake):  # noqa: F811
    w = EvalsFake(fake)
    pol = policy.Policy(TARGET, "demo", "local")
    pol.update(CFG, EVALS)
    v = telemetry.Vault()
    v.seal(CFG)
    b = make(fake, pol=pol, vault=v)
    out = run(b, req(1, "ping") + req(2, "tools/list") + req(3, "tools/call", name="add", arguments={"a": 1, "b": 2}))
    lines = [json.loads(x) for x in out.splitlines()]
    assert lines[2]["result"]["content"][0]["text"] == "3"
    assert evals_of(w.bodies[0]) is None and evals_of(w.bodies[1]) is None
    assert evals_of(w.bodies[2]) == {"version": EVALS["version"]}
    assert meta_of(w.bodies[2])["version"] == CFG["version"]  # both ride together
    # without telemetry the version still rides; the host's own _meta survives
    b2 = make(fake, pol=pol)
    run(b2, req(4, "resources/read", uri="x://y", _meta={"progressToken": "t"}))
    m = json.loads(w.bodies[-1])["params"]["_meta"]
    assert m["progressToken"] == "t" and m["io.ramen/evals"] == {"version": EVALS["version"]}
    assert "io.ramen/telemetry" not in m
    # nothing is added to a body when the bridge knows neither a version nor a telemetry config
    b3 = make(fake)
    raw = req(5, "prompts/get", name="p")
    assert b3._attach(raw, json.loads(raw)) == raw


def test_32026_signs_in_again_once_and_retries(home, fake, auth_pol):  # noqa: F811
    w = EvalsFake(fake)
    pol = policy.Policy(TARGET, "demo", "local", auth_pol.url)
    c = oauth.Client(auth_pol.url, "cid", "mcp:demo:local", opener=auth_pol.browser)
    c.policy = pol
    c.bearer()
    b = make(fake, pol=pol, vault=c.vault, bearer=lambda force=False: c.bearer(force=force, nonblocking=True))
    # the console pushed a new evals config to the workers
    w.version = "ev2222222222"
    auth_pol.evals = {**EVALS, "version": "ev2222222222"}
    out = json.loads(run(b, req(1, "tools/call", name="add", arguments={"a": 2, "b": 2})))
    assert out["result"]["content"][0]["text"] == "4"
    assert auth_pol.token_calls[-1]["grant_type"] == "refresh_token" and len(auth_pol.authorizes) == 1
    assert [evals_of(x)["version"] for x in w.bodies] == [EVALS["version"], "ev2222222222"]
    assert pol.evals_version() == "ev2222222222"
    assert json.loads(pol.path.read_text())["evals"]["version"] == "ev2222222222"
    # the telemetry report is not spent on the refused attempt: seq grows by one per delivered call
    reps = [meta_of(x) for x in w.bodies]
    assert [r["seq"] for r in reps] == [1, 2]
    # still stale after the retry → the error goes to the host, once
    w.version = "ev3333333333"
    out = json.loads(run(b, req(2, "tools/call", name="add", arguments={"a": 2, "b": 2})))
    assert out["error"]["code"] == -32026 and len(w.bodies) == 4
    # a dead refresh token → the interactive flow; while serving that is -32001 with the URL
    auth_pol.dead_refresh = True
    opened = []
    c.opener = opened.append
    out = json.loads(run(b, req(3, "tools/call", name="add", arguments={"a": 2, "b": 2})))
    assert out["error"]["code"] == -32001 and opened and "sign_in_url" in out["error"]["data"]


def test_a_static_key_adopts_the_version_the_worker_named(home, fake):  # noqa: F811
    w = EvalsFake(fake)
    b = make(fake)
    out = json.loads(run(b, req(1, "tools/call", name="add", arguments={"a": 1, "b": 1})))
    assert out["result"]["content"][0]["text"] == "2"
    assert evals_of(w.bodies[0]) is None and evals_of(w.bodies[1]) == {"version": EVALS["version"]}
    assert b.policy.evals_version() == EVALS["version"] and b.policy.path is None  # nothing written for a key


def test_start_without_a_bundle_and_no_way_to_sign_in_exits_3(home, monkeypatch, capsys):
    monkeypatch.setattr(bridge, "channel", lambda a: None)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False, raising=False)
    args = ["--target", TARGET, "--tls", "--oauth", "https://c", "--client-id", "cid", "--group", "demo", "--zone", "a"]
    assert bridge.main([*args, "--no-browser"]) == 3
    assert policy.MISSING in capsys.readouterr().err
    # a bundle from an earlier sign-in: the bridge may start and sign in lazily — here the fake sign-in fails → 2
    policy.Policy(TARGET, "demo", "a", "https://c").update(None, EVALS)

    class NoSignIn:
        tokens = None

        def __init__(self, *a, **k):
            self.policy = None

        def bearer(self, **k):
            raise oauth.OAuthError("x")

    monkeypatch.setattr(oauth, "Client", NoSignIn)
    assert bridge.main(args) == 2
    assert "ramen-mcp-bridge: x" in capsys.readouterr().err
    # a refresh token makes a sign-in possible even with --no-browser and no terminal
    policy.Policy(TARGET, "demo", "a", "https://c").remove_files()
    NoSignIn.tokens = {"refresh_token": "r"}
    assert bridge.main([*args, "--no-browser"]) == 3  # the stub still fails to sign in; but the path was tried
    assert "ramen-mcp-bridge: x" in capsys.readouterr().err


def test_main_signs_in_keeps_the_bundle_and_writes_the_client_files(home, fake, auth_pol, monkeypatch):  # noqa: F811
    import io

    (home / ".claude").mkdir()
    (home / ".cursor").mkdir()
    code = clients.vscode_user_dir()
    code.mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text(json.dumps({"theme": "dark", "hooks": {"Stop": [{"hooks": []}]}}))
    (code / "settings.json").write_text(json.dumps({"editor.fontSize": 14, "mcp": {"servers": {"other": {"x": 1}}}}))
    monkeypatch.setattr(oauth.webbrowser, "open", auth_pol.browser)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(req(1, "ping"))))
    out = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(out))
    args = [
        "--target",
        fake.target,
        "--oauth",
        auth_pol.url,
        "--client-id",
        "cid",
        "--group",
        "demo",
        "--zone",
        "local",
    ]
    assert bridge.main(args) == 0
    assert json.loads(out.getvalue())["result"] == {}
    host = policy.host_of(fake.target)
    bundle = json.loads((home / ".ramen" / "policy" / host / "demo-local.json").read_text())
    assert bundle["evals"]["version"] == EVALS["version"] and bundle["console"] == auth_pol.url
    cmd = f"ramen-mcp-bridge policy check --target {fake.target} --group demo --zone local"
    claude = json.loads((home / ".claude" / "settings.json").read_text())
    assert claude["theme"] == "dark" and claude["hooks"]["Stop"] == [{"hooks": []}]
    assert claude["hooks"]["SessionStart"] == [
        {"matcher": "", "hooks": [{"type": "command", "command": cmd}], "_ramen": True}
    ]
    rule = (home / ".cursor" / "rules" / "ramen-demo-local.mdc").read_text()
    assert rule.startswith("---\n") and "alwaysApply: true" in rule and "# ramen" in rule
    assert "Telemetry: not required" in rule and f"Evals: required (config version `{EVALS['version']}`)" in rule
    assert f"--target {fake.target}" in rule and "--oauth" in rule
    vs = json.loads((code / "settings.json").read_text())
    assert vs["editor.fontSize"] == 14 and vs["mcp"]["servers"]["other"] == {"x": 1}
    entry = vs["mcp"]["servers"]["ramen-demo-local"]
    assert entry["command"] == "uvx" and entry["_ramen"] is True
    assert entry["args"] == [
        "ramen-mcp-bridge@latest",
        "--target",
        fake.target,
        "--oauth",
        auth_pol.url,
        "--client-id",
        "cid",
        "--group",
        "demo",
        "--zone",
        "local",
    ]
    ledger = json.loads((home / ".ramen" / "clients.json").read_text())["entries"]
    assert sorted(e["kind"] for e in ledger) == ["claude_code", "cursor", "vscode"]
    # --no-client-config: the bundle only
    for p in (home / ".claude" / "settings.json", code / "settings.json"):
        p.write_text("{}")
    (home / ".cursor" / "rules" / "ramen-demo-local.mdc").unlink()
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(req(1, "ping"))))
    assert bridge.main([*args, "--no-client-config"]) == 0
    assert json.loads((home / ".claude" / "settings.json").read_text()) == {}
    assert not (home / ".cursor" / "rules" / "ramen-demo-local.mdc").exists()


def test_client_files_are_merged_idempotently_and_removed_exactly(home):
    (home / ".claude").mkdir()
    (home / ".cursor").mkdir()
    code = clients.vscode_user_dir()
    code.mkdir(parents=True)
    claude_path, vs_path = home / ".claude" / "settings.json", code / "settings.json"
    other_hook = {"matcher": "", "hooks": [{"type": "command", "command": "echo hi"}]}
    claude_path.write_text(json.dumps({"permissions": {"allow": ["Bash"]}, "hooks": {"SessionStart": [other_hook]}}))
    vs_path.write_text(json.dumps({"mcp": {"servers": {"mine": {"command": "x"}}}, "window.zoomLevel": 1}))
    pol = policy.Policy(TARGET, "demo", "a", "https://console.example")
    pol.update({"version": "t1", "required": True, "headers": {"k": "v"}}, EVALS)
    uvx = ["ramen-mcp-bridge@latest", "--target", TARGET, "--tls"]
    first = clients.install(pol, uvx)
    second = clients.install(pol, uvx)
    assert [e["kind"] for e in first] == ["claude_code", "cursor", "vscode"] and first == second
    claude = json.loads(claude_path.read_text())
    assert claude["permissions"] == {"allow": ["Bash"]}
    assert claude["hooks"]["SessionStart"][0] == other_hook and len(claude["hooks"]["SessionStart"]) == 2
    assert claude["hooks"]["SessionStart"][1]["_ramen"] is True
    assert "policy check --target ramen.example.com:443 --group demo --zone a" in json.dumps(claude)
    vs = json.loads(vs_path.read_text())
    assert vs["window.zoomLevel"] == 1 and set(vs["mcp"]["servers"]) == {"mine", "ramen-demo-a"}
    rule = (home / ".cursor" / "rules" / "ramen-demo-a.mdc").read_text()
    assert "Telemetry: required (config version `t1`)" in rule and "k" not in json.dumps(pol.bundle["telemetry"])
    assert len(json.loads((home / ".ramen" / "clients.json").read_text())["entries"]) == 3
    # a second zone adds its own entries; removing the first leaves the second and every foreign key alone
    pol_b = policy.Policy(TARGET, "demo", "b", "https://console.example")
    pol_b.update(None, None)
    clients.install(pol_b, uvx)
    assert len(json.loads(claude_path.read_text())["hooks"]["SessionStart"]) == 3
    reverted = clients.remove(TARGET, "demo", "a")
    assert sorted(e["kind"] for e in reverted) == ["claude_code", "cursor", "vscode"]
    claude = json.loads(claude_path.read_text())
    assert claude["hooks"]["SessionStart"][0] == other_hook and len(claude["hooks"]["SessionStart"]) == 2
    assert "--zone a" not in json.dumps(claude) and "--zone b" in json.dumps(claude)
    vs = json.loads(vs_path.read_text())
    assert set(vs["mcp"]["servers"]) == {"mine", "ramen-demo-b"} and vs["window.zoomLevel"] == 1
    assert not (home / ".cursor" / "rules" / "ramen-demo-a.mdc").exists()
    assert (home / ".cursor" / "rules" / "ramen-demo-b.mdc").exists()
    ledger = json.loads((home / ".ramen" / "clients.json").read_text())["entries"]
    assert {e["zone"] for e in ledger} == {"b"}
    clients.remove(TARGET, "demo", "b")
    assert not (home / ".ramen" / "clients.json").exists()
    assert "SessionStart" in json.loads(claude_path.read_text())["hooks"]  # the foreign hook stays
    # a settings file with comments is left alone, with a warning, and never clobbered
    vs_path.write_text('{\n  // my settings\n  "a": 1,\n}\n')
    out = clients.install(pol, uvx)
    assert [e["kind"] for e in out] == ["claude_code", "cursor"]
    assert vs_path.read_text().startswith("{\n  // my settings")
    # editors that are not installed get nothing
    clients.remove(TARGET, "demo", "a")
    import shutil

    shutil.rmtree(home / ".cursor")
    shutil.rmtree(code)
    assert [e["kind"] for e in clients.install(pol, uvx)] == ["claude_code"]


def test_policy_cli_show_check_remove(home, auth_pol, capsys):
    assert bridge.main(["policy", "show"]) == 2
    assert policy.MISSING in capsys.readouterr().err
    pol = policy.Policy(TARGET, "demo", "local", auth_pol.url)
    pol.update(CFG, EVALS)
    (home / ".cursor").mkdir()
    clients.install(pol, ["ramen-mcp-bridge@latest"])
    # show: the bundle, no headers, found without flags when it is the only one
    assert bridge.main(["policy", "show"]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["evals"]["version"] == EVALS["version"] and "headers" not in shown["telemetry"]
    # check against the console's public policy
    auth_pol.policy = {
        "telemetry": {"version": CFG["version"], "required": False},
        "evals": {"version": EVALS["version"], "required": True},
    }
    flags = ["--target", TARGET, "--group", "demo", "--zone", "local"]
    assert bridge.main(["policy", "check", *flags]) == 0
    assert "up to date" in capsys.readouterr().out
    assert auth_pol.policy_queries[-1] == {"group": "demo", "zone": "local"}
    auth_pol.policy["evals"]["version"] = "ev5555555555"
    assert bridge.main(["policy", "check", *flags]) == 2
    err = capsys.readouterr().err
    assert policy.STALE in err and "evals version ev0123456789 → ev5555555555" in err
    auth_pol.policy = {
        "telemetry": {"version": CFG["version"]},
        "evals": {"version": EVALS["version"], "required": False},
    }
    assert bridge.main(["policy", "check"]) == 2
    assert "evals required True → False" in capsys.readouterr().err
    # the console unreachable: 1, not a stale verdict
    pol.bundle["console"] = "http://127.0.0.1:1"
    policy.write_private(pol.path, json.dumps(pol.bundle))
    assert bridge.main(["policy", "check"]) == 1
    assert "cannot read" in capsys.readouterr().err
    # two bundles need the flags; the wrong flags find nothing
    policy.Policy(TARGET, "demo", "b", auth_pol.url).update(None, None)
    assert bridge.main(["policy", "show"]) == 1
    assert "2 bundles" in capsys.readouterr().err
    assert bridge.main(["policy", "show", "--target", TARGET, "--group", "demo", "--zone", "zzz"]) == 2
    assert bridge.main(["policy", "show", "--zone", "b"]) == 0
    capsys.readouterr()
    # remove: the client files reverted, the bundle and the evals config gone
    rule = home / ".cursor" / "rules" / "ramen-demo-local.mdc"
    assert rule.exists()
    assert bridge.main(["policy", "remove", *flags]) == 0
    err = capsys.readouterr().err
    assert "reverted cursor" in err and "removed the policy bundle" in err
    assert not rule.exists() and not pol.path.exists() and not pol.evals_file.exists()
    assert bridge.main(["policy", "show", *flags]) == 2


def test_vscode_user_dir_per_platform(home, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    assert clients.vscode_user_dir() == home / "Library" / "Application Support" / "Code" / "User"
    monkeypatch.setattr(sys, "platform", "linux")
    assert clients.vscode_user_dir() == home / ".config" / "Code" / "User"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "xdg"))
    assert clients.vscode_user_dir() == home / "xdg" / "Code" / "User"
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    assert clients.vscode_user_dir() == home / "AppData" / "Roaming" / "Code" / "User"
