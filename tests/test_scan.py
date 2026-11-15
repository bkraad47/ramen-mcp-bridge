"""SkillSpector policy (bridge 0.6.0, CONTRACTS §30.3 client side): the bundle, the version on calls, `-32027`, and
the local scan with a fake `skillspector` on PATH, all in a temp HOME."""

import json
import os
import stat
import sys
import time

import pytest
from test_bridge import fake, run  # noqa: F401 - fixture
from test_oauth import FakeAS
from test_policy import EVALS, TARGET, home, make, mode  # noqa: F401 - fixture
from test_telemetry import CFG, GATED, req

from ramen_mcp_bridge import bridge, clients, oauth, policy, scan

SS = {"version": "ss0123456789", "required": True, "llm": "", "baseline": "rules:\n  - id: x\n"}
FAKE = """#!{py}
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_SS_LOG"], "a") as f:
    f.write(json.dumps(args) + "\\n")
verdict = os.environ.get("FAKE_SS_VERDICT", "SAFE")
target = args[1]
names = sorted(d for d in os.listdir(target) if os.path.isfile(os.path.join(target, d, "SKILL.md")))
if "--recursive" in args:
    report = {{"risk_recommendation": verdict, "skills_scanned": len(names),
              "skills": [{{"name": n, "path": os.path.join(target, n), "risk_severity": "SAFE" if i else verdict}}
                         for i, n in enumerate(names)]}}
else:
    report = {{"skill_name": os.path.basename(target), "risk_assessment": {{"recommendation": verdict}}}}
text = json.dumps(report)
if "-o" in args:
    open(args[args.index("-o") + 1], "w").write(text)
else:
    print(text)
sys.exit(1 if verdict == "DO_NOT_INSTALL" else 0)
"""


def meta_ss(body: bytes) -> dict | None:
    return (json.loads(body).get("params") or {}).get("_meta", {}).get("io.ramen/skillspector")


@pytest.fixture
def auth_ss():
    a = FakeAS()
    a.telemetry = dict(CFG)
    a.evals = dict(EVALS)
    a.skillspector = dict(SS)
    yield a
    a.close()


@pytest.fixture
def fake_ss(home, monkeypatch, tmp_path):  # noqa: F811
    """A `skillspector` on PATH answering FAKE_SS_VERDICT and logging its arguments."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = bin_dir / "skillspector"
    exe.write_text(FAKE.format(py=sys.executable))
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "ss.log"
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("FAKE_SS_LOG", str(log))
    monkeypatch.delenv("FAKE_SS_VERDICT", raising=False)
    monkeypatch.chdir(tmp_path / "work") if (tmp_path / "work").mkdir() is None else None

    class F:
        path = exe

        @staticmethod
        def calls() -> list[list[str]]:
            return [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []

        @staticmethod
        def verdict(v: str) -> None:
            monkeypatch.setenv("FAKE_SS_VERDICT", v)

    return F


def skill(root, name: str, text: str = "# skill\n"):
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(text)
    return d


class SsFake:
    """A fake worker enforcing §30.3: gated calls name the current skillspector version, else -32027."""

    def __init__(self, fake, version=SS["version"]):  # noqa: F811
        self.inner, self.version, self.bodies = fake, version, []
        fake.hook = self.gate

    def gate(self, msg, md):
        self.bodies.append(json.dumps(msg).encode())
        if msg.get("method") not in GATED:
            return None
        ss = meta_ss(self.bodies[-1])
        if ss is None:
            return {"code": -32027, "message": "skillspector policy required", "data": {"version": self.version}}
        if ss.get("version") != self.version:
            return {
                "code": -32027,
                "message": "skillspector policy changed: sign in again",
                "data": {"version": self.version},
            }
        return None


def test_sign_in_keeps_skillspector_in_the_bundle_and_the_baseline_on_disk(home, auth_ss):  # noqa: F811
    pol = policy.Policy(TARGET, "demo", "local", auth_ss.url)
    c = oauth.Client(auth_ss.url, "cid", "mcp:demo:local", opener=auth_ss.browser)
    c.policy = pol
    assert c.bearer() == "good"
    saved = json.loads(pol.path.read_text())
    assert saved["skillspector"] == {"version": SS["version"], "required": True, "llm": ""}
    base = home / ".ramen" / "skillspector" / "ramen.example.com" / "demo" / "baseline.yaml"
    assert base.read_text() == SS["baseline"] and pol.baseline_file == base
    if os.name == "posix":
        assert mode(base) == "0o600"
    assert pol.skillspector_version() == SS["version"] and "skillspector" not in c.tokens
    assert policy.Policy(TARGET, "demo", "local").load()["skillspector"]["version"] == SS["version"]
    # no baseline → the file goes; no skillspector → None
    auth_ss.skillspector = {"version": "ss9", "required": False, "llm": "openai"}
    c.refresh()
    assert not base.exists() and pol.bundle["skillspector"] == {"version": "ss9", "required": False, "llm": "openai"}
    auth_ss.skillspector = None
    c.refresh()
    assert pol.skillspector_version() is None and pol.bundle["skillspector"] is None
    pol.update(None, None, SS)
    assert base.exists()
    pol.remove_files()
    assert not base.exists() and not pol.path.exists()


def test_every_gated_call_carries_the_skillspector_version(home, fake):  # noqa: F811
    w = SsFake(fake)
    pol = policy.Policy(TARGET, "demo", "local")
    pol.update(CFG, EVALS, SS)
    b = make(fake, pol=pol)
    out = run(b, req(1, "tools/list") + req(2, "tools/call", name="add", arguments={"a": 1, "b": 2}))
    assert json.loads(out.splitlines()[1])["result"]["content"][0]["text"] == "3"
    assert meta_ss(w.bodies[0]) is None and meta_ss(w.bodies[1]) == {"version": SS["version"]}
    m = json.loads(w.bodies[1])["params"]["_meta"]
    assert m["io.ramen/evals"] == {"version": EVALS["version"]}
    # a legacy body (no protocolVersion in _meta) rides the same way; nothing is added without a version
    pol2 = policy.Policy(TARGET, "demo", "local")
    pol2.update(None, None, {"version": "ss1", "required": True, "llm": ""})
    b2 = make(fake, pol=pol2)
    w.version = "ss1"
    run(b2, req(3, "prompts/get", name="p"))
    assert json.loads(w.bodies[-1])["params"]["_meta"] == {"io.ramen/skillspector": {"version": "ss1"}}
    raw = req(4, "prompts/get", name="p")
    assert make(fake)._attach(raw, json.loads(raw)) == raw


def test_32027_signs_in_again_once_and_a_key_adopts(home, fake, auth_ss):  # noqa: F811
    w = SsFake(fake)
    pol = policy.Policy(TARGET, "demo", "local", auth_ss.url)
    c = oauth.Client(auth_ss.url, "cid", "mcp:demo:local", opener=auth_ss.browser)
    c.policy = pol
    c.bearer()
    b = make(fake, pol=pol, vault=c.vault, bearer=lambda force=False: c.bearer(force=force, nonblocking=True))
    w.version = "ss2222222222"
    auth_ss.skillspector = {**SS, "version": "ss2222222222"}
    out = json.loads(run(b, req(1, "tools/call", name="add", arguments={"a": 2, "b": 2})))
    assert out["result"]["content"][0]["text"] == "4"
    assert auth_ss.token_calls[-1]["grant_type"] == "refresh_token" and len(auth_ss.authorizes) == 1
    assert [meta_ss(x)["version"] for x in w.bodies] == [SS["version"], "ss2222222222"]
    assert json.loads(pol.path.read_text())["skillspector"]["version"] == "ss2222222222"
    w.version = "ss3333333333"
    out = json.loads(run(b, req(2, "tools/call", name="add", arguments={"a": 2, "b": 2})))
    assert out["error"]["code"] == -32027 and len(w.bodies) == 4
    # a static key adopts the version the worker named
    w2 = SsFake(fake, "ssk")
    bk = make(fake)
    out = json.loads(run(bk, req(1, "tools/call", name="add", arguments={"a": 1, "b": 1})))
    assert out["result"]["content"][0]["text"] == "2"
    assert meta_ss(w2.bodies[0]) is None and meta_ss(w2.bodies[1]) == {"version": "ssk"}
    assert bk.policy.skillspector_version() == "ssk" and bk.policy.evals_version() is None


def test_compare_and_rule_text_include_skillspector(home):  # noqa: F811
    pol = policy.Policy(TARGET, "demo", "a", "https://c")
    pol.update(None, EVALS, SS)
    cur = {
        "evals": {"version": EVALS["version"], "required": True},
        "skillspector": {"version": "ssX", "required": False},
    }
    assert pol.compare(cur) == ["skillspector version ss0123456789 → ssX", "skillspector required True → False"]
    assert "skillspector" in policy.STALE
    rule = clients.rule_text(pol, ["ramen-mcp-bridge@latest"])
    assert "SkillSpector: required (policy version `ss0123456789`)" in rule and "DO_NOT_INSTALL" in rule
    assert "-32027" in rule
    pol.update(None, EVALS, None)
    assert "SkillSpector: not required" in clients.rule_text(pol, [])


def test_parse_both_report_shapes_and_verdicts():
    agg = {
        "risk_recommendation": "DO_NOT_INSTALL",
        "skills": [
            {"name": "good", "risk_severity": "SAFE"},
            {"name": "meh", "risk_severity": "caution"},
            {"name": "bad", "risk_severity": "Do Not Install"},
            {"path": "/x/noname", "risk_recommendation": "SAFE"},
        ],
    }
    assert scan.parse(agg, "dir") == [
        ("good", "SAFE"),
        ("meh", "CAUTION"),
        ("bad", "DO_NOT_INSTALL"),
        ("noname", "SAFE"),
    ]
    single = {"skill_name": "one", "risk_assessment": {"recommendation": "CAUTION"}}
    assert scan.parse(single, "one") == [("one", "CAUTION")]
    assert scan.parse({"risk_recommendation": "SAFE"}, "d") == [("d", "SAFE")]
    assert scan.parse({}, "d") == [("d", "UNKNOWN")]


def test_scan_dirs_are_the_existing_skill_roots(home, fake_ss, tmp_path):  # noqa: F811
    assert scan.skill_dirs() == []
    skill(home / ".claude" / "skills", "a")
    skill(tmp_path / "work" / ".claude" / "skills", "b")
    (home / ".codex" / "skills").mkdir(parents=True)  # empty: no skills, skipped
    assert scan.skill_dirs() == [home / ".claude" / "skills", tmp_path / "work" / ".claude" / "skills"]


def test_check_clean_caution_block_missing_cached_and_off(home, fake_ss, auth_ss, capsys, monkeypatch):  # noqa: F811
    pol = policy.Policy(TARGET, "demo", "local", auth_ss.url)
    pol.update(CFG, EVALS, SS)
    auth_ss.policy = {
        "telemetry": {"version": CFG["version"], "required": False},
        "evals": {"version": EVALS["version"], "required": True},
        "skillspector": {"version": SS["version"], "required": True},
    }
    # nothing to scan: a clean check
    assert bridge.main(["policy", "check"]) == 0
    assert "up to date" in capsys.readouterr().out and fake_ss.calls() == []
    # clean: two skills, --recursive, no baseline (more than one skill)
    skill(home / ".claude" / "skills", "a")
    skill(home / ".claude" / "skills", "b")
    assert bridge.main(["policy", "check"]) == 0
    out = capsys.readouterr()
    assert "skills: SAFE" in out.err or "SAFE" in out.err
    (call,) = fake_ss.calls()
    assert call[:2] == ["scan", str(home / ".claude" / "skills")] and "--recursive" in call and "--no-llm" in call
    assert "--baseline" not in call and call[call.index("--format") + 1] == "json"
    # cached: the same directory is not scanned again within 24 h; a change is
    assert bridge.main(["policy", "check"]) == 0 and len(fake_ss.calls()) == 1
    caches = list((home / ".ramen" / "scans" / "ramen.example.com").glob("*.json"))
    assert len(caches) == 1
    (home / ".claude" / "skills" / "b" / "SKILL.md").write_text("# changed\n")
    assert bridge.main(["policy", "check"]) == 0 and len(fake_ss.calls()) == 2
    # an expired cache is scanned again
    for p in (home / ".ramen" / "scans" / "ramen.example.com").glob("*.json"):
        d = json.loads(p.read_text())
        d["at"] = time.time() - scan.CACHE_TTL - 1
        p.write_text(json.dumps(d))
    capsys.readouterr()
    assert bridge.main(["policy", "check"]) == 0 and len(fake_ss.calls()) == 3
    # caution: printed, exit 0
    fake_ss.verdict("CAUTION")
    (home / ".claude" / "skills" / "a" / "SKILL.md").write_text("# v2\n")
    assert bridge.main(["policy", "check"]) == 0
    err = capsys.readouterr().err
    assert "CAUTION" in err and "a" in err and scan.BLOCK not in err
    # block: exit 3, the skill named, the message
    fake_ss.verdict("DO_NOT_INSTALL")
    (home / ".claude" / "skills" / "a" / "SKILL.md").write_text("# v3\n")
    assert bridge.main(["policy", "check"]) == 3
    err = capsys.readouterr().err
    assert scan.BLOCK in err and "DO_NOT_INSTALL" in err and str(home / ".claude" / "skills") in err and " a" in err
    # the block is cached too
    assert bridge.main(["policy", "check"]) == 3 and len(fake_ss.calls()) == 5
    # one skill and a baseline: no --recursive, --baseline <file>, the skill directory itself
    fake_ss.verdict("SAFE")
    import shutil

    shutil.rmtree(home / ".claude" / "skills" / "b")
    capsys.readouterr()
    assert bridge.main(["policy", "check"]) == 0
    call = fake_ss.calls()[-1]
    assert call[:2] == ["scan", str(home / ".claude" / "skills" / "a")] and "--recursive" not in call
    assert call[call.index("--baseline") + 1] == str(pol.baseline_file)
    # --no-client-scan: the bundle check only
    (home / ".claude" / "skills" / "a" / "SKILL.md").write_text("# v4\n")
    assert bridge.main(["policy", "check", "--no-client-scan"]) == 0 and len(fake_ss.calls()) == 6
    # not required: no scan either
    pol.update(CFG, EVALS, {**SS, "required": False})
    auth_ss.policy["skillspector"]["required"] = False
    assert bridge.main(["policy", "check"]) == 0 and len(fake_ss.calls()) == 6
    pol.update(CFG, EVALS, SS)
    auth_ss.policy["skillspector"]["required"] = True
    # `show` reports the scan verdict too
    capsys.readouterr()
    assert bridge.main(["policy", "show"]) == 0
    out = capsys.readouterr()
    assert json.loads(out.out)["skillspector"]["version"] == SS["version"] and "SAFE" in out.err
    # missing binary: exit 3 with the install hint
    monkeypatch.setenv("PATH", str(home / "nowhere"))
    (home / ".claude" / "skills" / "a" / "SKILL.md").write_text("# v5\n")
    assert bridge.main(["policy", "check"]) == 3
    err = capsys.readouterr().err
    assert scan.INSTALL_HINT in err and scan.BLOCK in err
    # a scanner that fails (no report) blocks too, uncached
    cached = len(list((home / ".ramen" / "scans" / "ramen.example.com").glob("*.json")))
    fake_ss.path.write_text(f"#!{sys.executable}\nimport sys; sys.exit(2)\n")
    monkeypatch.setenv("PATH", f"{fake_ss.path.parent}{os.pathsep}{home / 'nowhere'}")
    assert bridge.main(["policy", "check"]) == 3
    assert "skillspector failed" in capsys.readouterr().err
    assert len(list((home / ".ramen" / "scans" / "ramen.example.com").glob("*.json"))) == cached


def test_hook_command_carries_no_client_scan_and_replaces_the_old_entry(home):  # noqa: F811
    (home / ".claude").mkdir()
    pol = policy.Policy(TARGET, "demo", "a", "https://c")
    pol.update(None, None, SS)
    clients.install(pol, ["x"])
    hooks = json.loads((home / ".claude" / "settings.json").read_text())["hooks"]["SessionStart"]
    assert len(hooks) == 1 and hooks[0]["hooks"][0]["command"].endswith("--zone a")
    assert hooks[0]["_ramen_policy"] == clients.SKILLSPECTOR_NOTE
    clients.install(pol, ["x"], client_scan=False)
    hooks = json.loads((home / ".claude" / "settings.json").read_text())["hooks"]["SessionStart"]
    assert len(hooks) == 1 and hooks[0]["hooks"][0]["command"].endswith("--zone a --no-client-scan")
    clients.remove(TARGET, "demo", "a")
    assert not (home / ".claude" / "settings.json").exists()  # the bridge created it; emptied again, it goes


def test_main_flag_no_client_scan(monkeypatch):
    a = bridge.parse_args(["--target", "t:1", "--key", "k"])
    assert a.no_client_scan is False
    assert bridge.parse_args(["--target", "t:1", "--key", "k", "--no-client-scan"]).no_client_scan is True
    monkeypatch.setenv("RAMEN_BRIDGE_NO_CLIENT_SCAN", "1")
    assert bridge.parse_args(["--target", "t:1", "--key", "k"]).no_client_scan is True
