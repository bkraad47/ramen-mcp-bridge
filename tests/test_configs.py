"""Group LLM configs and telemetry targets (bridge 0.6.0, CONTRACTS §31.3 client side): the bundle, the consent wait,
the version on calls, `-32028`, every format / merge in a temp HOME, the OTel targets, check / show / remove."""

import base64
import json
import os
import sys

import pytest
from test_bridge import fake, run  # noqa: F401 - fixture
from test_oauth import FakeAS
from test_policy import EVALS, TARGET, home, make, mode  # noqa: F401 - fixture
from test_telemetry import CFG, GATED, req

from ramen_mcp_bridge import bridge, clients, configs, oauth, policy

MANIFEST = """version: 1
description: demo configs
targets:
  - {client: claude-code, file: claude.json, path: ~/.claude/settings.json, format: json, merge: deep}
  - {client: codex, file: codex.toml, path: ~/.codex/config.toml, format: toml, merge: deep}
  - {client: gemini-cli, file: gemini.yaml, path: "~/.gemini/{group}.yaml", format: yaml, merge: deep}
  - {client: claude-code, file: CLAUDE.md, path: ~/.claude/CLAUDE.md, format: text, merge: block}
  - {client: cursor, file: rule.mdc, path: "~/.cursor/rules/ramen-{group}-{zone}-{host}.mdc",
     format: text, merge: replace}
  - {client: env, file: ramen.env, path: "~/.ramen/{group}.env", format: env, merge: keys}
  - {client: notes, file: notes.txt, path: ~/notes.txt, format: text, merge: block}
"""
FILES = {
    "claude.json": json.dumps(
        {
            "permissions": {"allow": ["Bash(git:*)"]},
            "env": {"RAMEN_GROUP": "${RAMEN_GROUP}", "RAMEN_USER": "${RAMEN_USER}"},
            "model": "opus",
        }
    ),
    "codex.toml": 'model = "o3"\n[sandbox]\nmode = "strict"\n',
    "gemini.yaml": "theme: dark\nhost: ${RAMEN_HOST}\n",
    "CLAUDE.md": "Use the ${RAMEN_GROUP} tools first.\n",
    "rule.mdc": "---\nalwaysApply: true\n---\nRamen group ${RAMEN_GROUP} on ${RAMEN_HOST}.\n",
    "ramen.env": "RAMEN_GROUP=${RAMEN_GROUP}\nexport RAMEN_ENDPOINT=${RAMEN_OTLP_ENDPOINT}\n",
    "notes.txt": "line from ramen\n",
}
CF = {"version": "cf0123456789", "required": True, "accepted": True, "manifest": MANIFEST, "files": FILES}
TOKEN = "tok-s3cr3t-9f8e7d"
TEL = {"version": "t1", "required": True, "headers": {"k": "v"}, "otlp_endpoint": "http://col:4318"}


def jwt(email: str) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"email": email, "sub": "u1"}).encode()).rstrip(b"=").decode()
    return f"eyJhbGciOiJIUzI1NiJ9.{payload}.sig"


def meta_cf(body: bytes) -> dict | None:
    return (json.loads(body).get("params") or {}).get("_meta", {}).get("io.ramen/configs")


@pytest.fixture
def auth_cf():
    a = FakeAS()
    a.telemetry = dict(CFG)
    a.evals = dict(EVALS)
    a.configs = dict(CF)
    yield a
    a.close()


class CfFake:
    """A fake worker enforcing §31.2: gated calls name the current configs version, else -32028."""

    def __init__(self, fake, version=CF["version"]):  # noqa: F811
        self.inner, self.version, self.bodies = fake, version, []
        fake.hook = self.gate

    def gate(self, msg, md):
        self.bodies.append(json.dumps(msg).encode())
        if msg.get("method") not in GATED:
            return None
        cf = meta_cf(self.bodies[-1])
        if cf is None:
            return {"code": -32028, "message": "configs required", "data": {"version": self.version}}
        if cf.get("version") != self.version:
            return {"code": -32028, "message": "configs changed: sign in again", "data": {"version": self.version}}
        return None


def ledger_text(home) -> str:  # noqa: F811
    p = home / ".ramen" / "clients.json"
    return p.read_text() if p.exists() else ""


def entries(home):  # noqa: F811
    return [e for e in json.loads(ledger_text(home) or '{"entries": []}')["entries"] if e["kind"] == "configs"]


def test_sign_in_keeps_configs_in_the_bundle_and_the_files_on_disk(home, auth_cf):  # noqa: F811
    pol = policy.Policy(TARGET, "demo", "local", auth_cf.url)
    c = oauth.Client(auth_cf.url, "cid", "mcp:demo:local", opener=auth_cf.browser)
    c.policy = pol
    assert c.bearer() == "good"
    saved = json.loads(pol.path.read_text())
    assert saved["configs"] == {"version": CF["version"], "required": True, "accepted": True}
    assert "manifest" not in pol.path.read_text() and "configs" not in c.tokens
    d = home / ".ramen" / "configs" / "ramen.example.com" / "demo"
    assert pol.configs_dir == d and (d / "manifest.yaml").read_text() == MANIFEST
    assert sorted(p.name for p in d.iterdir()) == sorted(["manifest.yaml", *FILES])
    assert (d / "claude.json").read_text() == FILES["claude.json"]
    if os.name == "posix":
        assert mode(d / "manifest.yaml") == "0o600" and mode(d / "CLAUDE.md") == "0o600"
    assert pol.configs_version() == CF["version"] and pol.configs_accepted() and not pol.configs_pending()
    assert pol.token == "good" and pol.user == ""  # not a JWT: no name to label telemetry with
    assert policy.Policy(TARGET, "demo", "local").load()["configs"]["version"] == CF["version"]
    # a new version replaces the directory (dropped files go); no configs → the directory goes, the bundle says None
    auth_cf.configs = {**CF, "version": "cf2", "files": {"claude.json": "{}"}}
    c.refresh()
    assert sorted(p.name for p in d.iterdir()) == ["claude.json", "manifest.yaml"]
    assert pol.configs_version() == "cf2"
    auth_cf.configs = None
    c.refresh()
    assert not d.exists() and pol.bundle["configs"] is None and pol.configs_version() is None
    # compare and the stale text know configs
    pol.update(None, None, None, CF)
    assert pol.compare({"configs": {"version": "cfX", "required": True}}) == ["configs version cf0123456789 → cfX"]
    assert "configs" in policy.STALE
    pol.remove_files()
    assert not d.exists()


def test_unaccepted_configs_open_the_console_page_and_wait(home, auth_cf, capsys):  # noqa: F811
    auth_cf.configs = {**CF, "accepted": False}
    (home / ".claude").mkdir()
    opened: list[str] = []

    def opener(url: str) -> None:
        opened.append(url)
        if "/configs?" in url:
            auth_cf.configs = dict(CF)  # the person accepts in the browser; the next token answer says so
        else:
            auth_cf.browser(url)

    pol = policy.Policy(TARGET, "demo", "local", auth_cf.url)
    pol.on_update = configs.apply
    c = oauth.Client(auth_cf.url, "cid", "mcp:demo:local", opener=opener, consent_poll=0.05)
    c.policy = pol
    assert c.bearer() == "good"
    assert len(opened) == 2 and opened[1] == f"{auth_cf.url}/groups/demo/configs?next=/groups/demo"
    assert auth_cf.token_calls[-1]["grant_type"] == "refresh_token" and len(auth_cf.authorizes) == 1
    assert pol.configs_accepted() and f"accept the group's configs at {opened[1]}" in capsys.readouterr().err
    assert (home / ".claude" / "settings.json").exists()  # written once accepted, not before
    # never accepted: a bounded wait, a clear message, nothing written; while serving: the URL for the client
    auth_cf.configs = {**CF, "version": "cf9", "accepted": False}
    pol2 = policy.Policy(TARGET, "demo", "local", auth_cf.url)
    seen: list[str] = []

    def no_accept(url: str) -> None:
        seen.append(url)
        if "/configs?" not in url:
            auth_cf.browser(url)

    c2 = oauth.Client(auth_cf.url, "cid", "mcp:demo:local", opener=no_accept)
    c2.policy = pol2
    c2.login_timeout, c2.consent_poll = 0.3, 0.05
    with pytest.raises(oauth.OAuthError, match="not accepted within 0 s: open .*configs"):
        c2.bearer()
    assert seen[-1].endswith("/groups/demo/configs?next=/groups/demo") and len(seen) == 2
    with pytest.raises(oauth.SignInRequired) as e:
        c2.bearer(nonblocking=True)
    assert e.value.url == seen[-1] and len(seen) == 2  # the page is opened once per pending version
    assert pol2.configs_pending() and pol2.configs_version() == "cf9"


def test_every_gated_call_carries_the_configs_version_and_32028_signs_in_again(home, fake, auth_cf):  # noqa: F811
    w = CfFake(fake)
    pol = policy.Policy(TARGET, "demo", "local", auth_cf.url)
    c = oauth.Client(auth_cf.url, "cid", "mcp:demo:local", opener=auth_cf.browser)
    c.policy = pol
    c.bearer()
    b = make(fake, pol=pol, vault=c.vault, bearer=lambda force=False: c.bearer(force=force, nonblocking=True))
    out = run(b, req(1, "tools/list") + req(2, "tools/call", name="add", arguments={"a": 1, "b": 2}))
    assert json.loads(out.splitlines()[1])["result"]["content"][0]["text"] == "3"
    assert meta_cf(w.bodies[0]) is None and meta_cf(w.bodies[1]) == {"version": CF["version"]}
    assert json.loads(w.bodies[1])["params"]["_meta"]["io.ramen/evals"] == {"version": EVALS["version"]}
    # a new version on the workers: one re-sign-in (refresh), the call retried
    w.version = "cf2222222222"
    auth_cf.configs = {**CF, "version": "cf2222222222"}
    out = json.loads(run(b, req(3, "tools/call", name="add", arguments={"a": 2, "b": 2})))
    assert out["result"]["content"][0]["text"] == "4"
    assert auth_cf.token_calls[-1]["grant_type"] == "refresh_token" and len(auth_cf.authorizes) == 1
    assert [meta_cf(x)["version"] for x in w.bodies[2:]] == [CF["version"], "cf2222222222"]
    assert json.loads(pol.path.read_text())["configs"]["version"] == "cf2222222222"
    w.version = "cf3333333333"
    out = json.loads(run(b, req(4, "tools/call", name="add", arguments={"a": 2, "b": 2})))
    assert out["error"]["code"] == -32028 and len(w.bodies) == 6
    # a static key adopts the version the worker named; nothing is written for a key
    w2 = CfFake(fake, "cfk")
    bk = make(fake)
    out = json.loads(run(bk, req(1, "tools/call", name="add", arguments={"a": 1, "b": 1})))
    assert out["result"]["content"][0]["text"] == "2"
    assert meta_cf(w2.bodies[0]) is None and meta_cf(w2.bodies[1]) == {"version": "cfk"}
    assert bk.policy.configs_version() == "cfk" and bk.policy.path is None
    raw = req(5, "prompts/get", name="p")
    assert make(fake)._attach(raw, json.loads(raw)) == raw


def seed(home):  # noqa: F811
    """A machine with its own files where the manifest's targets land."""
    (home / ".claude").mkdir()
    (home / ".codex").mkdir()
    (home / ".cursor" / "rules").mkdir(parents=True)
    (home / ".ramen").mkdir()
    (home / ".claude" / "settings.json").write_text(
        json.dumps({"theme": "dark", "permissions": {"allow": ["Read"], "deny": ["x"]}, "env": {"MINE": "1"}})
    )
    (home / ".codex" / "config.toml").write_text('model = "gpt"\n\n[sandbox]\nmode = "loose"\nnetwork = true\n')
    (home / ".claude" / "CLAUDE.md").write_text("# Mine\n\nkeep me\n")
    (home / ".cursor" / "rules" / "ramen-demo-a-ramen.example.com.mdc").write_text("old rule\n")
    (home / ".ramen" / "demo.env").write_text("MINE=1\nRAMEN_GROUP=old\n")
    return {p: p.read_bytes() for p in home.rglob("*") if p.is_file()}


def test_apply_every_format_and_merge_idempotently_then_restore(home, capsys):  # noqa: F811
    original = seed(home)
    pol = policy.Policy(TARGET, "demo", "a", "https://c")
    pol.update(None, None, None, CF, token=TOKEN, user="ada@example.com")
    done = configs.apply(pol)
    assert [e["client"] for e in done] == [
        "claude-code",
        "codex",
        "gemini-cli",
        "claude-code",
        "cursor",
        "env",
        "notes",
    ]
    # json deep: Ramen's keys win, the user's others stay, placeholders filled
    claude = json.loads((home / ".claude" / "settings.json").read_text())
    assert claude == {
        "theme": "dark",
        "permissions": {"allow": ["Bash(git:*)"], "deny": ["x"]},
        "env": {"MINE": "1", "RAMEN_GROUP": "demo", "RAMEN_USER": "ada@example.com"},
        "model": "opus",
    }
    # toml deep
    import tomllib

    codex = tomllib.loads((home / ".codex" / "config.toml").read_text())
    assert codex == {"model": "o3", "sandbox": {"mode": "strict", "network": True}}
    # yaml deep into a file (and directory) that did not exist; {group} and {host} in the path and the text
    import yaml

    assert yaml.safe_load((home / ".gemini" / "demo.yaml").read_text()) == {
        "theme": "dark",
        "host": "ramen.example.com",
    }
    # text block in Markdown: the HTML markers, appended after the user's text
    md = (home / ".claude" / "CLAUDE.md").read_text()
    assert md == "# Mine\n\nkeep me\n<!-- ramen:demo -->\nUse the demo tools first.\n<!-- /ramen -->\n"
    # replace: the whole file is Ramen's; env keys: replaced by key in place, missing ones appended
    rule = home / ".cursor" / "rules" / "ramen-demo-a-ramen.example.com.mdc"
    assert rule.read_text() == "---\nalwaysApply: true\n---\nRamen group demo on ramen.example.com.\n"
    env = (home / ".ramen" / "demo.env").read_text()
    assert env == "MINE=1\nRAMEN_GROUP=demo\nexport RAMEN_ENDPOINT=https://c/otlp\n"
    # a plain text block in a new file: the `#` markers
    assert (home / "notes.txt").read_text() == "# ramen:demo\nline from ramen\n# /ramen\n"
    # idempotent: a second apply changes no byte and no ledger entry
    after = {p: p.read_bytes() for p in home.rglob("*") if p.is_file()}
    ledger = ledger_text(home)
    assert configs.apply(pol) == done
    assert {p: p.read_bytes() for p in home.rglob("*") if p.is_file()} == after and ledger_text(home) == ledger
    assert configs.verify(pol) == [] and configs.check(pol) == 0
    recorded = entries(home)
    assert len(recorded) == 7 and all(e["version"] == CF["version"] and e["hash"] for e in recorded)
    assert TOKEN not in ledger and "ada@example.com" not in json.dumps([e.get("snapshot") for e in recorded])
    assert [e["merge"] for e in recorded] == ["deep", "deep", "deep", "block", "replace", "keys", "block"]
    assert not [line for line in configs.show(pol) if not line.startswith("ok ")]
    # the user's own later edits do not count as a change; a removed Ramen key or block does
    claude["theme"] = "light"
    (home / ".claude" / "settings.json").write_text(json.dumps(claude))
    (home / ".claude" / "CLAUDE.md").write_text(md + "\nmore of mine\n")
    assert configs.verify(pol) == []
    del claude["env"]["RAMEN_USER"]
    (home / ".claude" / "settings.json").write_text(json.dumps(claude))
    (home / ".claude" / "CLAUDE.md").write_text("# Mine\n\nkeep me\n\nmore of mine\n")
    (home / "notes.txt").unlink()
    broken = configs.verify(pol)
    assert broken == [
        str(home / ".claude" / "settings.json"),
        str(home / ".claude" / "CLAUDE.md"),
        str(home / "notes.txt"),
    ]
    assert configs.check(pol) == 3
    err = capsys.readouterr().err
    assert configs.REMOVED in err and str(home / "notes.txt") in err
    shown = configs.show(pol)
    assert (
        sum(line.startswith("CHANGED") for line in shown) == 3 and "(json/deep, claude-code vcf0123456789)" in shown[0]
    )
    # applied again (a re-sign-in does this): back in place, the user's edits kept, the snapshot untouched
    configs.apply(pol)
    assert configs.verify(pol) == []
    assert json.loads((home / ".claude" / "settings.json").read_text())["theme"] == "light"
    assert (
        (home / ".claude" / "CLAUDE.md")
        .read_text()
        .endswith("more of mine\n<!-- ramen:demo -->\nUse the demo tools first.\n<!-- /ramen -->\n")
    )
    # remove: byte-for-byte where Ramen owned the file or a block and nothing else moved; Ramen's keys gone and the
    # prior values back where it merged; files Ramen created are deleted; the user's later edits stay
    (home / ".claude" / "CLAUDE.md").write_text(md)
    reverted = clients.remove(TARGET, "demo", "a")
    assert len(reverted) == 7 and entries(home) == []
    for p in (rule, home / ".ramen" / "demo.env", home / ".claude" / "CLAUDE.md", home / ".codex" / "config.toml"):
        assert p.read_bytes() == original[p] or p == home / ".codex" / "config.toml", p
    assert tomllib.loads((home / ".codex" / "config.toml").read_text()) == {
        "model": "gpt",
        "sandbox": {"mode": "loose", "network": True},
    }
    assert json.loads((home / ".claude" / "settings.json").read_text()) == {
        "theme": "light",
        "permissions": {"allow": ["Read"], "deny": ["x"]},
        "env": {"MINE": "1"},
    }
    assert not (home / ".gemini" / "demo.yaml").exists() and not (home / "notes.txt").exists()
    # a block removed from a file the user edited after: only the block goes
    configs.apply(pol)
    (home / ".claude" / "CLAUDE.md").write_text((home / ".claude" / "CLAUDE.md").read_text() + "\nlater\n")
    clients.remove(TARGET, "demo", "a")
    assert (home / ".claude" / "CLAUDE.md").read_text() == "# Mine\n\nkeep me\n\nlater\n"


def test_targets_that_cannot_be_written_are_skipped_with_a_note(home, capsys):  # noqa: F811
    (home / ".claude").mkdir()
    (home / ".claude" / "settings.json").write_text('{\n  // mine\n  "a": 1\n}\n')
    manifest = (
        "version: 1\ntargets:\n"
        "  - {client: a, file: claude.json, path: ~/.claude/settings.json, format: json, merge: deep}\n"
        "  - {client: b, file: x.txt, path: ~/x.txt, format: text, merge: deep}\n"
        "  - {client: c, file: y.ini, path: ~/y.ini, format: ini, merge: replace}\n"
        "  - {client: d, file: gone.txt, path: ~/gone.txt, format: text, merge: replace}\n"
        "  - {client: e, path: ~/z.txt, format: text, merge: replace}\n"
        "  - {client: f, file: bad.json, path: ~/bad.json, format: json, merge: deep}\n"
        "  - {client: g, file: ok.env, path: ~/ok.env, format: env, merge: keys}\n"
    )
    files = {"claude.json": "{}", "x.txt": "x", "y.ini": "y", "bad.json": "{nope", "ok.env": "A=1\nnot a line\nB=2\n"}
    pol = policy.Policy(TARGET, "demo", "a", "https://c")
    pol.update(None, None, None, {**CF, "manifest": manifest, "files": files}, token=TOKEN)
    done = configs.apply(pol)
    assert [e["client"] for e in done] == ["g"]
    assert (home / "ok.env").read_text() == "A=1\nB=2\n"
    err = capsys.readouterr().err
    assert "not plain json" in err and "does not fit format" in err and "unknown format 'ini'" in err
    assert "gone.txt is missing" in err and "incomplete" in err and "does not parse" in err and "dropped" in err
    assert (home / ".claude" / "settings.json").read_text().startswith("{\n  // mine")
    assert not (home / "x.txt").exists() and not (home / "y.ini").exists() and not (home / "bad.json").exists()
    # helpers
    assert configs.user_of(jwt("ada@example.com")) == "ada@example.com"
    assert configs.user_of("good") == "" and configs.user_of(None) == ""
    assert (
        configs.consent_url("https://c/", "my group") == "https://c/groups/my%20group/configs?next=/groups/my%20group"
    )
    assert configs.with_block("", "# ramen:g", "# /ramen", "x") == "# ramen:g\nx\n# /ramen\n"
    assert configs.without_block("a\n# ramen:g\nx\n# /ramen\n", "# ramen:g", "# /ramen") == "a\n"
    assert configs.block_body("a\n# ramen:g\n", "# ramen:g", "# /ramen") is None
    assert configs.apply(policy.Policy()) == []


def test_telemetry_targets_env_sh_rc_block_codex_and_token_refresh(home, capsys):  # noqa: F811
    (home / ".claude").mkdir()
    (home / ".codex").mkdir()
    (home / ".claude" / "settings.json").write_text(json.dumps({"theme": "dark"}))
    (home / ".codex" / "config.toml").write_text('model = "gpt"\n')
    (home / ".zshrc").write_text("export PATH=/x:$PATH\n")
    pol = policy.Policy(TARGET, "demo", "a", "https://c/")
    pol.update(TEL, None, None, None, token=TOKEN, user="ada@example.com")
    done = configs.apply(pol)
    assert [(e["client"], e["source"]) for e in done] == [
        (c, "telemetry") for c in ("claude-code", "env", "shell", "codex")
    ]
    env = json.loads((home / ".claude" / "settings.json").read_text())["env"]
    assert env == {
        "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
        "OTEL_METRICS_EXPORTER": "otlp",
        "OTEL_LOGS_EXPORTER": "otlp",
        "OTEL_TRACES_EXPORTER": "otlp",
        "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "https://c/otlp",
        "OTEL_EXPORTER_OTLP_HEADERS": f"Authorization=Bearer {TOKEN}",
        "OTEL_RESOURCE_ATTRIBUTES": "ramen.group=demo,ramen.user=ada@example.com,ramen.host=ramen.example.com",
    }
    assert json.loads((home / ".claude" / "settings.json").read_text())["theme"] == "dark"
    sh = (home / ".ramen" / "env.sh").read_text()
    assert sh.startswith("export OTEL_METRICS_EXPORTER=otlp\n") and "CLAUDE_CODE" not in sh
    assert f"export OTEL_EXPORTER_OTLP_HEADERS='Authorization=Bearer {TOKEN}'\n" in sh
    if os.name == "posix":
        assert mode(home / ".ramen" / "env.sh") == "0o600" and mode(home / ".claude" / "settings.json") == "0o600"
    zsh = (home / ".zshrc").read_text()
    assert zsh == "export PATH=/x:$PATH\n# ramen:demo\n[ -f ~/.ramen/env.sh ] && . ~/.ramen/env.sh\n# /ramen\n"
    assert not (home / ".bashrc").exists()
    import tomllib

    codex = tomllib.loads((home / ".codex" / "config.toml").read_text())
    assert codex["model"] == "gpt"
    assert codex["otel"]["exporter"]["otlp-http"] == {
        "endpoint": "https://c/otlp/v1/logs",
        "protocol": "binary",
        "headers": {"Authorization": f"Bearer {TOKEN}"},
    }
    # the token is in the files that need it and nowhere else
    assert TOKEN not in ledger_text(home) and TOKEN not in capsys.readouterr().err
    assert TOKEN not in json.dumps(pol.bundle)
    # a refreshed token rewrites the files (same entries, new hashes), the snapshots stay token-free
    before = {e["path"]: e for e in entries(home)}
    pol.update(TEL, None, None, None, token="tok-second-1234", user="ada@example.com")
    configs.apply(pol)
    assert (
        "tok-second-1234" in (home / ".ramen" / "env.sh").read_text()
        and TOKEN not in (home / ".ramen" / "env.sh").read_text()
    )
    after = {e["path"]: e for e in entries(home)}
    assert after.keys() == before.keys() and all(after[p]["hash"] != before[p]["hash"] for p in before if "rc" not in p)
    assert "tok-second-1234" not in ledger_text(home) and TOKEN not in ledger_text(home)
    assert after[str(home / ".zshrc")]["snapshot"] == "export PATH=/x:$PATH\n"
    assert configs.verify(pol) == []
    # --no-shell-rc: the rc block is not asked for any more and goes; everything else stays
    configs.apply(pol, shell_rc=False)
    assert (home / ".zshrc").read_text() == "export PATH=/x:$PATH\n" and len(entries(home)) == 3
    configs.apply(pol)
    assert "# ramen:demo" in (home / ".zshrc").read_text()
    # telemetry no longer required: every target is put back
    pol.update({**TEL, "required": False}, None, None, None, token=TOKEN)
    configs.apply(pol)
    assert entries(home) == [] and not (home / ".ramen" / "env.sh").exists()
    assert json.loads((home / ".claude" / "settings.json").read_text()) == {"theme": "dark"}
    assert (home / ".codex" / "config.toml").read_text().strip() == 'model = "gpt"'
    assert (home / ".zshrc").read_text() == "export PATH=/x:$PATH\n"
    # without a token (a bundle loaded from disk, nobody signed in yet) nothing with a token is written
    pol.update(TEL, None, None, None)
    assert configs.apply(pol) == []


def test_main_signs_in_and_applies_configs_and_telemetry(home, fake, auth_cf, monkeypatch):  # noqa: F811
    import io

    (home / ".claude").mkdir()
    (home / ".bashrc").write_text("# mine\n")
    auth_cf.telemetry = {**CFG, "required": True}
    monkeypatch.setattr(configs, "user_of", lambda tok: "ada@example.com" if tok == "good" else "")
    monkeypatch.setattr(oauth.webbrowser, "open", auth_cf.browser)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(req(1, "ping"))))
    out = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(out))
    args = ["--target", fake.target, "--oauth", auth_cf.url, "--client-id", "cid", "--group", "demo", "--zone", "local"]
    assert bridge.main([*args, "--no-shell-rc"]) == 0
    assert json.loads(out.getvalue())["result"] == {}
    claude = json.loads((home / ".claude" / "settings.json").read_text())
    assert claude["env"]["RAMEN_USER"] == "ada@example.com" and claude["model"] == "opus"
    assert "OTEL_EXPORTER_OTLP_HEADERS" in claude["env"] and claude["hooks"]["SessionStart"][0]["_ramen"] is True
    assert (home / ".bashrc").read_text() == "# mine\n"  # --no-shell-rc
    assert (home / ".ramen" / "env.sh").exists() and (home / "notes.txt").exists()
    kinds = sorted({e["kind"] for e in json.loads(ledger_text(home))["entries"]})
    assert kinds == ["claude_code", "configs"]
    # the flag and its environment form
    a = bridge.parse_args(["--target", "t:1", "--key", "k"])
    assert a.no_shell_rc is False
    monkeypatch.setenv("RAMEN_BRIDGE_NO_SHELL_RC", "1")
    assert bridge.parse_args(["--target", "t:1", "--key", "k"]).no_shell_rc is True


def test_a_running_bridge_refuses_to_forward_while_a_target_is_gone(home, fake, auth_cf, capsys):  # noqa: F811
    (home / ".claude").mkdir()
    w = CfFake(fake)
    pol = policy.Policy(fake.target, "demo", "local", auth_cf.url)
    pol.on_update = configs.apply
    c = oauth.Client(auth_cf.url, "cid", "mcp:demo:local", opener=auth_cf.browser)
    c.policy = pol
    c.bearer()
    b = make(fake, pol=pol, vault=c.vault, bearer=lambda force=False: c.bearer(force=force, nonblocking=True))
    call = req(1, "tools/call", name="add", arguments={"a": 1, "b": 2})
    assert json.loads(run(b, call))["result"]["content"][0]["text"] == "3"
    # a removed block: the re-sign-in writes it again and the call goes through
    (home / "notes.txt").unlink()
    refreshes = len(auth_cf.token_calls)
    assert json.loads(run(b, call))["result"]["content"][0]["text"] == "3"
    assert (home / "notes.txt").exists() and len(auth_cf.token_calls) == refreshes + 1
    # a re-sign-in that cannot bring the files back: the call is refused, named, nothing forwarded
    pol.on_update = None
    (home / "notes.txt").unlink()
    seen = len(w.bodies)
    out = json.loads(run(b, call))
    assert out["error"]["code"] == -32028 and out["error"]["message"] == configs.REMOVED
    assert out["error"]["data"]["paths"] == [str(home / "notes.txt")] and len(w.bodies) == seen
    assert configs.REMOVED in capsys.readouterr().err
    assert run(b, req(2, "tools/list")) != b""  # lists are not gated
    # a notification is dropped silently; back in place → forwarded again
    assert run(b, b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"add","arguments":{"a":1,"b":1}}}\n') == b""
    configs.apply(pol)
    assert json.loads(run(b, call))["result"]["content"][0]["text"] == "3"


def test_policy_cli_check_show_remove_with_configs(home, auth_cf, capsys):  # noqa: F811
    (home / ".claude").mkdir()
    (home / ".claude" / "settings.json").write_text(json.dumps({"theme": "dark"}))
    pol = policy.Policy(TARGET, "demo", "local", auth_cf.url)
    pol.update(CFG, EVALS, None, CF, token=TOKEN, user="ada@example.com")
    configs.apply(pol)
    auth_cf.policy = {
        "telemetry": {"version": CFG["version"], "required": False},
        "evals": {"version": EVALS["version"], "required": True},
        "configs": {"version": CF["version"], "required": True},
    }
    assert bridge.main(["policy", "check"]) == 0
    assert "up to date" in capsys.readouterr().out
    assert bridge.main(["policy", "show"]) == 0
    out = capsys.readouterr().out
    assert out.count("\nok      ") == 7 and f"{home / 'notes.txt'} (text/block, notes vcf0123456789)" in out
    # a removed key: exit 3 with the message, before the console is even asked (offline, the hook's reason)
    s = json.loads((home / ".claude" / "settings.json").read_text())
    del s["model"]
    (home / ".claude" / "settings.json").write_text(json.dumps(s))
    pol.bundle["console"] = "http://127.0.0.1:1"
    policy.write_private(pol.path, json.dumps(pol.bundle))
    assert bridge.main(["policy", "check"]) == 3
    err = capsys.readouterr().err
    assert configs.REMOVED in err and str(home / ".claude" / "settings.json") in err and "cannot read" not in err
    assert bridge.main(["policy", "show"]) == 0
    assert "CHANGED " + str(home / ".claude" / "settings.json") in capsys.readouterr().out
    # remove: every target reverted, the configs directory gone with the bundle
    assert bridge.main(["policy", "remove"]) == 0
    err = capsys.readouterr().err
    assert f"reverted configs: {home / 'notes.txt'}" in err and "removed the policy bundle" in err
    assert json.loads((home / ".claude" / "settings.json").read_text()) == {"theme": "dark"}
    assert not (home / "notes.txt").exists() and not pol.configs_dir.exists() and not pol.path.exists()
    assert not (home / ".ramen" / "clients.json").exists()
