"""Group LLM configs and telemetry targets (bridge 0.6.0, CONTRACTS §31.3).

At sign-in the token answer's `configs` object (`version`, `required`, `accepted`, the `manifest`, the `files`) joins
the policy bundle; the manifest and files rest at `~/.ramen/configs/<host>/<group>/` (0600). Once the person accepted
them the bridge writes every manifest target and, when the group requires telemetry, the built-in OTel targets:
Claude Code `~/.claude/settings.json` (`env`), `~/.ramen/env.sh`, a block in `~/.zshrc` / `~/.bashrc`, Codex
`~/.codex/config.toml`. Each write is recorded in `~/.ramen/clients.json` (path, format, merge, the sha256 of the
ramen-owned part, the pre-ramen snapshot) so `policy check` can tell a removed block from a kept one and `policy
remove` can put the file back. Tokens appear in the files that need them, never in the ledger or on stderr.

Formats and merges: `json | toml | yaml` with `deep` (Ramen's keys win, the user's others stay; Claude Code
`hooks.<Event>` lists are merged by hook command so the bridge's own hook and the user's survive), `text` with `block`
(`# ramen:<host>/<group>` … `# /ramen`; `<!-- ramen:<host>/<group> -->` … `<!-- /ramen -->` in Markdown; the 0.6.0
`ramen:<group>` form is still read and rewritten), `env` with `keys` (`KEY=value` lines replaced by key), and `replace`
(the whole file is Ramen's) for any format. One ledger entry per (path, source): a repo fragment and the built-in
telemetry target on the same file each keep their own owned keys and pre-ramen snapshot.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import shutil
import sys
import urllib.parse
from pathlib import Path

import tomli_w
import yaml

from .policy import Policy, home, host_of, say

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - py310
    import tomli as tomllib

KIND = "configs"
META = "io.ramen/configs"
STALE = -32028  # missing or stale configs version: sign in again
REMOVED = "Ramen configs removed or changed: reconnect (sign in) — Ramen cannot be used without them"
EXIT_REMOVED = 3
MISSING = "\0missing"
ENV_LINE = re.compile(r"^(export\s+)?([A-Za-z_][A-Za-z0-9_]*)=")
HOOKS_KEY = "hooks"  # ledger: {json path: [hook keys]} for the Claude Code hook lists a fragment merged into
PLACEHOLDERS = ("RAMEN_OTLP_ENDPOINT", "RAMEN_OTLP_HEADERS", "RAMEN_USER", "RAMEN_GROUP", "RAMEN_HOST")


def configs_dir(target: str, group: str) -> Path:
    return home() / ".ramen" / "configs" / host_of(target) / group


def consent_url(console: str, group: str) -> str:
    nxt = urllib.parse.quote(f"/groups/{group}", safe="/")
    return f"{console.rstrip('/')}/groups/{urllib.parse.quote(group, safe='')}/configs?next={nxt}"


def user_of(token: str | None) -> str:
    """The `email` (else `sub`) claim of a JWT access token, read without verifying — it only labels telemetry."""
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return str(claims.get("email") or claims.get("sub") or "")
    except (AttributeError, IndexError, ValueError, TypeError):
        return ""


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def digest(pairs: list) -> str:
    return sha(json.dumps(pairs, sort_keys=True, default=str))


def secret(value, token: str) -> bool:
    """Whether a pre-ramen value may carry a token (ours, or another host's bearer): it never enters the ledger."""
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return (bool(token) and token in text) or "Bearer " in text


class Ctx:
    """What fills a fragment: the console, the token (held in memory), the person, the group, the host."""

    def __init__(self, pol: Policy):
        self.group, self.zone, self.host = pol.group, pol.zone, host_of(pol.target or "")
        self.console = (pol.console or (pol.bundle or {}).get("console") or "").rstrip("/")
        self.token, self.user = pol.token or "", pol.user or ""

    @property
    def otlp_endpoint(self) -> str:
        return f"{self.console}/otlp"

    @property
    def otlp_headers(self) -> str:
        return f"Authorization=Bearer {self.token}"

    def values(self) -> dict[str, str]:
        return {
            "RAMEN_OTLP_ENDPOINT": self.otlp_endpoint,
            "RAMEN_OTLP_HEADERS": self.otlp_headers,
            "RAMEN_USER": self.user,
            "RAMEN_GROUP": self.group,
            "RAMEN_HOST": self.host,
        }

    def fill(self, text: str) -> str:
        for k, v in self.values().items():
            text = text.replace("${" + k + "}", v)
        return text

    def path(self, p: str) -> Path:
        p = p.replace("{group}", self.group).replace("{zone}", self.zone).replace("{host}", self.host)
        return Path(os.path.expanduser(p))


# --- structured merges (json / toml / yaml) ----------------------------------------------------------------------
LOAD = {"json": json.loads, "toml": tomllib.loads, "yaml": yaml.safe_load}
DUMP = {
    "json": lambda o: json.dumps(o, indent=2) + "\n",
    "toml": tomli_w.dumps,
    "yaml": lambda o: yaml.safe_dump(o, sort_keys=False),
}


def load(fmt: str, text: str) -> dict | None:
    if not text.strip():
        return {}
    try:
        obj = LOAD[fmt](text)
    except Exception:  # noqa: BLE001 - each parser has its own error type
        return None
    return obj if isinstance(obj, dict) else None


def leaves(frag: dict, prefix: tuple = ()) -> list[tuple[list, object]]:
    out: list[tuple[list, object]] = []
    for k, v in frag.items():
        if isinstance(v, dict) and v:
            out += leaves(v, (*prefix, k))
        else:
            out.append(([*prefix, k], v))
    return out


def get_path(obj, path: list):
    for k in path:
        if not isinstance(obj, dict) or k not in obj:
            return MISSING
        obj = obj[k]
    return obj


def set_path(obj: dict, path: list, value) -> None:
    for k in path[:-1]:
        if not isinstance(obj.get(k), dict):
            obj[k] = {}
        obj = obj[k]
    obj[path[-1]] = value


def del_path(obj: dict, path: list) -> None:
    if len(path) == 1:
        obj.pop(path[0], None)
        return
    child = obj.get(path[0])
    if isinstance(child, dict):
        del_path(child, path[1:])
        if not child:
            del obj[path[0]]


# --- Claude Code hook lists (P4-B4) ------------------------------------------------------------------------------
def is_hook_list(path: list, value) -> bool:
    """`hooks.<Event>` in a Claude Code settings file: a list of `{matcher, hooks: [{type, command}]}` entries."""
    return len(path) == 2 and path[0] == "hooks" and isinstance(value, list) and all(isinstance(e, dict) for e in value)


def hook_key(entry) -> str:
    """One hook entry's identity: its commands (the bridge's own `policy check …` differs from a repo's by target)."""
    cmds = sorted(str(h.get("command", "")) for h in (entry.get("hooks") or []) if isinstance(h, dict))
    return json.dumps(cmds) if cmds else json.dumps(entry, sort_keys=True, default=str)


def merge_hooks(cur, frag: list) -> list:
    """The fragment's entries replace those with the same commands (so they are added once); every other entry —
    the user's, the bridge's own hook — stays where it was."""
    keys = {hook_key(e) for e in frag}
    return [e for e in (cur if isinstance(cur, list) else []) if hook_key(e) not in keys] + list(frag)


def project_hooks(cur, keys: list):
    """The entries of `cur` that carry `keys`, in that order; MISSING when one is gone."""
    have = {hook_key(e): e for e in cur} if isinstance(cur, list) else {}
    return MISSING if any(k not in have for k in keys) else [have[k] for k in keys]


# --- text blocks ------------------------------------------------------------------------------------------------
def markers(path: Path, host: str, group: str) -> tuple[str, str]:
    name = f"{host}/{group}" if host else group
    if path.suffix.lower() in (".md", ".markdown"):
        return f"<!-- ramen:{name} -->", "<!-- /ramen -->"
    return f"# ramen:{name}", "# /ramen"


def find_block(lines: list[str], open_: str, close: str) -> tuple[int, int] | None:
    try:
        start = next(i for i, ln in enumerate(lines) if ln.strip() == open_)
        end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == close)
    except StopIteration:
        return None
    return start, end


def block_body(text: str, open_: str, close: str) -> str | None:
    lines = text.split("\n")
    span = find_block(lines, open_, close)
    return None if span is None else "\n".join(lines[span[0] + 1 : span[1]])


def without_block(text: str, open_: str, close: str) -> str:
    lines = text.split("\n")
    span = find_block(lines, open_, close)
    if span is None:
        return text
    out = lines[: span[0]] + lines[span[1] + 1 :]
    while len(out) > 1 and out[-1] == "" and out[-2] == "":
        out.pop()
    return "\n".join(out)


def with_block(text: str, open_: str, close: str, body: str) -> str:
    block = f"{open_}\n{body.rstrip()}\n{close}\n"
    lines = text.split("\n")
    span = find_block(lines, open_, close)
    if span is not None:
        return "\n".join(lines[: span[0]]) + ("\n" if span[0] else "") + block + "\n".join(lines[span[1] + 1 :])
    if not text:
        return block
    return text + ("" if text.endswith("\n") else "\n") + block


# --- env lines ----------------------------------------------------------------------------------------------------
def env_key(line: str) -> str | None:
    m = ENV_LINE.match(line.strip())
    return m.group(2) if m else None


def env_lines(text: str) -> dict[str, str]:
    """`KEY=value` (or `export KEY=value`) lines of a fragment, by key, first one wins."""
    out: dict[str, str] = {}
    for ln in text.splitlines():
        k = env_key(ln)
        if k and k not in out:
            out[k] = ln.rstrip()
        elif ln.strip() and not k:
            say(f"ramen-mcp-bridge: env fragment line is not KEY=value and was dropped: {ln[:40]!r}")
    return out


def with_keys(text: str, ours: dict[str, str], restore: dict[str, str] | None = None) -> str:
    """Our lines replace the file's lines of the same key (first in place, duplicates dropped), missing ones are
    appended; with `restore`, our keys are taken out and the prior lines put back where they stood."""
    out, seen = [], set()
    for ln in text.split("\n"):
        k = env_key(ln)
        if k is None or k not in ours:
            out.append(ln)
            continue
        if k in seen:
            continue
        seen.add(k)
        if restore is None:
            out.append(ours[k])
        elif k in restore:
            out.append(restore[k])
    while out and out[-1] == "":
        out.pop()
    if restore is None:
        out += [ours[k] for k in ours if k not in seen]
    return ("\n".join(out) + "\n") if out else ""


# --- one target ---------------------------------------------------------------------------------------------------
class Target:
    def __init__(self, client: str, path: Path, fmt: str, merge: str, text: str, source: str = "repo"):
        self.client, self.path, self.fmt, self.merge, self.text, self.source = client, path, fmt, merge, text, source

    def valid(self) -> str | None:
        if self.fmt not in ("json", "toml", "yaml", "text", "env"):
            return f"unknown format {self.fmt!r}"
        ok = {"deep": self.fmt in LOAD, "block": self.fmt == "text", "keys": self.fmt == "env", "replace": True}
        return None if ok.get(self.merge) else f"merge {self.merge!r} does not fit format {self.fmt!r}"


def read_text(path: Path) -> str | None:
    try:
        return path.read_text()
    except OSError:
        return None


def write_text(path: Path, text: str, private: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    with os.fdopen(os.open(tmp, flags, 0o600 if private else 0o644), "w") as f:
        f.write(text)
    os.replace(tmp, path)
    if private:
        os.chmod(path, 0o600)


def owned_hash(entry: dict, text: str | None) -> str | None:
    """The sha256 of the ramen-owned part of `text` as the ledger entry describes it; None when it is gone."""
    fmt, merge, owned = entry.get("format"), entry.get("merge"), entry.get("owned") or []
    if text is None:
        return None
    if merge == "replace":
        return sha(text)
    if merge == "block":
        body = block_body(text, *owned)
        return None if body is None else sha(body)
    if merge == "keys":
        have = {k: ln.rstrip() for ln in text.splitlines() if (k := env_key(ln)) in owned}
        return None if len(have) != len(owned) else digest(sorted(have.items()))
    cur = load(fmt, text)
    if cur is None:
        return None
    hooks = entry.get(HOOKS_KEY) or {}
    vals = [[p, owned_value(cur, p, hooks)] for p in owned]
    return None if any(v == MISSING for _, v in vals) else digest(vals)


def owned_value(obj, path: list, hooks: dict):
    """The leaf at `path` — for a merged hook list, only the fragment's entries of it."""
    v = get_path(obj, path)
    keys = hooks.get(json.dumps(path))
    return project_hooks(v, keys) if keys is not None and v != MISSING else v


def keep(entry: dict, key: str, value, token: str) -> None:
    """The pre-ramen state is taken at the first write and kept; a value that may hold a token is not kept."""
    if key not in entry:
        entry[key] = None if value is not None and secret(value, token) else value


def apply_target(t: Target, ctx: Ctx, before: dict | None, ident: dict, version: str) -> dict | None:
    """Write one target (first time or again); the ledger entry, or None when the file cannot be rewritten."""
    cur = read_text(t.path)
    existed = cur is not None
    entry = {
        "kind": KIND,
        **ident,
        "client": t.client,
        "path": str(t.path),
        "format": t.fmt,
        "merge": t.merge,
        "source": t.source,
        "version": version,
    }
    if before is not None:  # the pre-ramen state was taken at the first write; it is kept, never the token
        entry.update({k: before[k] for k in ("existed", "snapshot", "prior") if k in before})
    private = bool(ctx.token) and ctx.token in t.text
    token = ctx.token
    if t.merge == "replace":
        entry.setdefault("existed", existed)
        keep(entry, "snapshot", cur, token)
        entry["owned"], entry["hash"] = [], sha(t.text)
        if cur != t.text:
            write_text(t.path, t.text, private)
        return entry
    if t.merge == "block":
        open_, close = markers(t.path, ctx.host, ctx.group)
        prev = (before or {}).get("owned") or []
        if cur and len(prev) == 2 and prev[0] != open_ and find_block(cur.split("\n"), *prev) is not None:
            cur = without_block(cur, *prev)  # our own block in the 0.6.0 `ramen:<group>` form: rewritten below
        entry.setdefault("existed", existed)
        keep(entry, "snapshot", without_block(cur or "", open_, close) if existed else None, token)
        entry["owned"], entry["hash"] = [open_, close], sha(t.text.rstrip())
        new = with_block(cur or "", open_, close, t.text)
        if new != read_text(t.path):
            write_text(t.path, new, private)
        return entry
    if t.merge == "keys":
        ours = env_lines(t.text)
        have = {k: ln.rstrip() for ln in (cur or "").splitlines() if (k := env_key(ln)) in ours}
        entry.setdefault("existed", existed)
        keep(entry, "prior", {k: v for k, v in have.items() if not secret(v, token)}, token)
        entry["owned"], entry["hash"] = sorted(ours), digest(sorted(ours.items()))
        new = with_keys(cur or "", ours)
        if new != cur:
            write_text(t.path, new, private)
        return entry
    frag, obj = load(t.fmt, t.text), load(t.fmt, cur or "")
    if frag is None:
        say(f"ramen-mcp-bridge: the {t.fmt} fragment for {t.path} does not parse; skipped")
        return None
    if obj is None:
        say(f"ramen-mcp-bridge: {t.path} is not plain {t.fmt}; left unchanged — add the Ramen keys by hand")
        return None
    pairs = leaves(frag)
    hooks = {json.dumps(p): [hook_key(e) for e in v] for p, v in pairs if is_hook_list(p, v)}
    entry.setdefault("existed", existed)
    keep(entry, "snapshot", cur, token)
    prior = {}
    for p, _ in pairs:
        v = owned_value(obj, p, hooks)
        if v != MISSING and not secret(v, token):
            prior[json.dumps(p)] = v
    entry.setdefault("prior", prior)
    entry["owned"], entry["hash"] = [p for p, _ in pairs], digest([[p, owned_value(frag, p, hooks)] for p, _ in pairs])
    entry[HOOKS_KEY] = hooks
    for p, v in pairs:
        set_path(obj, p, merge_hooks(get_path(obj, p), v) if json.dumps(p) in hooks else v)
    new = DUMP[t.fmt](obj)
    if load(t.fmt, cur or "") != obj or not existed:
        write_text(t.path, new, private)
    return entry


def restore(entry: dict) -> None:
    """Put the file back as it was before Ramen: byte-for-byte where nothing else moved since the write; else only
    Ramen's part goes, the user's later edits stay. A file that only held Ramen's block gets its pre-block content."""
    path, merge, fmt = Path(entry.get("path", "")), entry.get("merge"), entry.get("format", "json")
    cur = read_text(path)
    if cur is None:
        return
    existed, snapshot = entry.get("existed", True), entry.get("snapshot")
    if merge == "replace":
        new = snapshot if existed else None
    elif merge == "block":
        owned = entry.get("owned") or markers(path, host_of(entry.get("target") or ""), entry.get("group", ""))
        rest = without_block(cur, *owned)
        same = rest.rstrip("\n") == (snapshot or "").rstrip("\n")
        if existed and snapshot is not None and (same or not rest.strip()):
            new = snapshot
        else:
            new = rest if (existed or rest.strip()) else None
    elif merge == "keys":
        ours = dict.fromkeys(entry.get("owned") or [], "")
        new = with_keys(cur, ours, restore=entry.get("prior") or {})
        new = new if (existed or new.strip()) else None
    else:
        obj = load(fmt, cur)
        if obj is None:
            return
        prior, hooks = entry.get("prior") or {}, entry.get(HOOKS_KEY) or {}
        for p in entry.get("owned") or []:
            key = json.dumps(p)
            if key in hooks:
                keys, have = set(hooks[key]), get_path(obj, p)
                rest = [e for e in (have if isinstance(have, list) else []) if hook_key(e) not in keys]
                back = [e for e in (prior.get(key) or []) if hook_key(e) in keys]
                if rest or back:
                    set_path(obj, p, rest + back)
                else:
                    del_path(obj, p)
            elif key in prior:
                set_path(obj, p, prior[key])
            else:
                del_path(obj, p)
        if existed and snapshot is not None and load(fmt, snapshot) == obj:
            new = snapshot  # nothing else moved since the write: the user's bytes, not the dumper's
        else:
            new = DUMP[fmt](obj) if (existed or obj) else None
    if new is None:
        try:
            path.unlink()
        except OSError:
            pass
    elif new != cur:
        write_text(path, new, False)


# --- the targets of a bundle -------------------------------------------------------------------------------------
def repo_targets(pol: Policy, ctx: Ctx) -> list[Target]:
    d = pol.configs_dir
    manifest = load("yaml", read_text(d / "manifest.yaml") or "") if d is not None else None
    out: list[Target] = []
    for t in (manifest or {}).get("targets") or []:
        if not isinstance(t, dict) or not all(isinstance(t.get(k), str) for k in ("file", "path", "format", "merge")):
            say(f"ramen-mcp-bridge: configs manifest target is incomplete and was skipped: {t!r}"[:160])
            continue
        text = read_text(d / Path(t["file"]).name)
        if text is None:
            say(f"ramen-mcp-bridge: configs file {t['file']} is missing; skipped")
            continue
        out.append(Target(str(t.get("client") or "any"), ctx.path(t["path"]), t["format"], t["merge"], ctx.fill(text)))
    return out


def otel_env(ctx: Ctx) -> dict[str, str]:
    return {
        "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
        "OTEL_METRICS_EXPORTER": "otlp",
        "OTEL_LOGS_EXPORTER": "otlp",
        "OTEL_TRACES_EXPORTER": "otlp",
        "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
        "OTEL_EXPORTER_OTLP_ENDPOINT": ctx.otlp_endpoint,
        "OTEL_EXPORTER_OTLP_HEADERS": ctx.otlp_headers,
        "OTEL_RESOURCE_ATTRIBUTES": f"ramen.group={ctx.group},ramen.user={ctx.user},ramen.host={ctx.host}",
    }


def telemetry_targets(ctx: Ctx, shell_rc: bool = True) -> list[Target]:
    env = otel_env(ctx)
    out = []
    if (home() / ".claude").is_dir():
        text = json.dumps({"env": env})
        out.append(Target("claude-code", home() / ".claude" / "settings.json", "json", "deep", text, "telemetry"))
    sh = "\n".join(f"export {k}={shlex.quote(v)}" for k, v in env.items() if k.startswith("OTEL_")) + "\n"
    out.append(Target("env", home() / ".ramen" / "env.sh", "env", "keys", sh, "telemetry"))
    if shell_rc:
        for rc in (".zshrc", ".bashrc"):
            if (home() / rc).is_file():
                line = "[ -f ~/.ramen/env.sh ] && . ~/.ramen/env.sh\n"
                out.append(Target("shell", home() / rc, "text", "block", line, "telemetry"))
    if (home() / ".codex").is_dir():
        exporter = {
            "otlp-http": {
                "endpoint": f"{ctx.otlp_endpoint}/v1/logs",
                "protocol": "binary",
                "headers": {"Authorization": f"Bearer {ctx.token}"},
            }
        }
        text = tomli_w.dumps({"otel": {"exporter": exporter}})
        out.append(Target("codex", home() / ".codex" / "config.toml", "toml", "deep", text, "telemetry"))
    return out


def ident_of(pol: Policy) -> dict:
    return {"target": pol.target or "", "group": pol.group, "zone": pol.zone}


def entries_of(ledger, pol: Policy) -> list[dict]:
    ident = ident_of(pol)
    return [e for e in ledger.entries if e.get("kind") == KIND and all(e.get(k) == v for k, v in ident.items())]


def entry_key(e: dict) -> tuple[str, str]:
    """One ledger entry per (path, source): a repo fragment and the telemetry target may share a file (P4-B2)."""
    return str(e.get("path", "")), str(e.get("source") or "repo")


def restore_all(entries: list[dict]) -> None:
    """Later writes first: a leaf two sources own gets the earlier source's value back, then the user's."""
    for e in reversed(entries):
        restore(e)


def apply(pol: Policy, shell_rc: bool = True) -> list[dict]:
    """Write every target the bundle asks for (accepted repo configs; telemetry when required and a token is held);
    targets recorded earlier that are no longer asked for are restored. The entries written."""
    from .clients import Ledger

    if pol.target is None:
        return []
    ctx, ident, ledger = Ctx(pol), ident_of(pol), Ledger()
    before = {entry_key(e): e for e in entries_of(ledger, pol)}
    version = pol.configs_version() or ""
    targets = repo_targets(pol, ctx) if pol.configs_accepted() else []
    if pol.telemetry_required() and ctx.token:
        targets += telemetry_targets(ctx, shell_rc)
    done: list[dict] = []
    for t in targets:
        if (why := t.valid()) is not None:
            say(f"ramen-mcp-bridge: configs target {t.path}: {why}; skipped")
            continue
        e = apply_target(t, ctx, before.get((str(t.path), t.source)), ident, version)
        if e is not None:
            ledger.upsert(e, ("kind", "target", "group", "zone", "path", "source"))
            done.append(e)
    kept = {entry_key(e) for e in done}
    gone = [e for k, e in before.items() if k not in kept]
    restore_all(gone)
    for e in gone:
        ledger.entries.remove(e)
    ledger.save()
    return done


def verify(pol: Policy) -> list[str]:
    """The recorded targets whose ramen-owned part is gone or changed; empty = all in place."""
    from .clients import Ledger

    return [e["path"] for e in entries_of(Ledger(), pol) if owned_hash(e, read_text(Path(e["path"]))) != e.get("hash")]


def check(pol: Policy) -> int:
    broken = verify(pol)
    if not broken:
        return 0
    for p in broken:
        say(f"ramen configs: {p}: removed or changed")
    say(REMOVED)
    return EXIT_REMOVED


def show(pol: Policy) -> list[str]:
    from .clients import Ledger

    out = []
    for e in entries_of(Ledger(), pol):
        ok = owned_hash(e, read_text(Path(e["path"]))) == e.get("hash")
        v = f" v{e['version']}" if e.get("version") else ""
        out.append(f"{'ok     ' if ok else 'CHANGED'} {e['path']} ({e['format']}/{e['merge']}, {e['client']}{v})")
    return out


def remove_dir(pol: Policy) -> None:
    if pol.configs_dir is not None:
        shutil.rmtree(pol.configs_dir, ignore_errors=True)
