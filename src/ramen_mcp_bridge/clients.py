"""Client config files (bridge 0.5.0, CONTRACTS §29.3): at sign-in the bridge tells the editors on this machine about
the group's policy, so an agent hears it even before its first Ramen call.

- Claude Code `~/.claude/settings.json`: a `hooks.SessionStart` entry running `ramen-mcp-bridge policy check …`
  (non-zero = stale/missing, the reconnect message on stderr)
- Cursor `~/.cursor/rules/ramen-<group>-<zone>.mdc`: an always-on rule stating the policy
- VS Code user `settings.json`: `mcp.servers["ramen-<group>-<zone>"]` pointing at the bridge

Each is written only when the editor's directory exists, merged idempotently (other keys survive), and marked
`"_ramen": true` (a `# ramen` line in the .mdc). When another host's sign-in already holds the plain Cursor / VS Code
name for this group and zone, this host's takes the suffix `-<host>` (two hosts of one group on one machine). A ledger
`~/.ramen/clients.json` lists every file and key written (with the file's pre-ramen bytes, token-free) so `policy
remove` can revert exactly that — byte-for-byte when nothing else changed. A JSON file the bridge cannot parse
(comments, trailing commas) is left alone with a warning, never overwritten. An LLM that never uses the bridge or
Ramen's workers cannot be forced — a limit.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .policy import Policy, home, host_of, newline_of, say, write_private

MARK = "_ramen"
IDENT = ("target", "group", "zone")
SKILLSPECTOR_NOTE = (
    "SkillSpector required: this hook scans the skills on this machine (~/.claude/skills, ./.claude/skills, "
    "~/.codex/skills); a DO_NOT_INSTALL skill blocks Ramen until it is fixed or removed"
)


def guardrails_note(pol: Policy) -> str | None:
    """§36.3: the rails in force, for the client files (the group's pack runs on the worker and, when the nemo extra
    is installed and `policy rails` is on, on this machine before and after every gated tool call)."""
    gr = (pol.bundle or {}).get("guardrails") or {}
    if not gr:
        return None
    where = "on the worker and locally in the bridge" if pol.rails_enabled() and gr.get("sha") else "on the worker"
    req = "required" if gr.get("required") else "in force"
    v = f" (policy version `{gr.get('version')}`)" if gr.get("version") else ""
    return (
        f"Guardrails {req}{v}: the group's NeMo rails run {where} on every gated tool call; a blocked call or result "
        "comes back as an isError tool result with _meta.ramen.guardrail (stage, rail, where) — do not retry it "
        "reworded to get around the rail"
    )


def policy_note(pol: Policy) -> dict:
    notes = [n for n in ((SKILLSPECTOR_NOTE if pol.skillspector_required() else None), guardrails_note(pol)) if n]
    return {"_ramen_policy": " · ".join(notes)} if notes else {}


def vscode_user_dir() -> Path:
    if sys.platform == "darwin":
        return home() / "Library" / "Application Support" / "Code" / "User"
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA") or home() / "AppData" / "Roaming") / "Code" / "User"
    return Path(os.environ.get("XDG_CONFIG_HOME") or home() / ".config") / "Code" / "User"


def ledger_path() -> Path:
    return home() / ".ramen" / "clients.json"


def _read_json(path: Path) -> dict | None:
    """The file's object; `{}` when absent; None when it is not JSON the bridge can rewrite faithfully."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    if not text.strip():
        return {}
    try:
        obj = json.loads(text)
    except ValueError:
        say(f"ramen-mcp-bridge: {path} is not plain JSON (comments?); left unchanged — add the Ramen entry by hand")
        return None
    return obj if isinstance(obj, dict) else None


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8", newline=newline_of(path))
    os.replace(tmp, path)


def check_command(target: str, group: str, zone: str, client_scan: bool = True) -> str:
    base = f"ramen-mcp-bridge policy check --target {target} --group {group} --zone {zone}"
    return base if client_scan else base + " --no-client-scan"


def rule_text(pol: Policy, bridge_args: list[str]) -> str:
    b = pol.bundle or {}
    tel, ev, ss = b.get("telemetry") or {}, b.get("evals") or {}, b.get("skillspector") or {}
    gr_note = guardrails_note(pol)
    lines = [
        "---",
        f"description: Ramen policy for {pol.group}/{pol.zone} on {pol.target}",
        "alwaysApply: true",
        "---",
        "# ramen",
        f"This machine uses Ramen group `{pol.group}`, zone `{pol.zone}` at `{pol.target}` through ramen-mcp-bridge.",
        f"- Telemetry: {'required' if tel.get('required') else 'not required'}"
        + (f" (config version `{tel.get('version')}`)" if tel.get("version") else "")
        + "; the bridge reports every Ramen call and the model must report its own model and tool calls with the "
        "`ramen_report` tool before the next Ramen call.",
        f"- Evals: {'required' if ev.get('required') else 'not required'}"
        + (f" (config version `{ev.get('version')}`)" if ev.get("version") else "")
        + "; every Ramen call names this version.",
        f"- SkillSpector: {'required' if ss.get('required') else 'not required'}"
        + (f" (policy version `{ss.get('version')}`)" if ss.get("version") else "")
        + (
            "; `ramen-mcp-bridge policy check` scans the skills on this machine with NVIDIA SkillSpector "
            "(`~/.claude/skills`, `./.claude/skills`, `~/.codex/skills`); a skill rated DO_NOT_INSTALL must be fixed "
            "or removed before Ramen can be used (exit 3)."
            if ss.get("required")
            else "."
        ),
        *([f"- {gr_note}."] if gr_note else []),
        (
            "- When a Ramen call answers `-32025`, `-32026`, `-32027`, `-32028` or `-32029` (config changed) or a "
            "check says the policy "
            "is stale or missing, sign in again: run"
        ),
        "  `uvx " + " ".join(bridge_args) + "`",
        "  (or restart the Ramen MCP server in this editor) and approve in the browser.",
        "- Ramen cannot be used without its policy; do not work around the bridge.",
        "",
    ]
    return "\n".join(lines)


class Ledger:
    def __init__(self):
        self.path = ledger_path()
        try:
            data = json.loads(self.path.read_bytes())
        except (OSError, ValueError):
            data = {}
        self.entries: list[dict] = list(data.get("entries") or []) if isinstance(data, dict) else []

    def add(self, entry: dict) -> None:
        if entry not in self.entries:
            self.entries.append(entry)

    def upsert(self, entry: dict, keys: tuple) -> None:
        """Replace the one entry sharing `keys` with this one (a configs target written again), else append."""
        ident = tuple(entry.get(k) for k in keys)
        self.entries = [e for e in self.entries if tuple(e.get(k) for k in keys) != ident]
        self.entries.append(entry)

    def take(self, target: str, group: str, zone: str) -> list[dict]:
        mine = [e for e in self.entries if (e.get("target"), e.get("group"), e.get("zone")) == (target, group, zone)]
        self.entries = [e for e in self.entries if e not in mine]
        return mine

    def find(self, kind: str, ident: dict) -> dict | None:
        """This (target, group, zone)'s entry of `kind`, if one was written before."""
        return next(
            (e for e in self.entries if e.get("kind") == kind and all(e.get(k) == v for k, v in ident.items())), None
        )

    def taken(self, kind: str, field: str, name: str, ident: dict) -> bool:
        """Whether another (target, group, zone) holds `name` (a VS Code key, a Cursor file) for this kind."""
        return any(
            e.get("kind") == kind and e.get(field) == name and any(e.get(k) != v for k, v in ident.items())
            for e in self.entries
        )

    def save(self) -> None:
        if self.entries:
            write_private(self.path, json.dumps({"entries": self.entries}, indent=1) + "\n")
        else:
            try:
                self.path.unlink()
            except OSError:
                pass


def _before(ledger: Ledger, kind: str, path: Path, ident: dict, token: str) -> dict:
    """The file's pre-ramen state for the ledger: taken at the first write, kept after; never a token."""
    prev = ledger.find(kind, ident)
    if prev is not None and "existed" in prev:
        return {k: prev[k] for k in ("existed", "snapshot") if k in prev}
    from .configs import secret

    text = path.read_text(encoding="utf-8") if path.exists() else None
    return {"existed": text is not None, "snapshot": None if text is not None and secret(text, token) else text}


def _name(ledger: Ledger, kind: str, field: str, base: str, suffixed: str, ident: dict, foreign: bool) -> str:
    """The plain name unless another host's sign-in holds it (per the ledger, or the file says so): then `-<host>`."""
    mine = ledger.find(kind, ident)
    if mine is not None and mine.get(field) in (base, suffixed):
        return mine[field]
    return suffixed if (foreign or ledger.taken(kind, field, base, ident)) else base


def install(pol: Policy, bridge_args: list[str], client_scan: bool = True) -> list[dict]:
    """Write (or refresh) every client file for this (target, group, zone); the entries written."""
    target, group, zone = pol.target or "", pol.group, pol.zone
    ident = {"target": target, "group": group, "zone": zone}
    ledger, token, host = Ledger(), pol.token or "", host_of(target)
    done: list[dict] = []
    note = policy_note(pol)

    claude = home() / ".claude"
    if claude.is_dir():
        path = claude / "settings.json"
        before = _before(ledger, "claude_code", path, ident, token)
        settings = _read_json(path)
        if settings is not None:
            hooks = settings.setdefault("hooks", {}) if isinstance(settings.get("hooks"), dict | None) else None
            if hooks is None:
                say(f"ramen-mcp-bridge: {path}: `hooks` is not an object; left unchanged")
            else:
                if settings.get("hooks") is None:
                    settings["hooks"] = hooks = {}
                start = hooks.setdefault("SessionStart", [])
                key = check_command(target, group, zone)
                cmd = check_command(target, group, zone, client_scan)
                entry = {"matcher": "", "hooks": [{"type": "command", "command": cmd}], MARK: True, **note}
                if isinstance(start, list) and entry not in start:
                    start[:] = [*(e for e in start if not _is_ours(e, key)), entry]
                    _write_json(path, settings)
                if isinstance(start, list):
                    done.append({"kind": "claude_code", "file": str(path), "key": key, **ident, **before})

    cursor = home() / ".cursor"
    if cursor.is_dir():
        rules, base = cursor / "rules", f"ramen-{group}-{zone}"
        text = rule_text(pol, bridge_args)
        plain = rules / f"{base}.mdc"
        foreign = (
            plain.exists() and "# ramen" in (old := plain.read_text(encoding="utf-8")) and f"at `{target}`" not in old
        )
        name = _name(ledger, "cursor", "file", str(plain), str(rules / f"{base}-{host}.mdc"), ident, foreign)
        path = Path(name)
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline=newline_of(path))
        done.append({"kind": "cursor", "file": str(path), "key": "", **ident})

    code = vscode_user_dir()
    if code.is_dir():
        path = code / "settings.json"
        before = _before(ledger, "vscode", path, ident, token)
        settings = _read_json(path)
        if settings is not None:
            mcp = settings.get("mcp")
            if mcp is None:
                mcp = settings["mcp"] = {}
            if isinstance(mcp, dict) and isinstance(mcp.get("servers", {}), dict):
                servers = mcp.setdefault("servers", {})
                base = f"ramen-{group}-{zone}"
                have = servers.get(base)
                foreign = isinstance(have, dict) and bool(have.get(MARK)) and target not in (have.get("args") or [])
                key = _name(ledger, "vscode", "key", base, f"{base}-{host}", ident, foreign)
                entry = {"command": "uvx", "args": list(bridge_args), MARK: True, **note}
                if servers.get(key) != entry:
                    servers[key] = entry
                    _write_json(path, settings)
                done.append({"kind": "vscode", "file": str(path), "key": key, **ident, **before})
            else:
                say(f"ramen-mcp-bridge: {path}: `mcp.servers` is not an object; left unchanged")

    for e in done:
        ledger.upsert(e, ("kind", *IDENT))
    ledger.save()
    return done


def _is_ours(entry, cmd: str) -> bool:
    """Our hook for this (target, group, zone): the check command, with or without `--no-client-scan`."""
    if not isinstance(entry, dict):
        return False
    return any(isinstance(h, dict) and str(h.get("command", "")).startswith(cmd) for h in entry.get("hooks") or [])


def _put_back(path: Path, settings: dict, entry: dict) -> None:
    """The settings minus our part: the pre-ramen bytes when that is what is left, else the dumper's; a file Ramen
    created and emptied again is deleted."""
    snapshot, pruned = entry.get("snapshot"), _pruned(settings)
    if not entry.get("existed", True) and not pruned:
        try:
            path.unlink()
        except OSError:
            pass
    elif isinstance(snapshot, str) and _read_json_text(snapshot) in (settings, pruned):
        path.write_text(snapshot, encoding="utf-8", newline=newline_of(path))
    else:
        _write_json(path, settings)


def _pruned(settings: dict) -> dict:
    """`settings` without the containers our entry alone filled (`hooks`, `mcp.servers`, `mcp`) once they are empty."""
    out = {k: v for k, v in settings.items() if not (k == "hooks" and v == {})}
    mcp = out.get("mcp")
    if isinstance(mcp, dict) and mcp.get("servers") == {}:
        mcp = {k: v for k, v in mcp.items() if k != "servers"}
        out = {**{k: v for k, v in out.items() if k != "mcp"}, **({"mcp": mcp} if mcp else {})}
    return out


def _read_json_text(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return None


def remove(target: str, group: str, zone: str) -> list[dict]:
    """Revert every ledger entry of this (target, group, zone); the entries reverted."""
    from . import configs

    ledger = Ledger()
    mine = ledger.take(target, group, zone)
    # §31.3: the configs and telemetry targets go back as they were, the last write first (two sources on one file)
    configs.restore_all([e for e in mine if e.get("kind") == configs.KIND])
    for e in mine:
        path = Path(e.get("file", ""))
        kind, key = e.get("kind"), e.get("key", "")
        if kind == configs.KIND:
            continue
        if kind == "skill":  # §33.2: a file `skills install` wrote
            from . import skills

            skills.remove_file(e)
            continue
        if kind == "cursor":
            try:
                path.unlink()
            except OSError:
                pass
            continue
        settings = _read_json(path) if path.exists() else None
        if not settings:
            continue
        if kind == "claude_code":
            hooks = settings.get("hooks")
            start = hooks.get("SessionStart") if isinstance(hooks, dict) else None
            if isinstance(start, list):
                kept = [x for x in start if not _is_ours(x, key)]
                if kept:
                    hooks["SessionStart"] = kept
                else:
                    hooks.pop("SessionStart", None)
                _put_back(path, settings, e)
        elif kind == "vscode":
            servers = (settings.get("mcp") or {}).get("servers") if isinstance(settings.get("mcp"), dict) else None
            if isinstance(servers, dict) and isinstance(servers.get(key), dict) and servers[key].get(MARK):
                del servers[key]
                _put_back(path, settings, e)
    ledger.save()
    return mine
