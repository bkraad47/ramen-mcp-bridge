"""Skills over MCP (bridge 0.6.0, CONTRACTS §33.2): `ramen-mcp-bridge skills list` asks the worker `skills/list`;
`skills install <name> [--dir ~/.claude/skills]` reads every `skill://<name>/<file>` with `resources/read` through the
bridge's normal path (policy versions, re-sign-in) and writes them under `<dir>/<name>/` (0644, `..` and absolute paths
refused, ≤ 256 KiB each). When the bundle says `skillspector.required` the files are scanned first (§30.3); a
`DO_NOT_INSTALL` verdict, a failed scan or no `skillspector` on PATH writes nothing and exits 3. Every file is recorded
in the ledger `~/.ramen/clients.json` (kind `skill`) so `policy remove` deletes it again.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import tempfile
from pathlib import Path

from . import scan
from .clients import Ledger
from .policy import home, say

KIND = "skill"
SCHEME = "skill://"
MAX_FILE = 256 * 1024
EXIT_BLOCK = scan.EXIT_BLOCK
EXIT_ERROR = 1


class SkillError(Exception):
    def __init__(self, msg: str, code: int = EXIT_ERROR):
        super().__init__(msg)
        self.code = code


def default_dir() -> Path:
    return home() / ".claude" / "skills"


def valid_name(name) -> bool:
    return isinstance(name, str) and 0 < len(name) <= 64 and name.replace("_", "a").replace("-", "a").isalnum()


def safe_rel(rel) -> str | None:
    """A relative path that stays inside the skill directory; None for anything else."""
    if not isinstance(rel, str) or not rel or "\\" in rel or "\x00" in rel or rel.startswith("/"):
        return None
    parts = rel.split("/")
    return rel if all(p not in ("", ".", "..") for p in parts) else None


def _rpc(bridge, rid: int, method: str, params: dict) -> dict:
    """One call through `Bridge.forward` (gating, versions, re-sign-in as for any host); the `result` object."""
    raw = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}).encode()
    reply = bridge.forward(raw)
    try:
        msg = json.loads(reply) if reply else {}
    except ValueError:
        msg = {}
    if "result" not in msg:
        err = msg.get("error") or {"message": "no answer"}
        raise SkillError(f"{method}: {err.get('message') or err}")
    return msg["result"] if isinstance(msg["result"], dict) else {}


def list_skills(bridge) -> list[dict]:
    skills = _rpc(bridge, 1, "skills/list", {}).get("skills")
    return [s for s in skills if isinstance(s, dict) and valid_name(s.get("name"))] if isinstance(skills, list) else []


def read_file(bridge, rid: int, name: str, rel: str) -> bytes:
    uri = f"{SCHEME}{name}/{rel}"
    contents = _rpc(bridge, rid, "resources/read", {"uri": uri}).get("contents") or []
    c = contents[0] if contents and isinstance(contents[0], dict) else {}
    if isinstance(c.get("text"), str):
        data = c["text"].encode()
    elif isinstance(c.get("blob"), str):
        try:
            data = base64.b64decode(c["blob"], validate=True)
        except ValueError:
            raise SkillError(f"{uri}: blob is not base64") from None
    else:
        raise SkillError(f"{uri}: the worker returned no text or blob")
    if len(data) > MAX_FILE:
        raise SkillError(f"{uri}: {len(data)} bytes, over the 256 KiB limit")
    return data


def fetch(bridge, name: str) -> dict[str, bytes]:
    """Every file of the skill, by relative path; `SKILL.md` always among them."""
    skill = next((s for s in list_skills(bridge) if s.get("name") == name), None)
    if skill is None:
        raise SkillError(f"skill {name!r}: the worker does not serve it (see `ramen-mcp-bridge skills list`)")
    files = skill.get("files") if isinstance(skill.get("files"), list) else []
    rels = []
    for f in ["SKILL.md", *files]:
        rel = safe_rel(f)
        if rel is None:
            raise SkillError(f"skill {name!r}: path refused: {f!r}")
        if rel not in rels:
            rels.append(rel)
    return {rel: read_file(bridge, i + 2, name, rel) for i, rel in enumerate(rels)}


def _scan(pol, staged: Path, name: str) -> None:
    """§30.3 before the files reach the skills directory; raises SkillError(EXIT_BLOCK) for DO_NOT_INSTALL."""
    exe = scan.find_exe("skillspector")
    if exe is None:
        say(f"skillspector: not on PATH; install it with: {scan.INSTALL_HINT}")
        raise SkillError(f"skill {name!r}: the group requires a SkillSpector scan and none can run", EXIT_BLOCK)
    baseline = pol.baseline_file if pol.baseline_file is not None and pol.baseline_file.is_file() else None
    report = scan.run_scan(exe, staged / name if baseline else staged, baseline)
    results = scan.parse(report, name) if report is not None else None
    if results is None:
        raise SkillError(f"skill {name!r}: the scan failed", EXIT_BLOCK)
    for n, verdict in results:
        if verdict == "DO_NOT_INSTALL":
            raise SkillError(f"skill {name!r}: SkillSpector says DO_NOT_INSTALL — nothing written", EXIT_BLOCK)
        say(f"skillspector: {n}: {verdict}")


def install(bridge, pol, name: str, dest: Path, target: str, group: str, zone: str) -> list[Path]:
    """Write the skill under `dest/<name>/`; the files written. A directory there that Ramen did not write is left
    alone (error); one it wrote is replaced."""
    if not valid_name(name):
        raise SkillError(f"skill name refused: {name!r}")
    files = fetch(bridge, name)
    ledger = Ledger()
    final = dest / name
    ours = {e.get("file") for e in ledger.entries if e.get("kind") == KIND and e.get("key") == name}
    if final.exists() and not ours:
        raise SkillError(f"{final} exists and was not installed by Ramen; remove it first")
    dest.mkdir(parents=True, exist_ok=True)
    staged = Path(tempfile.mkdtemp(prefix=".ramen-skill-", dir=dest))
    try:
        for rel, data in files.items():
            p = staged / name / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            with os.fdopen(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644), "wb") as f:
                f.write(data)
            os.chmod(p, 0o644)
        if pol is not None and pol.skillspector_required():
            _scan(pol, staged, name)
        if final.exists():
            shutil.rmtree(final)
        os.replace(staged / name, final)
    finally:
        shutil.rmtree(staged, ignore_errors=True)
    written = [final / rel for rel in files]
    ident = {"target": target, "group": group, "zone": zone}
    ledger.entries = [e for e in ledger.entries if not (e.get("kind") == KIND and e.get("key") == name)]
    for p in written:
        ledger.add({"kind": KIND, "file": str(p), "key": name, **ident})
    ledger.save()
    return written


def remove_file(entry: dict) -> None:
    """`policy remove`: the file goes, then the directories it leaves empty up to the skill's own."""
    path = Path(entry.get("file", ""))
    try:
        path.unlink()
    except OSError:
        return
    for d in path.parents:
        try:
            d.rmdir()  # only while empty; stops at the first directory that still holds something
        except OSError:
            break
        if d.name == entry.get("key"):
            break
