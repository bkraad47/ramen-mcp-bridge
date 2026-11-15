"""The local SkillSpector scan (bridge 0.6.0, CONTRACTS §30.3): when the group's policy requires it, `policy check`
(so the Claude Code SessionStart hook) and `policy show` run `skillspector scan <dir> --recursive --no-llm --format
json` over the skill directories on this machine (`~/.claude/skills`, `<cwd>/.claude/skills`, `~/.codex/skills`, the
ones that exist and hold a skill). A directory with exactly one skill and a bundle baseline is scanned skill by
skill with `--baseline`. `DO_NOT_INSTALL` for any skill, a scanner that fails, or no `skillspector` binary → exit 3;
`CAUTION` is printed. Results are cached per directory content hash in `~/.ramen/scans/<host>/` for 24 h.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .policy import Policy, home, host_of, say, write_private

INSTALL_HINT = "uv tool install 'git+https://github.com/NVIDIA/SkillSpector.git@v2.13.4'"
BLOCK = "Ramen policy: fix or remove these skills — Ramen cannot be used with them"
EXIT_BLOCK = 3
CACHE_TTL = 24 * 3600
TIMEOUT = 600


def skills_in(d: Path) -> list[Path]:
    """The immediate subdirectories holding a `SKILL.md` (what `--recursive` scans)."""
    try:
        return sorted(p for p in d.iterdir() if p.is_dir() and (p / "SKILL.md").is_file())
    except OSError:
        return []


def skill_dirs(cwd: Path | None = None) -> list[Path]:
    roots = [home() / ".claude" / "skills", (cwd or Path.cwd()) / ".claude" / "skills", home() / ".codex" / "skills"]
    out: list[Path] = []
    for r in roots:
        if r.is_dir() and r not in out and skills_in(r):
            out.append(r)
    return out


def content_hash(d: Path, baseline: Path | None) -> str:
    h = hashlib.sha256()
    for root, dirs, files in os.walk(d):
        dirs.sort()
        for f in sorted(files):
            p = Path(root) / f
            h.update(str(p.relative_to(d)).encode())
            try:
                h.update(p.read_bytes())
            except OSError:
                pass
    if baseline is not None and baseline.is_file():
        h.update(b"--baseline")
        h.update(baseline.read_bytes())
    return h.hexdigest()[:32]


def cache_path(target: str, digest: str) -> Path:
    return home() / ".ramen" / "scans" / host_of(target) / f"{digest}.json"


def _verdict(text) -> str:
    v = str(text or "UNKNOWN").strip().upper().replace("-", "_").replace(" ", "_")
    return v or "UNKNOWN"


def parse(report: dict, fallback_name: str) -> list[tuple[str, str]]:
    """`[(skill, verdict)]` from the aggregate shape (`skills[].risk_severity`) or the single-skill one
    (`risk_assessment.recommendation`)."""
    skills = report.get("skills")
    if isinstance(skills, list) and skills:
        out = []
        for s in skills:
            if not isinstance(s, dict):
                continue
            name = s.get("name") or Path(str(s.get("path") or fallback_name)).name
            out.append((str(name), _verdict(s.get("risk_severity") or s.get("risk_recommendation"))))
        return out
    ra = report.get("risk_assessment")
    rec = ra.get("recommendation") if isinstance(ra, dict) else report.get("risk_recommendation")
    return [(str(report.get("skill_name") or report.get("name") or fallback_name), _verdict(rec))]


def run_scan(exe: str, target: Path, baseline: Path | None) -> dict | None:
    """One `skillspector scan`; None when the scanner produced no report."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.json"
        cmd = [exe, "scan", str(target), "--no-llm", "--format", "json", "-o", str(out)]
        cmd += ["--baseline", str(baseline)] if baseline else ["--recursive"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            say(f"skillspector failed on {target}: {e}")
            return None
        try:
            report = json.loads(out.read_text() if out.is_file() else proc.stdout)
        except (OSError, ValueError):
            tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-1:]
            say(f"skillspector failed on {target} (exit {proc.returncode}): {' '.join(tail)}")
            return None
    return report if isinstance(report, dict) else None


def scan_dir(exe: str, d: Path, baseline: Path | None, target: str) -> list[tuple[str, str]] | None:
    """The verdicts for one skill root, from the cache when its contents have not changed."""
    skills = skills_in(d)
    use_baseline = baseline if (baseline is not None and baseline.is_file() and len(skills) == 1) else None
    digest = content_hash(d, use_baseline)
    cache = cache_path(target, digest)
    try:
        c = json.loads(cache.read_text())
        if time.time() - float(c["at"]) < CACHE_TTL:
            return [(str(n), str(v)) for n, v in c["results"]]
    except (OSError, ValueError, KeyError, TypeError):
        pass
    if use_baseline is not None:
        report = run_scan(exe, skills[0], use_baseline)
        results = parse(report, skills[0].name) if report is not None else None
    else:
        report = run_scan(exe, d, None)
        results = parse(report, d.name) if report is not None else None
    if results is not None:
        write_private(cache, json.dumps({"at": time.time(), "dir": str(d), "results": results}))
    return results


def check(pol: Policy, cwd: Path | None = None) -> int:
    """The local scan the policy asks for: 0 when every skill may stay, EXIT_BLOCK else."""
    if not pol.skillspector_required():
        return 0
    dirs = skill_dirs(cwd)
    if not dirs:
        return 0
    exe = shutil.which("skillspector")
    if exe is None:
        say(f"skillspector: not on PATH; install it with: {INSTALL_HINT}")
        say(BLOCK)
        return EXIT_BLOCK
    target = pol.target or ""
    blocked: list[str] = []
    for d in dirs:
        results = scan_dir(exe, d, pol.baseline_file, target)
        if results is None:
            blocked.append(f"{d} (scan failed)")
            continue
        for name, verdict in results:
            if verdict == "DO_NOT_INSTALL":
                blocked.append(f"{d}: {name} DO_NOT_INSTALL")
            elif verdict == "CAUTION":
                say(f"skillspector: {d}: {name} CAUTION")
        say(f"skillspector: {d}: {len(results)} skills: {_summary(results)}")
    if blocked:
        for b in blocked:
            say(f"skillspector: {b}")
        say(BLOCK)
        return EXIT_BLOCK
    return 0


def _summary(results: list[tuple[str, str]]) -> str:
    worst = max(
        (v for _, v in results),
        key=lambda v: (
            ["SAFE", "UNKNOWN", "CAUTION", "DO_NOT_INSTALL"].index(v)
            if v in ("SAFE", "UNKNOWN", "CAUTION", "DO_NOT_INSTALL")
            else 1
        ),
    )
    return worst
