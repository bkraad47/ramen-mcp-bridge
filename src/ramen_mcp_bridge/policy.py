"""The policy bundle (bridge 0.5.0 / 0.6.0, CONTRACTS §29.3 and §30.3 client side).

The token answer's `telemetry`, `evals` and `skillspector` objects are the group's policy for this client. The bridge
keeps them at `~/.ramen/policy/<host>/<group>-<zone>.json` (0600, dirs 0700) — minus the telemetry `headers`, which
stay in the in-memory vault only (§26.3) — the evals config text at
`~/.ramen/evals/<host>/<group>/promptfooconfig.yaml` and the SkillSpector baseline at
`~/.ramen/skillspector/<host>/<group>/baseline.yaml`. Every gated call carries
`_meta["io.ramen/evals"]` and `_meta["io.ramen/skillspector"]` = `{"version": v}`; `-32026` / `-32027` mean the worker
wants a newer one. `HOME` decides where `~` is (tests point it at a temp dir).
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

META = "io.ramen/evals"
SKILLSPECTOR_META = "io.ramen/skillspector"
EVALS_STALE = -32026  # missing or stale evals version: sign in again
SKILLSPECTOR_STALE = -32027  # missing or stale skillspector policy version: sign in again
KEYS = ("telemetry", "evals", "skillspector")
MISSING = "Ramen policy missing: reconnect (sign in) — Ramen cannot be used without it"
STALE = "Ramen policy stale: reconnect (sign in) — the group's telemetry, evals or skillspector config changed"
EXIT_MISSING = 3


def home() -> Path:
    return Path(os.environ.get("HOME") or Path.home())


def host_of(target: str) -> str:
    """`host:port` → a directory name (`host`); anything odd is reduced to safe characters."""
    host = target.rsplit(":", 1)[0] if re.fullmatch(r".+:\d+", target) else target
    return re.sub(r"[^A-Za-z0-9._-]", "_", host) or "unknown"


def bundle_path(target: str, group: str, zone: str) -> Path:
    return home() / ".ramen" / "policy" / host_of(target) / f"{group}-{zone}.json"


def evals_path(target: str, group: str) -> Path:
    return home() / ".ramen" / "evals" / host_of(target) / group / "promptfooconfig.yaml"


def baseline_path(target: str, group: str) -> Path:
    return home() / ".ramen" / "skillspector" / host_of(target) / group / "baseline.yaml"


def write_private(path: Path, text: str) -> None:
    """0600 file under 0700 directories, replaced atomically."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for p in (path.parent, path.parent.parent):
        if p != home() and p.is_relative_to(home() / ".ramen"):
            os.chmod(p, 0o700)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        f.write(text)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def public_telemetry(telemetry: dict | None) -> dict | None:
    """What the bundle keeps of the telemetry object: never the collector headers."""
    if not telemetry:
        return None
    return {k: v for k, v in telemetry.items() if k != "headers"}


class Policy:
    """One (target, group, zone)'s bundle: in memory always, on disk when `target` is known. `on_update` (the client
    config writer) runs after each save."""

    def __init__(self, target: str | None = None, group: str = "", zone: str = "", console: str | None = None):
        self.target, self.group, self.zone, self.console = target, group, zone, console
        self.bundle: dict | None = None
        self.on_update = None

    @property
    def path(self) -> Path | None:
        return bundle_path(self.target, self.group, self.zone) if self.target else None

    @property
    def evals_file(self) -> Path | None:
        return evals_path(self.target, self.group) if self.target else None

    @property
    def baseline_file(self) -> Path | None:
        return baseline_path(self.target, self.group) if self.target else None

    # --- what rides on calls -----------------------------------------------------------------------------------
    def version_of(self, key: str) -> str | None:
        v = ((self.bundle or {}).get(key) or {}).get("version")
        return v if isinstance(v, str) and v else None

    def evals_version(self) -> str | None:
        return self.version_of("evals")

    def skillspector_version(self) -> str | None:
        return self.version_of("skillspector")

    def skillspector_required(self) -> bool:
        return bool(((self.bundle or {}).get("skillspector") or {}).get("required"))

    def adopt(self, key: str, version: str) -> None:
        """A worker named a version the bridge has no policy for and cannot sign in to get (a static key)."""
        self.bundle = {**(self.bundle or {}), key: {**((self.bundle or {}).get(key) or {}), "version": version}}

    def adopt_evals(self, version: str) -> None:
        self.adopt("evals", version)

    # --- persistence --------------------------------------------------------------------------------------------
    def load(self) -> dict | None:
        if self.path is None:
            return None
        try:
            b = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return None
        self.bundle = b if isinstance(b, dict) else None
        return self.bundle

    def update(self, telemetry: dict | None, evals: dict | None, skillspector: dict | None = None) -> dict:
        """After a sign-in (or refresh): keep the token answer's policy, write the bundle, the evals config and the
        SkillSpector baseline."""
        ev = dict(evals) if evals else None
        config = ev.pop("config", None) if ev else None
        ss = dict(skillspector) if skillspector else None
        baseline = ss.pop("baseline", None) if ss else None
        self.bundle = {
            "target": self.target,
            "group": self.group,
            "zone": self.zone,
            "console": self.console,
            "telemetry": public_telemetry(telemetry),
            "evals": ev,
            "skillspector": ss,
        }
        if self.path is not None:
            write_private(self.path, json.dumps(self.bundle, indent=1) + "\n")
            for path, text in ((self.evals_file, config), (self.baseline_file, baseline)):
                if isinstance(text, str) and text:
                    write_private(path, text)
                else:
                    try:
                        path.unlink()
                    except OSError:
                        pass
        if self.on_update is not None:
            self.on_update(self)
        return self.bundle

    def remove_files(self) -> None:
        for p in (self.path, self.evals_file, self.baseline_file):
            try:
                if p is not None:
                    p.unlink()
            except OSError:
                pass
        self.bundle = None

    # --- the offline check against /.well-known/ramen-policy ----------------------------------------------------
    def fetch_current(self, timeout: float = 10.0, context=None) -> dict:
        console = (self.bundle or {}).get("console") or self.console
        if not console:
            raise RuntimeError("the bundle names no console")
        q = urllib.parse.urlencode({"group": self.group, "zone": self.zone})
        url = f"{console.rstrip('/')}/.well-known/ramen-policy?{q}"
        try:
            with urllib.request.urlopen(url, timeout=timeout, context=context) as r:
                cur = json.loads(r.read())
        except (urllib.error.URLError, ValueError, OSError) as e:
            raise RuntimeError(f"cannot read {url}: {e}") from e
        return cur if isinstance(cur, dict) else {}

    def compare(self, current: dict) -> list[str]:
        """What differs between the bundle and the console's current policy; empty = up to date."""
        out = []
        for key in KEYS:
            mine, theirs = (self.bundle or {}).get(key) or {}, current.get(key) or {}
            if (mine.get("version") or None) != (theirs.get("version") or None):
                out.append(f"{key} version {mine.get('version') or '-'} → {theirs.get('version') or '-'}")
            if bool(mine.get("required")) != bool(theirs.get("required")):
                out.append(f"{key} required {bool(mine.get('required'))} → {bool(theirs.get('required'))}")
        return out


def list_bundles() -> list[Path]:
    root = home() / ".ramen" / "policy"
    return sorted(root.glob("*/*.json")) if root.is_dir() else []


def find(target: str | None, group: str | None, zone: str | None) -> Policy | None:
    """The one bundle the flags name; with none given, the only bundle there is."""
    candidates = []
    for p in list_bundles():
        try:
            b = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(b, dict):
            continue
        if target and host_of(target) != p.parent.name:
            continue
        if group and b.get("group") != group:
            continue
        if zone and b.get("zone") != zone:
            continue
        candidates.append(b)
    if len(candidates) != 1:
        return None
    b = candidates[0]
    pol = Policy(
        b.get("target") or target, b.get("group") or group or "", b.get("zone") or zone or "", b.get("console")
    )
    pol.bundle = b
    return pol


def say(msg: str) -> None:
    print(msg, file=sys.stderr)
