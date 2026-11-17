"""The policy bundle (bridge 0.5.0 / 0.6.0, CONTRACTS §29.3 and §30.3 client side).

The token answer's `telemetry`, `evals` and `skillspector` objects are the group's policy for this client. The bridge
keeps them at `~/.ramen/policy/<host>/<group>-<zone>.json` (0600, dirs 0700) — minus the telemetry `headers`, which
stay in the in-memory vault only (§26.3) — the evals config text at
`~/.ramen/evals/<host>/<group>/promptfooconfig.yaml` and the SkillSpector baseline at
`~/.ramen/skillspector/<host>/<group>/baseline.yaml` and the group's LLM configs (§31.3, manifest + files) at
`~/.ramen/configs/<host>/<group>/` and the guardrails pack (§36.3, `mcp/guardrails.yaml` + `mcp/guardrails/**`) at
`~/.ramen/guardrails/<host>/<group>/`. Every gated call carries `_meta["io.ramen/evals"]`, `_meta["io.ramen/skillspector"]`,
`_meta["io.ramen/configs"]` and `_meta["io.ramen/guardrails"]` = `{"version": v}`; `-32026` … `-32029` mean the worker
wants a newer one. The token answer's `guardrails.client_llm` (the credential the local rails use) stays in memory only.
`HOME` decides where `~` is (tests point it at a temp dir).
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

META = "io.ramen/evals"
SKILLSPECTOR_META = "io.ramen/skillspector"
CONFIGS_META = "io.ramen/configs"
GUARDRAILS_META = "io.ramen/guardrails"
EVALS_STALE = -32026  # missing or stale evals version: sign in again
SKILLSPECTOR_STALE = -32027  # missing or stale skillspector policy version: sign in again
CONFIGS_STALE = -32028  # missing or stale configs version: sign in again (and accept)
GUARDRAILS_STALE = -32029  # missing or stale guardrails policy version: sign in again
KEYS = ("telemetry", "evals", "skillspector", "configs", "guardrails")
MISSING = "Ramen policy missing: reconnect (sign in) — Ramen cannot be used without it"
STALE = "Ramen policy stale: reconnect (sign in) — the group's telemetry, evals, skillspector, configs or guardrails changed"
EXIT_MISSING = 3
PACK_LIMIT = 64 * 1024  # §36.3: the packed guardrails config is at most 64 KiB (before base64)
CLIENT_LLM_KEYS = ("provider", "model", "api_key", "base_url", "endpoint", "deployment")


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


def write_private(path: Path, data: str | bytes) -> None:
    """0600 file under 0700 directories, replaced atomically; text goes out as UTF-8 with its own line endings, the
    same bytes on every OS (Windows' text mode would write the locale code page and CRLF)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for p in (path.parent, path.parent.parent):
        if p != home() and p.is_relative_to(home() / ".ramen"):
            os.chmod(p, 0o700)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(data.encode() if isinstance(data, str) else data)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def public_telemetry(telemetry: dict | None) -> dict | None:
    """What the bundle keeps of the telemetry object: never the collector headers."""
    if not telemetry:
        return None
    return {k: v for k, v in telemetry.items() if k != "headers"}


def guardrails_dir(target: str, group: str) -> Path:
    return home() / ".ramen" / "guardrails" / host_of(target) / group


def _pack_member(name: str) -> str | None:
    """`mcp/guardrails.yaml` → `guardrails.yaml`, `mcp/guardrails/x/y.co` → `guardrails/x/y.co`; anything that is not a
    plain relative path inside the pack is refused."""
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if parts[:1] == ["mcp"]:
        parts = parts[1:]
    if not parts or any(p == ".." for p in parts) or parts[0] not in ("guardrails.yaml", "guardrails"):
        return None
    return "/".join(parts)


def unpack_guardrails(config: str, dest: Path) -> dict[str, bytes] | None:
    """The base64 tar of the pack as `{relative path: bytes}` written under `dest` (0700 / 0600, replaced whole); None
    when the pack is not a tar the bridge trusts (too big, odd member names, links)."""
    try:
        raw = base64.b64decode(config, validate=True)
    except (ValueError, TypeError):
        return None
    if len(raw) > PACK_LIMIT * 2:
        return None
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tar:
            for m in tar.getmembers():
                if m.isdir():
                    continue
                rel = _pack_member(m.name)
                if rel is None or not m.isfile() or m.size > PACK_LIMIT:
                    return None
                f = tar.extractfile(m)
                files[rel] = f.read() if f else b""
    except (tarfile.TarError, ValueError, OSError):
        return None
    if "guardrails.yaml" not in files or sum(len(b) for b in files.values()) > PACK_LIMIT:
        return None
    shutil.rmtree(dest, ignore_errors=True)
    for rel, data in files.items():
        p = dest / rel
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_private(p, data)
    for d in {dest, *(dest / Path(rel).parent for rel in files)}:
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
    return files


def dir_sha(d: Path | None) -> str | None:
    """sha256 over the files of the unpacked pack (relative path + bytes, sorted); None when the directory is gone."""
    if d is None or not d.is_dir():
        return None
    h = hashlib.sha256()
    for p in sorted(x for x in d.rglob("*") if x.is_file()):
        h.update(p.relative_to(d).as_posix().encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


def client_llm_of(guardrails: dict | None) -> dict | None:
    """The LLM credential the token answer hands the local rails: kept in memory, never written, never printed."""
    llm = (guardrails or {}).get("client_llm")
    if not isinstance(llm, dict) or not isinstance(llm.get("provider"), str) or not llm.get("provider"):
        return None
    return {k: v for k, v in llm.items() if k in CLIENT_LLM_KEYS and isinstance(v, str) and v}


class Policy:
    """One (target, group, zone)'s bundle: in memory always, on disk when `target` is known. `on_update` (the client
    config writer) runs after each save."""

    def __init__(self, target: str | None = None, group: str = "", zone: str = "", console: str | None = None):
        self.target, self.group, self.zone, self.console = target, group, zone, console
        self.bundle: dict | None = None
        self.on_update = None
        # §31.3: the access token and the person it names, held here for the files that carry them — never saved
        self.token: str | None = None
        self.user: str | None = None
        # §36.3: the credential the local rails call their LLM with — memory only, scrubbed from every log line
        self.client_llm: dict | None = None

    @property
    def path(self) -> Path | None:
        return bundle_path(self.target, self.group, self.zone) if self.target else None

    @property
    def evals_file(self) -> Path | None:
        return evals_path(self.target, self.group) if self.target else None

    @property
    def baseline_file(self) -> Path | None:
        return baseline_path(self.target, self.group) if self.target else None

    @property
    def configs_dir(self) -> Path | None:
        return home() / ".ramen" / "configs" / host_of(self.target) / self.group if self.target else None

    @property
    def guardrails_dir(self) -> Path | None:
        return guardrails_dir(self.target, self.group) if self.target else None

    # --- §36.3: the guardrails policy -------------------------------------------------------------------------
    def guardrails_version(self) -> str | None:
        return self.version_of("guardrails")

    def guardrails_required(self) -> bool:
        return bool(((self.bundle or {}).get("guardrails") or {}).get("required"))

    def guardrails_sha(self) -> str | None:
        """The content hash of the unpacked pack at the last sign-in; None = the bundle carries no config."""
        v = ((self.bundle or {}).get("guardrails") or {}).get("sha")
        return v if isinstance(v, str) and v else None

    def rails_enabled(self) -> bool:
        """`policy rails on|off`: on unless switched off; meaningful only when the bundle carries a config."""
        return (self.bundle or {}).get("rails") != "off"

    def set_rails(self, on: bool) -> None:
        self.bundle = {**(self.bundle or {}), "rails": "on" if on else "off"}
        if self.path is not None:
            write_private(self.path, json.dumps(self.bundle, indent=1) + "\n")

    def verify_guardrails(self) -> list[str]:
        """The unpacked pack's directory when it is gone or changed since the sign-in (as `configs.verify`)."""
        want = self.guardrails_sha()
        if want is None or self.guardrails_dir is None:
            return []
        return [] if dir_sha(self.guardrails_dir) == want else [str(self.guardrails_dir)]

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

    def configs_version(self) -> str | None:
        return self.version_of("configs")

    def configs_accepted(self) -> bool:
        return bool(((self.bundle or {}).get("configs") or {}).get("accepted"))

    def configs_pending(self) -> bool:
        """The group has configs this person has not accepted (§31.1): no call goes through until they do."""
        return bool((self.bundle or {}).get("configs")) and not self.configs_accepted()

    def telemetry_required(self) -> bool:
        return bool(((self.bundle or {}).get("telemetry") or {}).get("required"))

    def consent_url(self) -> str:
        console = (self.console or (self.bundle or {}).get("console") or "").rstrip("/")
        nxt = urllib.parse.quote(f"/groups/{self.group}", safe="/")
        return f"{console}/groups/{urllib.parse.quote(self.group, safe='')}/configs?next={nxt}"

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
            b = json.loads(self.path.read_bytes())
        except (OSError, ValueError):
            return None
        self.bundle = b if isinstance(b, dict) else None
        return self.bundle

    def update(
        self,
        telemetry: dict | None,
        evals: dict | None,
        skillspector: dict | None = None,
        configs: dict | None = None,
        token: str | None = None,
        user: str | None = None,
        guardrails: dict | None = None,
    ) -> dict:
        """After a sign-in (or refresh): keep the token answer's policy, write the bundle, the evals config, the
        SkillSpector baseline, the configs directory (manifest + files) and the guardrails pack; the token and the
        rails' LLM credential stay in memory."""
        ev = dict(evals) if evals else None
        config = ev.pop("config", None) if ev else None
        ss = dict(skillspector) if skillspector else None
        baseline = ss.pop("baseline", None) if ss else None
        cf = dict(configs) if configs else None
        manifest = cf.pop("manifest", None) if cf else None
        files = cf.pop("files", None) if cf else None
        gr = dict(guardrails) if guardrails else None
        pack = gr.pop("config", None) if gr else None
        self.client_llm = client_llm_of(gr)
        if gr:
            gr.pop("client_llm", None)
            gr.pop("sha", None)
            if err := gr.pop("error", None):  # the console could not pack it: the version still rides
                say(f"ramen-mcp-bridge: guardrails pack not delivered ({err}); the rails run on the worker only")
        self.token, self.user = token, user
        rails = (self.bundle or {}).get("rails")
        self.bundle = {
            "target": self.target,
            "group": self.group,
            "zone": self.zone,
            "console": self.console,
            "telemetry": public_telemetry(telemetry),
            "evals": ev,
            "skillspector": ss,
            "configs": cf,
            "guardrails": gr,
            **({"rails": rails} if rails else {}),
        }
        if self.path is not None:
            shutil.rmtree(self.guardrails_dir, ignore_errors=True)
            if gr is not None and isinstance(pack, str) and pack:
                if unpack_guardrails(pack, self.guardrails_dir) is None:
                    say("ramen-mcp-bridge: the guardrails pack in the token answer is not a tar the bridge accepts")
                else:
                    gr["sha"] = dir_sha(self.guardrails_dir)
            write_private(self.path, json.dumps(self.bundle, indent=1) + "\n")
            for path, text in ((self.evals_file, config), (self.baseline_file, baseline)):
                if isinstance(text, str) and text:
                    write_private(path, text)
                else:
                    try:
                        path.unlink()
                    except OSError:
                        pass
            shutil.rmtree(self.configs_dir, ignore_errors=True)
            if isinstance(manifest, str) and manifest:
                write_private(self.configs_dir / "manifest.yaml", manifest)
                for name, text in (files or {}).items() if isinstance(files, dict) else ():
                    if isinstance(text, str) and Path(name).name == name and name != "manifest.yaml":
                        write_private(self.configs_dir / name, text)
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
        for d in (self.configs_dir, self.guardrails_dir):
            if d is not None:
                shutil.rmtree(d, ignore_errors=True)
        self.bundle = None
        self.client_llm = None

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
            b = json.loads(p.read_bytes())
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
