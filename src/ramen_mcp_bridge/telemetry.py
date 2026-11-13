"""Telemetry through Ramen (bridge 0.4.0, CONTRACTS §26.3 client side).

The token answer's `telemetry` object (`otlp_endpoint`, `headers`, `resource_attributes`, `version`, `required`) rests
in a `Vault`: encrypted under a key drawn at random for this process, never written to disk, never logged. Every call
the bridge forwards is recorded; the host reports its model and non-MCP tool calls through the `ramen_report` tool; a
gated call (`tools/call`, `prompts/get`, `resources/read`) carries everything recorded since the last report under
`params._meta["io.ramen/telemetry"]`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time

META = "io.ramen/telemetry"
GATED = frozenset({"tools/call", "prompts/get", "resources/read"})
KINDS = ("mcp", "llm", "tool", "other")
MAX_EVENTS, MAX_BYTES, MAX_REASONING, MAX_PENDING = 200, 64 * 1024, 4096, 2000
REPORT_REQUIRED, CONFIG_STALE = -32024, -32025

TOOL = {
    "name": "ramen_report",
    "description": (
        "Report your own activity to Ramen before your next Ramen call. This Ramen group records telemetry about "
        "what its clients do; the bridge already reports every MCP call it forwards, and you must report, with this "
        "tool, every model call (kind 'llm', name = the model) and every non-MCP tool call (kind 'tool', name = the "
        "tool) you made since your last Ramen call, with your reasoning for it. Nothing is sent until the next "
        "Ramen tools/call, prompts/get or resources/read, which carries the reports."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "kind": {"type": "string", "enum": ["llm", "tool", "other"]},
            "name": {"type": "string", "description": "model name, tool name, or what else it was"},
            "ms": {"type": "integer", "minimum": 0, "description": "how long it took, milliseconds"},
            "ok": {"type": "boolean", "description": "whether it succeeded"},
            "reasoning": {"type": "string", "description": "why you made it (up to 4 KiB is kept)"},
        },
        "required": ["kind", "name", "ms", "ok"],
    },
}


class Vault:
    """One JSON object encrypted in memory: HMAC-SHA256 in counter mode as the key stream (encrypt-then-MAC with a
    second derived key), stdlib only — the bridge takes no binary dependency for one small secret. The key lives in
    this instance only; `repr` shows nothing."""

    def __init__(self):
        self._key = secrets.token_bytes(32)
        self._blob: bytes | None = None

    def __repr__(self) -> str:
        return f"Vault({'sealed' if self._blob else 'empty'})"

    def _sub(self, label: bytes) -> bytes:
        return hmac.new(self._key, label, hashlib.sha256).digest()

    def _xor(self, nonce: bytes, data: bytes) -> bytes:
        enc, out, i = self._sub(b"enc"), b"", 0
        while len(out) < len(data):
            out += hmac.new(enc, nonce + i.to_bytes(4, "big"), hashlib.sha256).digest()
            i += 1
        return bytes(a ^ b for a, b in zip(data, out))

    def seal(self, obj: dict | None) -> None:
        if obj is None:
            self._blob = None
            return
        nonce = secrets.token_bytes(16)
        ct = self._xor(nonce, json.dumps(obj).encode())
        self._blob = nonce + ct + hmac.new(self._sub(b"mac"), nonce + ct, hashlib.sha256).digest()

    def open(self) -> dict | None:
        if self._blob is None:
            return None
        nonce, ct, tag = self._blob[:16], self._blob[16:-32], self._blob[-32:]
        if not hmac.compare_digest(tag, hmac.new(self._sub(b"mac"), nonce + ct, hashlib.sha256).digest()):
            raise ValueError("telemetry vault: bad tag")
        return json.loads(self._xor(nonce, ct))


def _ts(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int(t * 1000) % 1000:03d}Z"


class Recorder:
    """Events since the last report, oldest first. `take` builds the next report (seq +1, within the limits) and
    keeps what it took as in flight until `commit` (the worker accepted it) or `restore` (it never got there)."""

    def __init__(self):
        self.pending: list[dict] = []
        self.inflight: list[dict] = []
        self.seq = 0

    def record(self, kind: str, name: str, ms: int, ok: bool, reasoning: str | None = None, start: float | None = None):
        ev = {"ts": _ts(start if start is not None else time.time() - ms / 1000), "kind": kind, "name": name}
        ev.update(ms=int(ms), ok=bool(ok))
        if reasoning:
            ev["reasoning"] = reasoning[:MAX_REASONING]
        self.pending.append(ev)
        del self.pending[:-MAX_PENDING]

    def take(self, version: str) -> dict:
        self.seq += 1
        rep: dict = {"version": version, "seq": self.seq, "events": []}
        size = len(json.dumps(rep).encode())
        taken = 0
        for ev in self.pending[:MAX_EVENTS]:
            size += len(json.dumps(ev).encode()) + 2
            if size > MAX_BYTES:
                break
            taken += 1
        self.inflight, self.pending = self.pending[:taken], self.pending[taken:]
        rep["events"] = list(self.inflight)
        return rep

    def commit(self) -> None:
        self.inflight = []

    def restore(self) -> None:
        self.pending[:0] = self.inflight
        self.inflight = []


class Telemetry:
    def __init__(self, vault: Vault | None = None):
        self.vault, self.recorder = vault or Vault(), Recorder()

    def version(self) -> str | None:
        cfg = self.vault.open()
        return cfg.get("version") if cfg else None

    def adopt(self, version: str) -> None:
        """A worker named a version the bridge has no config for and cannot sign in to get: report under it."""
        self.vault.seal({"version": version})

    def handle_report(self, args: object) -> str | None:
        """`ramen_report` from the host: record it; the text to answer, or None when the arguments are wrong."""
        if not isinstance(args, dict) or args.get("kind") not in KINDS or not isinstance(args.get("name"), str):
            return None
        ms, ok, why = args.get("ms"), args.get("ok"), args.get("reasoning")
        if not isinstance(ms, int) or isinstance(ms, bool) or ms < 0 or not isinstance(ok, bool):
            return None
        if why is not None and not isinstance(why, str):
            return None
        self.recorder.record(args["kind"], args["name"], ms, ok, why)
        return f"recorded ({len(self.recorder.pending)} pending; sent with the next Ramen call)"
