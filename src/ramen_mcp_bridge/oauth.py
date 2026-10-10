"""Sign in as a person instead of presenting a group key (Ramen 0.5.95 / bridge 0.2.0).

The console is Ramen's OAuth 2.1 authorization server (CONTRACTS §16.3): authorization code + PKCE S256 for a
pre-registered public client, access tokens the worker verifies by itself, refresh tokens rotated on use. The bridge
opens the person's browser on the console's sign-in page (password, magic link, or the configured provider — Microsoft
Entra ID, Google Workspace, any OIDC issuer), receives the code on a loopback port (RFC 8252), exchanges it, and keeps
the refresh token in a file only the user can read. Tokens are refreshed before they expire and after an
UNAUTHENTICATED call; when the refresh token is gone or dead the browser flow runs again.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import secrets
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections.abc import Callable
from pathlib import Path

EARLY = 60  # refresh this many seconds before the access token expires


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def pkce() -> tuple[str, str]:
    verifier = b64url(secrets.token_bytes(32))
    return verifier, b64url(hashlib.sha256(verifier.encode()).digest())


def default_token_file(console: str, client_id: str, scope: str) -> Path:
    key = hashlib.sha256(f"{console}|{client_id}|{scope}".encode()).hexdigest()[:16]
    if sys.platform == "win32":  # no mode bits on Windows; %LOCALAPPDATA% is per-user by ACL and never roams
        root = os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local"
    else:
        root = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    base = Path(root) / "ramen-mcp-bridge"
    return base / f"tokens-{key}.json"


class TokenFile:
    def __init__(self, path: Path):
        self.path = Path(path)

    def load(self) -> dict | None:
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return None

    def save(self, tokens: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            json.dump(tokens, f)
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    def clear(self) -> None:
        try:
            self.path.unlink()
        except OSError:
            pass


class MemoryStore:
    """0.3.0 default: tokens live in this process only. Nothing touches the disk; a new bridge signs in again."""

    def load(self) -> dict | None:
        return None

    def save(self, tokens: dict) -> None:
        pass

    def clear(self) -> None:
        pass


class KeychainStore:
    """0.3.0 `--keychain`: the tokens live in the operating system's secret store, behind its own access control —
    macOS Keychain through `security`, a Secret Service (GNOME Keyring, KWallet) through `secret-tool`. Nothing is
    written as a file. `available()` says whether this machine has one."""

    SERVICE = "ramen-mcp-bridge"

    def __init__(self, account: str, runner: Callable[..., object] | None = None):
        import shutil
        import subprocess

        self.account = account
        self.tool = next((t for t in ("security", "secret-tool") if shutil.which(t)), None)
        self._run = runner or (lambda cmd, **kw: subprocess.run(cmd, capture_output=True, text=True, check=False, **kw))

    @classmethod
    def available(cls) -> bool:
        import shutil

        return any(shutil.which(t) for t in ("security", "secret-tool"))

    def _cmd(self, op: str) -> list[str]:
        if self.tool == "security":
            base = {"load": "find-generic-password", "save": "add-generic-password", "clear": "delete-generic-password"}
            cmd = ["security", base[op], "-a", self.account, "-s", self.SERVICE]
            return cmd + (["-w"] if op == "load" else ["-U"] if op == "save" else [])
        base = {"load": "lookup", "save": "store", "clear": "clear"}
        cmd = ["secret-tool", base[op]] + (["--label", self.SERVICE] if op == "save" else [])
        return cmd + ["service", self.SERVICE, "account", self.account]

    def load(self) -> dict | None:
        if not self.tool:
            return None
        r = self._run(self._cmd("load"))
        try:
            return json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else None  # type: ignore[union-attr]
        except ValueError:
            return None

    def save(self, tokens: dict) -> None:
        if not self.tool:
            raise OAuthError("no keychain tool on this machine (security / secret-tool)")
        raw = json.dumps(tokens)
        if self.tool == "security":
            self._run(self._cmd("save") + ["-w", raw])
        else:
            self._run(self._cmd("save"), input=raw)

    def clear(self) -> None:
        if self.tool:
            self._run(self._cmd("clear"))


class OAuthError(Exception):
    pass


class SignInRequired(OAuthError):
    """0.3.0: a call arrived while no valid token is held. The browser flow has been started; `url` is where the
    person signs in. The bridge turns this into a JSON-RPC error the AI client can read out to the person."""

    def __init__(self, url: str):
        super().__init__(f"sign in to Ramen first: open {url} and approve, then retry")
        self.url = url


def _post_form(url: str, form: dict, timeout: float, context=None) -> dict:
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
            raise OAuthError(f"{body.get('error')}: {body.get('error_description')}") from None
        except ValueError:
            raise OAuthError(f"HTTP {e.code} from {url}") from None


class Client:
    """One console + one registered client id + one scope (`mcp:<group>:<zone>`)."""

    def __init__(
        self,
        console: str,
        client_id: str,
        scope: str,
        store: TokenFile | MemoryStore | KeychainStore | None = None,
        opener: Callable[[str], object] | None = None,
        timeout: float = 60.0,
        login_timeout: float = 300.0,
        listen: tuple[str, int] = ("127.0.0.1", 0),
        ca: str | None = None,
        idle_secs: float = 1800.0,
    ):
        """`store` (0.3.0): where tokens rest — `MemoryStore` (default, nothing on disk), `KeychainStore` (the OS
        secret store) or `TokenFile` (a plain 0600 file; opt-in, for automation). `idle_secs`: tokens are forgotten
        this long after the last call (default thirty minutes; 0 keeps them for the console's own lifetimes), and the
        next call needs a fresh sign-in."""
        self.console, self.client_id, self.scope = console.rstrip("/"), client_id, scope
        self.store = store if store is not None else MemoryStore()
        self.opener = opener or webbrowser.open
        self.timeout, self.login_timeout, self.listen = timeout, login_timeout, listen
        self.idle_secs = idle_secs
        self.last_used = time.time()
        self.pending_url: str | None = None
        self._login_thread: threading.Thread | None = None
        self._login_error: Exception | None = None
        self.tokens: dict | None = self.store.load()
        self._meta: dict | None = None
        # `--ca` verifies the console as well as the worker: the AWS guide's console cert is self-signed
        self.context = ssl.create_default_context(cafile=ca) if ca else None

    # --- discovery -----------------------------------------------------------------------------------------------
    def metadata(self) -> dict:
        if self._meta is None:
            url = f"{self.console}/.well-known/oauth-authorization-server"
            try:
                with urllib.request.urlopen(url, timeout=self.timeout, context=self.context) as r:
                    self._meta = json.loads(r.read())
            except (urllib.error.URLError, ValueError) as e:
                raise OAuthError(f"cannot read {url}: {e}") from e
        return self._meta

    # --- the browser flow ----------------------------------------------------------------------------------------
    def login(self) -> dict:
        verifier, challenge = pkce()
        state = b64url(secrets.token_bytes(16))
        got: dict = {}
        done = threading.Event()

        class Callback(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query))
                if self.path.startswith("/favicon"):
                    self.send_response(204)
                    self.end_headers()
                    return
                ok = self.path.startswith("/callback") and q.get("state") == state and "code" in q
                if ok and "code" not in got:
                    got.update(q)
                ok = ok or ("code" in got and self.path.startswith("/callback"))  # a reload after success
                # 0.2.3: the tab closes itself once the code is in (browsers allow window.close() only for tabs a
                # script opened — the bridge opened this one — so the text stays as the fallback).
                body = (
                    b"<html><body style='font-family:sans-serif'><h2>ramen-mcp-bridge</h2><p>"
                    + (
                        b"Signed in. This tab closes by itself; close it if it does not."
                        b"</p><script>setTimeout(function(){window.close()},800)</script>"
                        if ok
                        else b"Sign-in failed: " + json.dumps(q).encode() + b"</p>"
                    )
                    + b"</body></html>"
                )
                self.send_response(200 if ok else 400)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                if ok or q.get("error"):
                    got.setdefault("error", q.get("error"))
                    done.set()

            def log_message(self, *_):  # quiet
                pass

        srv = http.server.HTTPServer(self.listen, Callback)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            redirect = f"http://127.0.0.1:{port}/callback"
            params = {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": redirect,
                "scope": self.scope,
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": self.scope,
            }
            url = self.metadata()["authorization_endpoint"] + "?" + urllib.parse.urlencode(params)
            self.pending_url = url
            print(f"ramen-mcp-bridge: sign in at {url}", file=sys.stderr)
            self.opener(url)
            if not done.wait(self.login_timeout):
                raise OAuthError("sign-in timed out: no callback from the browser")
            if "code" not in got:
                raise OAuthError(f"sign-in refused: {got.get('error')}")
            tokens = _post_form(
                self.metadata()["token_endpoint"],
                {
                    "grant_type": "authorization_code",
                    "code": got["code"],
                    "client_id": self.client_id,
                    "redirect_uri": redirect,
                    "code_verifier": verifier,
                },
                self.timeout,
                self.context,
            )
        finally:
            # 0.2.3: keep answering for a moment — a browser that reloads, follows the fallback link or fetches the
            # favicon right after the callback must get the "Signed in" page, not ERR_CONNECTION_REFUSED
            threading.Event().wait(3.0)
            srv.shutdown()
            srv.server_close()
        return self._keep(tokens)

    def refresh(self) -> dict:
        if not (self.tokens or {}).get("refresh_token"):
            raise OAuthError("no refresh token")
        tokens = _post_form(
            self.metadata()["token_endpoint"],
            {"grant_type": "refresh_token", "refresh_token": self.tokens["refresh_token"], "client_id": self.client_id},
            self.timeout,
            self.context,
        )
        return self._keep(tokens)

    def _keep(self, tokens: dict) -> dict:
        tokens = dict(tokens)
        tokens["expires_at"] = time.time() + float(tokens.get("expires_in") or 3600)
        self.tokens = tokens
        self.store.save(tokens)
        return tokens

    # --- what the bridge asks for --------------------------------------------------------------------------------
    def forget(self, why: str = "") -> None:
        """Drop every token, here and in the store; the next call signs in again."""
        if self.tokens is not None and why:
            print(f"ramen-mcp-bridge: {why}; signing in again", file=sys.stderr)
        self.store.clear()
        self.tokens = None

    def bearer(self, force: bool = False, nonblocking: bool = False) -> str:
        """A valid access token: cached while fresh, refreshed when near its end (or on `force`), else a new sign-in.
        Idle tokens (no call for `idle_secs`) are forgotten first. With `nonblocking` (what the bridge uses while it
        serves an MCP client) a needed sign-in is started in the background and `SignInRequired` carries its URL, so
        the client is told instead of left hanging; the call succeeds once the person has approved."""
        now = time.time()
        if self.tokens and self.idle_secs and now - self.last_used > self.idle_secs:
            self.forget(f"no call for {int(self.idle_secs)} s, tokens forgotten")
        self.last_used = now
        t = self.tokens or {}
        if not force and t.get("access_token") and t.get("expires_at", 0) - EARLY > now:
            return t["access_token"]
        if t.get("refresh_token"):
            try:
                return self.refresh()["access_token"]
            except OAuthError as e:
                self.forget(f"refresh failed ({e})")
        if not nonblocking:
            return self.login()["access_token"]
        return self._login_in_background()

    def _login_in_background(self) -> str:
        th = self._login_thread
        if th is not None and not th.is_alive():  # a previous attempt ended: with tokens, or with an error
            self._login_thread = None
            if self._login_error is not None:
                err, self._login_error = self._login_error, None
                raise err
            if self.tokens and self.tokens.get("access_token"):
                return self.tokens["access_token"]
        if self._login_thread is None:
            self.pending_url = None

            def run():
                try:
                    self.login()
                except OAuthError as e:
                    self._login_error = e

            self._login_thread = threading.Thread(target=run, daemon=True)
            self._login_thread.start()
            for _ in range(50):  # the URL is known as soon as login() reaches the opener
                if self.pending_url or not self._login_thread.is_alive():
                    break
                time.sleep(0.1)
        if self.pending_url:
            raise SignInRequired(self.pending_url)
        raise OAuthError("sign-in could not be started")
