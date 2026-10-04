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


class OAuthError(Exception):
    pass


def _post_form(url: str, form: dict, timeout: float) -> dict:
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
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
        store: TokenFile,
        opener: Callable[[str], object] | None = None,
        timeout: float = 60.0,
        login_timeout: float = 300.0,
        listen: tuple[str, int] = ("127.0.0.1", 0),
    ):
        self.console, self.client_id, self.scope, self.store = console.rstrip("/"), client_id, scope, store
        self.opener = opener or webbrowser.open
        self.timeout, self.login_timeout, self.listen = timeout, login_timeout, listen
        self.tokens: dict | None = store.load()
        self._meta: dict | None = None

    # --- discovery -----------------------------------------------------------------------------------------------
    def metadata(self) -> dict:
        if self._meta is None:
            url = f"{self.console}/.well-known/oauth-authorization-server"
            try:
                with urllib.request.urlopen(url, timeout=self.timeout) as r:
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
                ok = self.path.startswith("/callback") and q.get("state") == state and "code" in q
                if ok:
                    got.update(q)
                body = (
                    b"<html><body style='font-family:sans-serif'><h2>ramen-mcp-bridge</h2><p>"
                    + (b"Signed in. You can close this tab." if ok else b"Sign-in failed: " + json.dumps(q).encode())
                    + b"</p></body></html>"
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
            )
        finally:
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
        )
        return self._keep(tokens)

    def _keep(self, tokens: dict) -> dict:
        tokens = dict(tokens)
        tokens["expires_at"] = time.time() + float(tokens.get("expires_in") or 3600)
        self.tokens = tokens
        self.store.save(tokens)
        return tokens

    # --- what the bridge asks for --------------------------------------------------------------------------------
    def bearer(self, force: bool = False) -> str:
        """A valid access token: cached while fresh, refreshed when near its end (or on `force`), else a new sign-in."""
        t = self.tokens or {}
        if not force and t.get("access_token") and t.get("expires_at", 0) - EARLY > time.time():
            return t["access_token"]
        if t.get("refresh_token"):
            try:
                return self.refresh()["access_token"]
            except OAuthError as e:
                print(f"ramen-mcp-bridge: refresh failed ({e}); signing in again", file=sys.stderr)
                self.store.clear()
                self.tokens = None
        return self.login()["access_token"]
