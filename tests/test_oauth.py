"""Signing in through the console instead of presenting a group key (bridge 0.2.0), against a fake authorization
server that behaves like Ramen's (code + PKCE, refresh rotation, one-shot codes)."""

import hashlib
import http.server
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import grpc
import pytest
from test_bridge import fake, run  # noqa: F401 - fixture

from ramen_mcp_bridge import bridge, oauth
from ramen_proto.ramen.v1 import mcp_pb2_grpc


class FakeAS:
    """`/.well-known/oauth-authorization-server`, `/oauth/authorize` (records the request; the test plays the browser),
    `/oauth/token` (code once, verifier checked, refresh rotated). `access` is the token the fake worker accepts."""

    def __init__(self, access="good"):
        self.access, self.codes, self.refreshes, self.authorizes, self.token_calls = access, {}, set(), [], []
        self.dead_refresh = False
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def _json(self, status, body):
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                u = urllib.parse.urlparse(self.path)
                if u.path == "/.well-known/oauth-authorization-server":
                    base = f"http://127.0.0.1:{outer.port}"
                    return self._json(
                        200,
                        {
                            "issuer": base,
                            "authorization_endpoint": f"{base}/oauth/authorize",
                            "token_endpoint": f"{base}/oauth/token",
                        },
                    )
                if u.path == "/oauth/authorize":
                    q = dict(urllib.parse.parse_qsl(u.query))
                    outer.authorizes.append(q)
                    code = f"code-{len(outer.codes)}"
                    outer.codes[code] = q
                    return self._json(200, {"code": code})  # the test forwards it to the bridge's callback
                self._json(404, {"error": "not found"})

            def do_POST(self):
                form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
                outer.token_calls.append(form)
                if form.get("grant_type") == "authorization_code":
                    q = outer.codes.pop(form.get("code"), None)
                    if (
                        not q
                        or q["redirect_uri"] != form.get("redirect_uri")
                        or q["client_id"] != form.get("client_id")
                    ):
                        return self._json(
                            400, {"error": "invalid_grant", "error_description": "code is unknown or used"}
                        )
                    want = oauth.b64url(hashlib.sha256(form.get("code_verifier", "").encode()).digest())
                    if want != q["code_challenge"]:
                        return self._json(
                            400, {"error": "invalid_grant", "error_description": "code_verifier mismatch"}
                        )
                elif form.get("grant_type") == "refresh_token":
                    if outer.dead_refresh or form.get("refresh_token") not in outer.refreshes:
                        return self._json(
                            400, {"error": "invalid_grant", "error_description": "refresh token is unknown"}
                        )
                    outer.refreshes.discard(form["refresh_token"])
                else:
                    return self._json(400, {"error": "unsupported_grant_type", "error_description": "no"})
                rt = f"rt-{len(outer.token_calls)}"
                outer.refreshes.add(rt)
                return self._json(
                    200,
                    {
                        "access_token": outer.access,
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "refresh_token": rt,
                        "scope": "mcp:demo:local",
                    },
                )

            def log_message(self, *_):
                pass

        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.port}"

    def browser(self, url: str) -> None:
        """What a person's browser does: sign in (instantly here) and get sent back to the bridge's callback."""
        with urllib.request.urlopen(url) as r:
            code = json.loads(r.read())["code"]
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
        cb = q["redirect_uri"] + "?" + urllib.parse.urlencode({"code": code, "state": q["state"]})
        threading.Thread(target=lambda: urllib.request.urlopen(cb).read(), daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def auth():
    a = FakeAS()
    yield a
    a.close()


def test_login_exchanges_a_pkce_code_and_keeps_the_refresh_token(auth, tmp_path):
    store = oauth.TokenFile(tmp_path / "t.json")
    c = oauth.Client(auth.url, "cid", "mcp:demo:local", store, opener=auth.browser)
    assert c.bearer() == "good"
    q = auth.authorizes[0]
    assert q["client_id"] == "cid" and q["scope"] == "mcp:demo:local" and q["code_challenge_method"] == "S256"
    assert q["redirect_uri"].startswith("http://127.0.0.1:") and q["redirect_uri"].endswith("/callback")
    assert q["resource"] == "mcp:demo:local" and len(q["state"]) >= 16
    saved = json.loads((tmp_path / "t.json").read_text())
    assert saved["refresh_token"] == "rt-1" and saved["expires_at"] > time.time()
    if os.name == "posix":  # Windows has no mode bits; the file lives in the per-user %LOCALAPPDATA% instead
        assert oct(os.stat(tmp_path / "t.json").st_mode & 0o777) == "0o600"
    assert c.bearer() == "good" and len(auth.authorizes) == 1 and len(auth.token_calls) == 1  # cached while fresh


def test_refresh_before_expiry_and_sign_in_again_when_the_refresh_token_is_dead(auth, tmp_path):
    store = oauth.TokenFile(tmp_path / "t.json")
    c = oauth.Client(auth.url, "cid", "mcp:demo:local", store, opener=auth.browser)
    c.bearer()
    c.tokens["expires_at"] = time.time() + 10  # inside the EARLY window
    assert c.bearer() == "good"
    assert auth.token_calls[-1]["grant_type"] == "refresh_token" and auth.token_calls[-1]["refresh_token"] == "rt-1"
    assert c.tokens["refresh_token"] == "rt-2" and len(auth.authorizes) == 1  # rotated, no browser
    auth.dead_refresh = True
    assert c.bearer(force=True) == "good"
    assert len(auth.authorizes) == 2 and c.tokens["refresh_token"] == "rt-4"  # browser again, fresh family
    # a second client reads the file and needs no browser
    c2 = oauth.Client(auth.url, "cid", "mcp:demo:local", store, opener=lambda url: pytest.fail("no browser expected"))
    assert c2.bearer() == "good"


def test_refused_or_absent_callbacks_are_errors(auth, tmp_path):
    store = oauth.TokenFile(tmp_path / "t.json")

    def deny(url):
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
        cb = q["redirect_uri"] + "?" + urllib.parse.urlencode({"error": "access_denied", "state": q["state"]})

        def hit():
            try:
                urllib.request.urlopen(cb).read()
            except urllib.error.HTTPError:
                pass  # the bridge answers a refusal with 400 on purpose

        threading.Thread(target=hit, daemon=True).start()

    c = oauth.Client(auth.url, "cid", "mcp:demo:local", store, opener=deny, login_timeout=5)
    with pytest.raises(oauth.OAuthError, match="access_denied"):
        c.bearer()
    c = oauth.Client(auth.url, "cid", "mcp:demo:local", store, opener=lambda url: None, login_timeout=0.3)
    with pytest.raises(oauth.OAuthError, match="timed out"):
        c.bearer()
    with pytest.raises(oauth.OAuthError, match="cannot read"):
        oauth.Client("http://127.0.0.1:1", "cid", "mcp:demo:local", store).metadata()


def test_bridge_signs_calls_with_the_token_and_retries_once_after_unauthenticated(auth, fake, tmp_path):  # noqa: F811
    stale = FakeAS(access="stale")  # first sign-in yields a token the worker refuses; the retry refreshes to a good one
    try:
        store = oauth.TokenFile(tmp_path / "t.json")
        c = oauth.Client(stale.url, "cid", "mcp:demo:local", store, opener=stale.browser)
        c.bearer()
        stale.access = "good"
        stub = mcp_pb2_grpc.McpStub(grpc.insecure_channel(fake.target))
        b = bridge.Bridge(stub, [("ramen-group", "demo"), ("ramen-zone", "local")], 5.0, bearer=c.bearer)
        out = run(b, b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
        assert json.loads(out)["result"] == {}
        assert [m.get("authorization") for m in fake.seen] == ["Bearer stale", "Bearer good"]
        assert stale.token_calls[-1]["grant_type"] == "refresh_token"
    finally:
        stale.close()


def test_parse_args_oauth(monkeypatch, tmp_path):
    monkeypatch.delenv("RAMEN_MCP_KEY", raising=False)
    for k in ("TARGET", "KEY", "OAUTH", "CLIENT_ID", "TOKEN_FILE"):
        monkeypatch.delenv(f"RAMEN_BRIDGE_{k}", raising=False)
    a = bridge.parse_args(
        [
            "--target",
            "h:443",
            "--tls",
            "--oauth",
            "https://console/",
            "--client-id",
            "cid",
            "--group",
            "demo",
            "--zone",
            "a",
        ]
    )
    assert a.oauth == "https://console" and a.client_id == "cid" and a.key is None
    assert a.token_file == str(oauth.default_token_file("https://console", "cid", "mcp:demo:a"))
    with pytest.raises(SystemExit):
        bridge.parse_args(["--target", "h:443", "--oauth", "https://console"])  # needs a client id
    with pytest.raises(SystemExit):
        bridge.parse_args(["--target", "h:443", "--oauth", "https://console", "--client-id", "cid"])  # needs group+zone
    monkeypatch.setenv("RAMEN_BRIDGE_OAUTH", "https://c2")
    monkeypatch.setenv("RAMEN_BRIDGE_CLIENT_ID", "env-cid")
    monkeypatch.setenv("RAMEN_BRIDGE_TOKEN_FILE", str(tmp_path / "tok.json"))
    a = bridge.parse_args(["--target", "h:443", "--group", "g", "--zone", "z", "--no-browser"])
    assert a.oauth == "https://c2" and a.client_id == "env-cid" and a.token_file == str(tmp_path / "tok.json")
    assert a.no_browser is True


def test_default_token_file_is_per_user_on_each_platform(monkeypatch, tmp_path):
    monkeypatch.setattr(oauth.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert oauth.default_token_file("c", "i", "s").parent == tmp_path / "local" / "ramen-mcp-bridge"
    monkeypatch.setattr(oauth.sys, "platform", "linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    assert oauth.default_token_file("c", "i", "s").parent == tmp_path / "xdg" / "ramen-mcp-bridge"


def test_ca_bundle_verifies_the_console_too(monkeypatch, tmp_path):
    """Ramen 0.6.1 AWS run: `--ca` reached the gRPC channel only, so `--oauth` against a console with the self-signed
    certificate the AWS guide makes failed with CERTIFICATE_VERIFY_FAILED on discovery."""
    seen = []

    class Resp:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps(self.body).encode()

    def fake_urlopen(req, timeout=None, context=None):
        seen.append(context)
        return Resp({"token_endpoint": "https://c/oauth/token", "access_token": "a", "expires_in": 60})

    loaded = []
    monkeypatch.setattr(oauth.ssl, "create_default_context", lambda cafile=None: loaded.append(cafile) or "ctx")
    monkeypatch.setattr(oauth.urllib.request, "urlopen", fake_urlopen)
    store = oauth.TokenFile(tmp_path / "t.json")
    store.save({"refresh_token": "r", "expires_at": 0})
    c = oauth.Client("https://c", "cid", "mcp:demo:a", store, ca="lb.pem")
    c.refresh()
    assert loaded == ["lb.pem"] and seen == ["ctx", "ctx"]  # discovery and the token call
    seen.clear()
    oauth.Client("https://c", "cid", "mcp:demo:a", store).metadata()
    assert seen == [None]

    made = {}

    class NoSignIn:
        def __init__(self, *a, **k):
            made.update(k)

        def bearer(self):
            raise oauth.OAuthError("x")

    monkeypatch.setattr(oauth, "Client", NoSignIn)
    monkeypatch.setattr(bridge, "channel", lambda a: None)
    args = ["--target", "t:443", "--ca", "lb.pem", "--oauth", "https://c", "--client-id", "cid", "--group", "g"]
    assert bridge.main([*args, "--zone", "z"]) == 2
    assert made.get("ca") == "lb.pem"
