"""Starts the real server (uvicorn, real CLI) and checks that its console output leaks nothing."""
import os
import re
import socket
import subprocess
import sys
import time

import httpx

from .conftest import Dev, b64, envelope


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_real_server_output_has_no_ip_keys_or_tokens(tmp_path):
    keyfile = tmp_path / "elsewhere.key"
    keyfile.write_text("ef" * 32)
    port = free_port()
    env = dict(os.environ, NOC_DB_PATH=str(tmp_path / "noc.db"), NOC_DB_KEY_FILE=str(keyfile))
    p = subprocess.Popen([sys.executable, "-m", "app.cli", "serve", "--port", str(port)], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(50):
            try:
                httpx.get(f"http://127.0.0.1:{port}/nope"); break
            except httpx.TransportError:
                time.sleep(0.1)
        # read the binding token the way the operator would: from the phone's console
        deadline, buf = time.time() + 5, ""
        while "\n" not in buf.split("(enter it in the app):")[-1].strip() and time.time() < deadline:
            buf += p.stdout.readline()
            if re.search(r"[0-9a-f]{64}", buf):
                break
        token = re.search(r"[0-9a-f]{64}", buf).group(0)
        base = f"http://127.0.0.1:{port}"
        admin, user = Dev(), Dev()
        assert httpx.post(base + "/v1/admin/bind", json={"token": token, "pubkey": admin.pub_s}).status_code == 204
        body = b'{"role":"user"}'
        path = f"/v1/admin/users/{user.pub_s}"
        h = admin.headers("PUT", path, body); h["content-type"] = "application/json"
        assert httpx.put(base + path, content=body, headers=h).status_code == 204
        mid = b64(os.urandom(16)); tok = b64(os.urandom(32))
        import json
        body = json.dumps({"id": mid, "token": tok}).encode()
        h = user.headers("POST", "/v1/mailboxes", body); h["content-type"] = "application/json"
        assert httpx.post(base + "/v1/mailboxes", content=body, headers=h).status_code == 201
        pp = f"/v1/mailboxes/{mid}/packets"
        assert httpx.post(base + pp, content=envelope(), headers=user.headers("POST", pp, envelope())).status_code == 201
        httpx.get(base + pp, headers={"x-mailbox-token": tok})
        # stage 2 endpoints: anonymous send, anonymous prekeys, constant-size exchange
        httpx.post(base + pp, content=envelope())
        httpx.get(base + f"/v1/prekeys/{user.pub_s}")
        import base64
        raw = lambda x: base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
        slot = bytes([3]) + raw(mid) + raw(tok) + os.urandom(16) + raw(mid) + os.urandom(16384)
        assert len(httpx.post(base + "/v1/exchange", content=slot).content) == 1 + 16 + 16384
    finally:
        p.terminate()
        out = buf + p.communicate(timeout=10)[0]
    assert "127.0.0.1" not in out.replace("Uvicorn running on http://127.0.0.1", "")
    for secret in (admin.pub_s, user.pub_s, mid, tok):
        assert secret not in out
    assert out.count(token) == 1                    # token is shown once, on the console only
    # also confirm nothing was written to disk logs
    assert not [f for f in os.listdir(tmp_path) if f.endswith(".log")]
