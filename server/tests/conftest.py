import base64
import os
import time

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from app.admin.bind import BindState
from app.auth import signing_message
from app import pq
from app.config import ENVELOPE_SIZE, Settings
from app.main import create_app

KEY = "ab" * 32


def b64(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()


class Dev:
    def __init__(self, admin=False):
        self.sk = SigningKey.generate()
        self.pub = bytes(self.sk.verify_key)
        self.pub_s = b64(self.pub)
        self.pq = pq.keypair() if admin else None          # administrators hold an ML-DSA-65 key as well

    def headers(self, method, path, body=b"", ts=None, nonce=None):
        ts = str(ts if ts is not None else int(time.time()))
        nonce = nonce or b64(os.urandom(16))
        msg = signing_message(method, path, ts, nonce, body)
        sig = self.sk.sign(msg).signature
        h = {"x-key": self.pub_s, "x-ts": ts, "x-nonce": nonce, "x-sig": b64(sig)}
        if self.pq:
            h["x-pq-sig"] = b64(pq.sign(self.pq[1], b"NOC1-PQ\n" + msg))
        return h


class Api:
    def __init__(self, client):
        self.c = client

    def call(self, dev, method, path, json=None, content=None, **kw):
        import json as j
        body = content if content is not None else (j.dumps(json).encode() if json is not None else b"")
        h = dev.headers(method, path, body, **kw)
        if json is not None:
            h["content-type"] = "application/json"
        return self.c.request(method, path, content=body, headers=h)


@pytest.fixture
def env(tmp_path):
    settings = Settings(db_path=str(tmp_path / "noc.db"), db_key_hex=KEY, packet_ttl_s=3600)
    bind = BindState()
    token = bind.issue()
    app = create_app(settings, bind)
    with TestClient(app) as client:
        api = Api(client)
        admin = Dev(admin=True)
        r = client.post("/v1/admin/bind", json={"token": token, "pubkey": admin.pub_s, "pq_pubkey": b64(admin.pq[0])})
        assert r.status_code == 204
        yield type("E", (), dict(app=app, client=client, api=api, admin=admin, settings=settings,
                                 token=token, path=settings.db_path))


@pytest.fixture
def user(env):
    d = Dev()
    assert env.api.call(env.admin, "PUT", f"/v1/admin/users/{d.pub_s}", json={"role": "user"}).status_code == 204
    return d


def envelope(fill=b"x"):
    return fill * ENVELOPE_SIZE
