import base64
import logging
import os

import pytest
from fastapi.testclient import TestClient

from app.admin.bind import BindState
from app.config import ENVELOPE_SIZE, Settings
from app.logging.setup import RedactFilter
from app.main import create_app

from app import pq

from .conftest import Dev, b64, envelope


def mailbox(env, owner):
    mid, tok = os.urandom(16), os.urandom(32)
    r = env.api.call(owner, "POST", "/v1/mailboxes", json={"id": b64(mid), "token": b64(tok)})
    assert r.status_code == 201
    return b64(mid), b64(tok)


# ------------------------------------------------------------ superadmin bind
def test_bind_token_is_one_time(env):
    other = Dev(admin=True)
    r = env.client.post("/v1/admin/bind", json={"token": env.token, "pubkey": other.pub_s, "pq_pubkey": b64(other.pq[0])})
    assert r.status_code == 404


def test_bind_wrong_token_locks_out(tmp_path):
    s = Settings(db_path=str(tmp_path / "a.db"), db_key_hex="cd" * 32)
    bind = BindState()
    good = bind.issue()
    with TestClient(create_app(s, bind)) as c:
        d = Dev(admin=True)
        for _ in range(5):
            assert c.post("/v1/admin/bind", json={"token": "0" * 64, "pubkey": d.pub_s, "pq_pubkey": b64(d.pq[0])}).status_code == 404
        assert c.post("/v1/admin/bind", json={"token": good, "pubkey": d.pub_s, "pq_pubkey": b64(d.pq[0])}).status_code == 404


def test_bind_malformed_rejected(env):
    assert env.client.post("/v1/admin/bind", json={"token": "x", "pubkey": "y"}).status_code == 422


# ------------------------------------------------------------ auth
def test_unregistered_device_rejected(env):
    assert env.api.call(Dev(), "GET", "/v1/admin/users").status_code == 401


def test_replay_rejected(env):
    h = env.admin.headers("GET", "/v1/admin/users")
    assert env.client.get("/v1/admin/users", headers=h).status_code == 200
    assert env.client.get("/v1/admin/users", headers=h).status_code == 401


def test_stale_timestamp_rejected(env):
    import time
    assert env.api.call(env.admin, "GET", "/v1/admin/users", ts=int(time.time()) - 3600).status_code == 401


def test_signature_binds_body_and_path(env, user):
    h = user.headers("POST", "/v1/mailboxes", b"{}")
    r = env.client.post("/v1/mailboxes", content=b'{"id":"a","token":"b"}', headers=h)
    assert r.status_code == 401


def test_user_cannot_administer(env, user):
    assert env.api.call(user, "GET", "/v1/admin/users").status_code == 403
    assert env.api.call(user, "PUT", f"/v1/admin/users/{Dev().pub_s}", json={"role": "user"}).status_code == 403


def test_cannot_demote_or_delete_superadmin(env):
    assert env.api.call(env.admin, "DELETE", f"/v1/admin/users/{env.admin.pub_s}").status_code == 404
    assert env.api.call(env.admin, "PUT", f"/v1/admin/users/{env.admin.pub_s}", json={"role": "user"}).status_code == 409


def test_role_superadmin_cannot_be_granted(env):
    assert env.api.call(env.admin, "PUT", f"/v1/admin/users/{Dev().pub_s}", json={"role": "superadmin"}).status_code == 422


# ------------------------------------------------------------ mailboxes
def test_roundtrip_and_ack(env, user):
    mid, tok = mailbox(env, user)
    sender = Dev()
    env.api.call(env.admin, "PUT", f"/v1/admin/users/{sender.pub_s}", json={"role": "user"})
    r = env.api.call(sender, "POST", f"/v1/mailboxes/{mid}/packets", content=envelope(b"a"))
    assert r.status_code == 201
    got = env.client.get(f"/v1/mailboxes/{mid}/packets", headers={"x-mailbox-token": tok}).json()
    assert len(got) == 1
    assert base64.urlsafe_b64decode(got[0]["data"] + "==") == envelope(b"a")
    pid = got[0]["id"]
    assert env.client.delete(f"/v1/mailboxes/{mid}/packets/{pid}", headers={"x-mailbox-token": tok}).status_code == 204
    assert env.client.get(f"/v1/mailboxes/{mid}/packets", headers={"x-mailbox-token": tok}).json() == []


def test_wrong_token_and_unknown_mailbox_look_identical(env, user):
    mid, _ = mailbox(env, user)
    bad = b64(os.urandom(32))
    a = env.client.get(f"/v1/mailboxes/{mid}/packets", headers={"x-mailbox-token": bad})
    b = env.client.get(f"/v1/mailboxes/{b64(os.urandom(16))}/packets", headers={"x-mailbox-token": bad})
    assert a.status_code == b.status_code == 404 and a.content == b.content


@pytest.mark.parametrize("size", [0, 1, ENVELOPE_SIZE - 1, ENVELOPE_SIZE + 1])
def test_only_exact_envelope_size_accepted(env, user, size):
    mid, _ = mailbox(env, user)
    assert env.api.call(user, "POST", f"/v1/mailboxes/{mid}/packets", content=b"x" * size).status_code == 400


def test_oversized_body_rejected_early(env, user):
    mid, _ = mailbox(env, user)
    r = env.client.post(f"/v1/mailboxes/{mid}/packets", content=b"x" * 100_000,
                        headers=user.headers("POST", f"/v1/mailboxes/{mid}/packets", b"x" * 100_000))
    assert r.status_code == 413


def test_packet_to_unknown_mailbox(env, user):
    assert env.api.call(user, "POST", f"/v1/mailboxes/{b64(os.urandom(16))}/packets", content=envelope()).status_code == 404


def test_mailbox_capacity(env, user):
    env.app.state.settings = Settings(db_path=env.path, db_key_hex="ab" * 32, mailbox_max_packets=2)
    mid, _ = mailbox(env, user)
    codes = [env.api.call(user, "POST", f"/v1/mailboxes/{mid}/packets", content=envelope()).status_code for _ in range(3)]
    assert codes == [201, 201, 404]


def test_bad_ids_rejected(env, user):
    for bad in ["x", "a" * 22 + "'", "../../etc", "a" * 100, "'; DROP TABLE packets;--"]:
        r = env.client.get(f"/v1/mailboxes/{bad}/packets", headers={"x-mailbox-token": b64(os.urandom(32))})
        assert r.status_code in (400, 404, 405)
    assert env.client.get("/v1/mailboxes/%27%3B%20DROP/packets", headers={"x-mailbox-token": "x"}).status_code == 400


def test_expired_packets_purged(env, user):
    mid, tok = mailbox(env, user)
    env.api.call(user, "POST", f"/v1/mailboxes/{mid}/packets", content=envelope())
    env.app.state.store.conn.execute("UPDATE packets SET expires=1")
    assert env.client.get(f"/v1/mailboxes/{mid}/packets", headers={"x-mailbox-token": tok}).json() == []
    assert env.app.state.store.purge_expired() == 1


def test_removing_user_revokes_everything(env, user):
    mid, tok = mailbox(env, user)
    env.api.call(user, "PUT", "/v1/prekeys", json={"bundle": b64(b"bundle"), "one_time": [b64(b"1")]})
    env.api.call(user, "POST", f"/v1/mailboxes/{mid}/packets", content=envelope())
    assert env.api.call(env.admin, "DELETE", f"/v1/admin/users/{user.pub_s}").status_code == 204
    assert env.api.call(user, "GET", "/v1/admin/users").status_code == 401
    assert env.client.get(f"/v1/mailboxes/{mid}/packets", headers={"x-mailbox-token": tok}).status_code == 404
    c = env.app.state.store.conn
    assert c.execute("SELECT COUNT(*) FROM packets").fetchone()[0] == 0
    assert c.execute("SELECT COUNT(*) FROM prekey_bundles").fetchone()[0] == 0


# ------------------------------------------------------------ prekeys
def test_one_time_prekeys_are_consumed(env, user):
    other = Dev()
    env.api.call(env.admin, "PUT", f"/v1/admin/users/{other.pub_s}", json={"role": "user"})
    env.api.call(user, "PUT", "/v1/prekeys", json={"bundle": b64(b"B"), "one_time": [b64(b"1"), b64(b"2")]})
    seen = [env.api.call(other, "GET", f"/v1/prekeys/{user.pub_s}").json()["one_time"] for _ in range(3)]
    assert seen == [b64(b"1"), b64(b"2"), None]


# ------------------------------------------------------------ websocket
def test_ws_wakeup_without_content(env, user):
    mid, tok = mailbox(env, user)
    with env.client.websocket_connect("/v1/ws") as ws:
        ws.send_text('{"mailbox":"%s","token":"%s"}' % (mid, tok))
        assert ws.receive_text() == "ok"
        env.api.call(user, "POST", f"/v1/mailboxes/{mid}/packets", content=envelope())
        assert ws.receive_text() == "new"


def test_ws_bad_token_closed(env, user):
    mid, _ = mailbox(env, user)
    with env.client.websocket_connect("/v1/ws") as ws:
        ws.send_text('{"mailbox":"%s","token":"%s"}' % (mid, b64(os.urandom(32))))
        with pytest.raises(Exception):
            ws.receive_text()


# ------------------------------------------------------------ storage / logs
def test_db_file_is_encrypted_and_wrong_key_fails(env, user):
    raw = open(env.path, "rb").read()
    assert not raw.startswith(b"SQLite format 3")
    from app.db.store import Store
    with pytest.raises(Exception):
        Store(env.path, "00" * 32, ENVELOPE_SIZE)


def test_no_ip_or_name_columns(env):
    cols = [r[1] for t in ("devices", "mailboxes", "packets", "prekey_bundles")
            for r in env.app.state.store.conn.execute(f"PRAGMA table_info({t})")]
    assert not any(c in ("ip", "name", "text", "address") for c in cols)


def test_redact_filter_removes_ips_and_keys():
    f = RedactFilter()
    rec = logging.LogRecord("x", 20, "", 0, "from 203.0.113.7 key %s tok %s v6 2001:db8::1", (b64(os.urandom(32)), os.urandom(32).hex()), None)
    f.filter(rec)
    out = rec.getMessage()
    assert "203.0.113.7" not in out and "2001:db8" not in out and "[redacted]" in out


def test_server_logs_contain_no_secrets(env, user, caplog):
    caplog.set_level(logging.DEBUG)
    mid, tok = mailbox(env, user)
    env.api.call(user, "POST", f"/v1/mailboxes/{mid}/packets", content=envelope())
    env.client.get(f"/v1/mailboxes/{mid}/packets", headers={"x-mailbox-token": tok})
    text = "\n".join(r.getMessage() for r in caplog.records if not r.name.startswith("httpx"))  # server-side only
    for secret in (mid, tok, user.pub_s, env.token, "testclient"):
        assert secret not in text
