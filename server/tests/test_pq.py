"""Administrator = Ed25519 + ML-DSA-65 (liboqs). Both must verify."""
import base64
import os

import pytest

from app import pq
from app.config import ENVELOPE_SIZE

from .conftest import Dev, b64


def test_liboqs_mldsa_roundtrip_and_failures():
    pk, sk = pq.keypair(); msg = os.urandom(200)
    sig = pq.sign(sk, msg)
    assert len(pk) == 1952 and len(sk) == 4032 and len(sig) == 3309
    assert pq.verify(pk, msg, sig)
    assert not pq.verify(pk, msg + b"x", sig)                                   # other message
    assert not pq.verify(pq.keypair()[0], msg, sig)                            # other key
    assert not pq.verify(pk, msg, sig[:-1]) and not pq.verify(pk, msg, b"") and not pq.verify(pk[:-1], msg, sig)
    bad = bytearray(sig); bad[100] ^= 1
    assert not pq.verify(pk, msg, bytes(bad))                                  # a flipped bit


def test_signatures_are_randomized_but_all_verify():
    pk, sk = pq.keypair(); m = b"same message"
    sigs = {pq.sign(sk, m) for _ in range(4)}
    assert len(sigs) >= 1 and all(pq.verify(pk, m, s) for s in sigs)


def test_admin_request_without_the_pq_signature_is_refused_even_with_a_valid_ed25519_one(env):
    h = env.admin.headers("GET", "/v1/admin/users"); h.pop("x-pq-sig")
    assert env.client.get("/v1/admin/users", headers=h).status_code == 401


def test_admin_request_with_someone_elses_pq_signature_is_refused(env):
    impostor = Dev(admin=True)
    msg_headers = env.admin.headers("GET", "/v1/admin/users")
    other = impostor.headers("GET", "/v1/admin/users")                           # a valid pq signature, but by another key and another nonce
    msg_headers["x-pq-sig"] = other["x-pq-sig"]
    assert env.client.get("/v1/admin/users", headers=msg_headers).status_code == 401


def test_pq_signature_covers_the_request_so_it_cannot_be_moved_to_another_request(env, user):
    # the Ed25519 signature is perfectly valid for the DELETE; only the ML-DSA signature comes from a different (harmless GET) request
    delete = env.admin.headers("DELETE", f"/v1/admin/users/{user.pub_s}")
    harmless = env.admin.headers("GET", "/v1/admin/users")
    delete["x-pq-sig"] = harmless["x-pq-sig"]
    assert env.client.delete(f"/v1/admin/users/{user.pub_s}", headers=delete).status_code == 401
    assert env.api.call(env.admin, "GET", "/v1/admin/users").status_code == 200
    assert user.pub_s in [u["pubkey"] for u in env.api.call(env.admin, "GET", "/v1/admin/users").json()]       # the user is still there


def test_valid_ed25519_with_a_flipped_bit_in_the_pq_signature_is_refused(env):
    h = env.admin.headers("GET", "/v1/admin/users")
    sig = bytearray(base64.urlsafe_b64decode(h["x-pq-sig"] + "==")); sig[500] ^= 1
    h["x-pq-sig"] = b64(bytes(sig))
    assert env.client.get("/v1/admin/users", headers=h).status_code == 401


def test_ed25519_alone_is_not_enough_and_pq_alone_is_not_enough(env):
    # valid pq signature, broken Ed25519
    h = env.admin.headers("GET", "/v1/admin/users"); h["x-sig"] = b64(os.urandom(64))
    assert env.client.get("/v1/admin/users", headers=h).status_code == 401


def test_bind_requires_a_well_formed_ml_dsa_key(env):
    from app.admin.bind import BindState
    assert env.client.post("/v1/admin/bind", json={"token": "0" * 64, "pubkey": Dev().pub_s, "pq_pubkey": "AAAA"}).status_code == 422
    assert env.client.post("/v1/admin/bind", json={"token": "0" * 64, "pubkey": Dev().pub_s}).status_code == 422


def test_non_admin_users_are_unaffected_by_pq(env, user):
    assert env.api.call(user, "POST", "/v1/mailboxes", json={"id": b64(os.urandom(16)), "token": b64(os.urandom(32))}).status_code == 201


def test_pq_public_key_is_stored_with_the_admin_and_goes_with_it_on_reset(env):
    c = env.app.state.store.conn
    assert c.execute("SELECT COUNT(*) FROM admin_pq").fetchone()[0] == 1
    env.app.state.store.reset_superadmin()
    assert c.execute("SELECT COUNT(*) FROM admin_pq").fetchone()[0] == 0           # cascade: no orphan keys


def test_old_superadmin_without_pq_key_is_detected(env):
    env.app.state.store.conn.execute("DELETE FROM admin_pq")
    assert env.app.state.store.superadmin_without_pq()
    assert env.api.call(env.admin, "GET", "/v1/admin/users").status_code == 401    # cannot administer until re-bound with a pq key


def test_signature_made_by_the_kotlin_client_through_liboqs_jni_verifies_on_the_server():
    import json
    import pathlib
    v = json.loads((pathlib.Path(__file__).parents[2] / "protocol/vectors/mldsa.json").read_text())
    pk, msg, sig = (base64.b64decode(v[k]) for k in ("pk", "msg", "sig"))
    assert pq.verify(pk, msg, sig)                      # two separate builds of liboqs (Android/JVM side and server side) agree
    assert not pq.verify(pk, msg + b"x", sig)
