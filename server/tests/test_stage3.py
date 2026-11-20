import base64

from app import pq

from app import pq

from .conftest import Dev, b64


def raw(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def rotate(env, old: Dev, new: Dev, proof=None, pq_proof=None, new_pub=None, new_pq=None):
    new_pub = new_pub or new.pub
    new_pq = new_pq or new.pq[0]
    proof = proof or new.sk.sign(b"NOC1-ROTATE\n" + old.pub + new_pub).signature
    pq_proof = pq_proof or pq.sign(new.pq[1], b"NOC1-ROTATE-PQ\n" + old.pub + new_pub + new_pq)
    return env.api.call(old, "POST", "/v1/admin/rotate-key", json={"new_pubkey": b64(new_pub), "proof": b64(proof),
                                                                  "new_pq_pubkey": b64(new_pq), "pq_proof": b64(pq_proof)})


def test_admin_actions_are_logged_with_the_admins_own_signature(env, user):
    env.api.call(env.admin, "DELETE", f"/v1/admin/users/{user.pub_s}")
    log = env.api.call(env.admin, "GET", "/v1/admin/log").json()
    assert [e["action"] for e in log] == ["remove_user", "add_user"]
    assert log[0]["target"] == user.pub_s and len(raw(log[0]["sig"])) == 64
    assert set(log[0]) == {"action", "target", "sig", "pq_sig"}            # no time, no address
    assert len(raw(log[0]["pq_sig"])) == 3309


def test_admin_log_is_admin_only(env, user):
    assert env.api.call(user, "GET", "/v1/admin/log").status_code == 403


def test_rotate_key_moves_the_single_superadmin_and_old_keys_die(env, user):
    new = Dev(admin=True)
    assert rotate(env, env.admin, new).status_code == 204
    assert env.api.call(env.admin, "GET", "/v1/admin/users").status_code == 401            # old key pair is gone
    users = env.api.call(new, "GET", "/v1/admin/users").json()
    assert [u["role"] for u in users].count("superadmin") == 1
    assert env.api.call(new, "PUT", f"/v1/admin/users/{Dev().pub_s}", json={"role": "user"}).status_code == 204
    assert "rotate_key" in [e["action"] for e in env.api.call(new, "GET", "/v1/admin/log").json()]


def test_rotate_key_needs_proof_of_possession_of_both_new_keys(env):
    new = Dev(admin=True); other = Dev(admin=True)
    bad_ed = other.sk.sign(b"NOC1-ROTATE\n" + env.admin.pub + new.pub).signature
    assert rotate(env, env.admin, new, proof=bad_ed).status_code == 400
    bad_pq = pq.sign(other.pq[1], b"NOC1-ROTATE-PQ\n" + env.admin.pub + new.pub + new.pq[0])
    assert rotate(env, env.admin, new, pq_proof=bad_pq).status_code == 400
    assert env.api.call(env.admin, "GET", "/v1/admin/users").status_code == 200              # nothing changed


def test_rotate_key_to_the_same_key_and_by_non_admin_refused(env, user):
    assert rotate(env, env.admin, env.admin).status_code == 409
    assert rotate(env, user, Dev(admin=True)).status_code == 403


def test_there_is_no_remote_way_to_get_a_binding_token(env):
    from app.api.routes import router
    paths = {r.path for r in router.routes if hasattr(r, "path")}
    assert "/v1/admin/bind" in paths and len(paths) > 10                                    # we really looked at the whole API
    assert not [p for p in paths if "token" in p.lower() and "mailbox" not in p.lower()]
    assert [p for p in paths if "bind" in p] == ["/v1/admin/bind"]                           # the only entrance, and it needs the on-screen token
    # and once a superadmin exists even the right token is useless
    assert env.client.post("/v1/admin/bind", json={"token": env.token, "pubkey": (lambda x: x.pub_s)(Dev(admin=True)), "pq_pubkey": b64(pq.keypair()[0])}).status_code == 404


def test_binding_token_is_printed_never_stored(env):
    c = env.app.state.store.conn
    tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for t in tables:
        for row in c.execute(f"SELECT * FROM {t}"):                                          # table names come from sqlite_master, not from users
            assert env.token.encode() not in b"".join(x if isinstance(x, bytes) else str(x).encode() for x in row)
