import os

from app.config import D_HAS_PACKET, D_REJECTED, D_UNAUTH, ENVELOPE_SIZE, F_ACK, F_UPLOAD, SLOT_DOWN, SLOT_UP
from app.limits.rate import Limiter

from .conftest import Dev, b64, envelope
from .test_server import mailbox


def raw(s: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def slot(flags=0, recv=None, token=None, ack=None, dest=None, env=None):
    return (bytes([flags]) + (recv or os.urandom(16)) + (token or os.urandom(32)) + (ack or os.urandom(16))
            + (dest or os.urandom(16)) + (env or os.urandom(ENVELOPE_SIZE)))


def exch(env, body):
    return env.client.post("/v1/exchange", content=body)   # no device headers at all: anonymous


# ------------------------------------------------------------ anonymous sealed-sender style access
def test_packet_can_be_sent_without_any_identity(env, user):
    mid, tok = mailbox(env, user)
    r = env.client.post(f"/v1/mailboxes/{mid}/packets", content=envelope())   # no x-key / x-sig
    assert r.status_code == 201
    assert len(env.client.get(f"/v1/mailboxes/{mid}/packets", headers={"x-mailbox-token": tok}).json()) == 1


def test_prekeys_fetchable_anonymously_and_rate_limited(env, user):
    env.api.call(user, "PUT", "/v1/prekeys", json={"bundle": b64(b"B"), "one_time": [b64(b"1")]})
    assert env.client.get(f"/v1/prekeys/{user.pub_s}").status_code == 200
    env.app.state.prekey_limit = Limiter(2)
    codes = [env.client.get(f"/v1/prekeys/{user.pub_s}").status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_put_rate_limit_per_mailbox(env, user):
    mid, _ = mailbox(env, user)
    env.app.state.put_limit = Limiter(3)
    codes = [env.client.post(f"/v1/mailboxes/{mid}/packets", content=envelope()).status_code for _ in range(4)]
    assert codes == [201, 201, 201, 429]


def test_limiter_window_expires():
    t = [0.0]
    lim = Limiter(2, 10, clock=lambda: t[0])
    assert lim.allow(b"k") and lim.allow(b"k") and not lim.allow(b"k")
    t[0] = 11
    assert lim.allow(b"k")


# ------------------------------------------------------------ constant-size exchange
def test_slot_sizes_are_fixed_for_every_outcome(env, user):
    mid, tok = mailbox(env, user)
    other, _ = mailbox(env, user)
    cases = [
        slot(),                                                         # pure dummy, unknown mailbox
        slot(recv=raw(mid), token=raw(tok)),                            # authorized, nothing waiting
        slot(recv=raw(mid), token=os.urandom(32)),                      # wrong token
        slot(F_UPLOAD, recv=raw(mid), token=raw(tok), dest=raw(other)), # real upload
        slot(F_UPLOAD, dest=os.urandom(16)),                            # upload to nowhere
    ]
    sizes = set()
    for c in cases:
        assert len(c) == SLOT_UP
        r = exch(env, c)
        assert r.status_code == 200
        sizes.add(len(r.content))
    assert sizes == {SLOT_DOWN}


def test_wrong_request_size_rejected(env):
    assert exch(env, b"x" * (SLOT_UP - 1)).status_code == 400
    assert exch(env, b"").status_code == 400


def test_exchange_delivers_acks_and_does_not_leak_flags(env, user):
    a, atok = mailbox(env, user); b, btok = mailbox(env, user)
    e1 = os.urandom(ENVELOPE_SIZE)
    # anonymous upload into b's mailbox while downloading from a's
    r = exch(env, slot(F_UPLOAD, recv=raw(a), token=raw(atok), dest=raw(b), env=e1))
    assert r.content[0] == 0                                  # nothing for a yet, upload accepted
    # b receives it
    r = exch(env, slot(recv=raw(b), token=raw(btok)))
    assert r.content[0] & D_HAS_PACKET and r.content[17:] == e1
    pid = r.content[1:17]
    # same packet again until acknowledged
    assert exch(env, slot(recv=raw(b), token=raw(btok))).content[1:17] == pid
    r = exch(env, slot(F_ACK, recv=raw(b), token=raw(btok), ack=pid))
    assert not (r.content[0] & D_HAS_PACKET)
    assert env.app.state.store.list_packets(raw(b), 10) == []


def test_bad_token_and_rejected_upload_flags(env, user):
    mid, _ = mailbox(env, user)
    assert exch(env, slot(recv=raw(mid), token=os.urandom(32))).content[0] & D_UNAUTH
    assert exch(env, slot(F_UPLOAD, dest=os.urandom(16))).content[0] & D_REJECTED


def test_dummy_slot_changes_nothing_and_responses_look_random(env, user):
    mid, tok = mailbox(env, user)
    before = env.app.state.store.conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    r1 = exch(env, slot(recv=raw(mid), token=raw(tok))); r2 = exch(env, slot(recv=raw(mid), token=raw(tok)))
    assert env.app.state.store.conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0] == before
    assert r1.content != r2.content                           # dummy payload is fresh randomness each time
    assert len(set(r1.content[17:])) > 200


def test_exchange_upload_respects_rate_limit(env, user):
    mid, _ = mailbox(env, user)
    env.app.state.put_limit = Limiter(1)
    assert not exch(env, slot(F_UPLOAD, dest=raw(mid))).content[0] & D_REJECTED
    assert exch(env, slot(F_UPLOAD, dest=raw(mid))).content[0] & D_REJECTED
