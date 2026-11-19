import asyncio
import json
import logging
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from pydantic import BaseModel, Field

from ..auth import authenticate
import os
import struct
from ..config import ENVELOPE_SIZE, SLOT_UP, SLOT_DOWN, F_UPLOAD, F_ACK, F_PREKEY, D_HAS_PACKET, D_UNAUTH, D_REJECTED, D_PREKEY, D_NOPREKEY
from ..limits.validation import b64d, b64d_max, b64e

log = logging.getLogger("noc")
router = APIRouter(prefix="/v1")


class Notifier:
    def __init__(self):
        self.subs = defaultdict(set)

    def notify(self, mid: bytes):
        for q in list(self.subs.get(mid, ())):
            q.put_nowait(1)


# ---------------------------------------------------------------- deps
async def device(request: Request) -> bytes:
    pub, _ = await authenticate(request)
    return pub


async def superadmin(request: Request) -> bytes:
    pub, _ = await authenticate(request)
    if request.app.state.store.device_role(pub) != "superadmin":
        raise HTTPException(403)
    return pub


def _token(request: Request) -> bytes:
    return b64d(request.headers.get("x-mailbox-token", ""), 32)


def _authorized_mailbox(request: Request, mid_s: str) -> bytes:
    mid = b64d(mid_s, 16)
    token = _token(request)
    if not request.app.state.store.check_token(mid, token):
        raise HTTPException(404)  # same answer for unknown mailbox and wrong token
    return mid


# ---------------------------------------------------------------- admin
class BindIn(BaseModel):
    token: str = Field(min_length=64, max_length=64)
    pubkey: str = Field(min_length=43, max_length=43)


@router.post("/admin/bind", status_code=204)
async def bind(body: BindIn, request: Request):
    st = request.app.state
    pub = b64d(body.pubkey, 32)
    if st.store.has_superadmin() or not st.bind.consume(body.token):
        raise HTTPException(404)
    if not st.store.bind_superadmin(pub):
        raise HTTPException(404)
    log.info("superadmin bound")
    return Response(status_code=204)


class RoleIn(BaseModel):
    role: str = Field(pattern="^user$")


@router.get("/admin/users")
async def list_users(request: Request, _: bytes = Depends(superadmin)):
    return [{"pubkey": b64e(p), "role": r} for p, r in request.app.state.store.list_users()]


@router.put("/admin/users/{pubkey}", status_code=204)
async def put_user(pubkey: str, body: RoleIn, request: Request, _: bytes = Depends(superadmin)):
    pub = b64d(pubkey, 32)
    if not request.app.state.store.add_user(pub, body.role):
        raise HTTPException(409)
    request.app.state.store.log_admin("add_user", pub, b64d(request.headers["x-sig"], 64))
    log.info("user added or role changed")
    return Response(status_code=204)


@router.delete("/admin/users/{pubkey}", status_code=204)
async def delete_user(pubkey: str, request: Request, _: bytes = Depends(superadmin)):
    pub = b64d(pubkey, 32)
    if not request.app.state.store.delete_user(pub):
        raise HTTPException(404)
    request.app.state.store.log_admin("remove_user", pub, b64d(request.headers["x-sig"], 64))
    log.info("user removed")
    return Response(status_code=204)


class RotateIn(BaseModel):
    new_pubkey: str = Field(min_length=43, max_length=43)
    proof: str = Field(min_length=86, max_length=86)        # signature BY THE NEW KEY: proves it is held, not just typed in


@router.post("/admin/rotate-key", status_code=204)
async def rotate_key(body: RotateIn, request: Request, old: bytes = Depends(superadmin)):
    """Change of the administrator's key: signed by the old key (request signature) and proven by the new one."""
    new = b64d(body.new_pubkey, 32)
    if new == old:
        raise HTTPException(409)
    try:
        VerifyKey(new).verify(b"NOC1-ROTATE\n" + old + new, b64d(body.proof, 64))
    except BadSignatureError:
        raise HTTPException(400, "bad proof")
    if not request.app.state.store.rotate_superadmin(old, new):
        raise HTTPException(409)
    request.app.state.store.log_admin("rotate_key", new, b64d(request.headers["x-sig"], 64))
    log.info("administrator key changed")
    return Response(status_code=204)


@router.get("/admin/log")
async def admin_log(request: Request, _: bytes = Depends(superadmin)):
    return [{"action": a, "target": b64e(t), "sig": b64e(g)} for a, t, g in request.app.state.store.admin_log()]


# ---------------------------------------------------------------- prekeys
class PrekeysIn(BaseModel):
    bundle: str = Field(max_length=12000)
    one_time: list[str] = Field(default_factory=list, max_length=100)


@router.put("/prekeys", status_code=204)
async def put_prekeys(body: PrekeysIn, request: Request, me: bytes = Depends(device)):
    s = request.app.state.settings
    bundle = b64d_max(body.bundle, s.prekey_blob_max)
    otp = [b64d_max(x, s.prekey_blob_max) for x in body.one_time]
    request.app.state.store.put_prekeys(me, bundle, otp, s.max_one_time_prekeys)
    return Response(status_code=204)


@router.get("/prekeys/{pubkey}")
async def get_prekeys(pubkey: str, request: Request):
    """Anonymous: the server must not learn who is about to write to whom. Rate-limited per owner."""
    owner = b64d(pubkey, 32)
    if not request.app.state.prekey_limit.allow(owner):
        raise HTTPException(429)
    r = request.app.state.store.take_prekeys(owner)
    if not r:
        raise HTTPException(404)
    bundle, otp = r
    return {"bundle": b64e(bundle), "one_time": b64e(otp) if otp else None}


# ---------------------------------------------------------------- mailboxes
class MailboxIn(BaseModel):
    id: str = Field(min_length=22, max_length=22)
    token: str = Field(min_length=43, max_length=43)


@router.post("/mailboxes", status_code=201)
async def create_mailbox(body: MailboxIn, request: Request, me: bytes = Depends(device)):
    ok = request.app.state.store.create_mailbox(
        b64d(body.id, 16), me, b64d(body.token, 32), request.app.state.settings.max_mailboxes_per_device)
    if not ok:
        raise HTTPException(409)
    return Response(status_code=201)


@router.delete("/mailboxes/{mid}", status_code=204)
async def delete_mailbox(mid: str, request: Request):
    request.app.state.store.delete_mailbox(_authorized_mailbox(request, mid))
    return Response(status_code=204)


@router.post("/mailboxes/{mid}/packets", status_code=201)
async def put_packet(mid: str, request: Request):
    """Anonymous ("sealed sender"): knowing the mailbox id is the write capability; the sender is inside the envelope."""
    body = await request.body()
    if len(body) != ENVELOPE_SIZE:
        raise HTTPException(400, "bad size")
    st = request.app.state
    mbox = b64d(mid, 16)
    if not st.put_limit.allow(mbox):
        raise HTTPException(429)
    pid = st.store.put_packet(mbox, body, st.settings.packet_ttl_s, st.settings.mailbox_max_packets)
    if pid is None:
        raise HTTPException(404)
    st.notifier.notify(mbox)
    return {"id": b64e(pid)}


@router.get("/mailboxes/{mid}/packets")
async def get_packets(mid: str, request: Request, limit: int = 50):
    mbox = _authorized_mailbox(request, mid)
    limit = max(1, min(limit, 100))
    return [{"id": b64e(i), "data": b64e(d)} for i, d in request.app.state.store.list_packets(mbox, limit)]


@router.delete("/mailboxes/{mid}/packets/{pid}", status_code=204)
async def ack_packet(mid: str, pid: str, request: Request):
    mbox = _authorized_mailbox(request, mid)
    if not request.app.state.store.ack_packet(mbox, b64d(pid, 16)):
        raise HTTPException(404)
    return Response(status_code=204)


# ---------------------------------------------------------------- websocket (wake-up only, no content)
@router.websocket("/ws")
async def ws(sock: WebSocket):
    await sock.accept()
    st = sock.app.state
    q: asyncio.Queue = asyncio.Queue()
    mid = None
    try:
        first = json.loads(await asyncio.wait_for(sock.receive_text(), 10))
        mid = b64d(first["mailbox"], 16)
        if not st.store.check_token(mid, b64d(first["token"], 32)):
            await sock.close(code=1008)
            return
        st.notifier.subs[mid].add(q)
        await sock.send_text("ok")
        while True:
            try:
                await asyncio.wait_for(q.get(), 30)
                await sock.send_text("new")
            except asyncio.TimeoutError:
                await sock.send_text("ping")
    except (WebSocketDisconnect, asyncio.TimeoutError, KeyError, ValueError, HTTPException, TypeError):
        pass
    except RuntimeError:
        pass
    finally:
        if mid is not None:
            st.notifier.subs[mid].discard(q)


# ---------------------------------------------------------------- constant-size exchange (cover traffic)
@router.post("/exchange")
async def exchange(request: Request):
    """One request = one upload slot + one download slot, always the same size, real or dummy.
    up:   flags | recv mailbox | recv token | ack id | dest mailbox | envelope
    down: flags | packet id | packet
    """
    st = request.app.state
    body = await request.body()
    if len(body) != SLOT_UP:
        raise HTTPException(400, "bad size")
    flags, recv, token, ackid, dest, env = body[0], body[1:17], body[17:49], body[49:65], body[65:81], body[81:]
    down, pid, data = 0, os.urandom(16), os.urandom(ENVELOPE_SIZE)
    if st.store.check_token(recv, token):
        if flags & F_ACK:
            st.store.ack_packet(recv, ackid)
        got = [] if flags & F_PREKEY else st.store.list_packets(recv, 1)
        if got:
            down |= D_HAS_PACKET
            pid, data = got[0]
    else:
        down |= D_UNAUTH
    if flags & F_PREKEY:
        # key request travels inside the same fixed-size slot, so it is invisible among ordinary traffic
        owner = env[:32]
        if not st.prekey_limit.allow(owner):
            down |= D_REJECTED
        else:
            r = st.store.take_prekeys(owner)
            if r is None:
                down |= D_NOPREKEY
            else:
                bundle, otp = r
                packed = struct.pack(">I", len(bundle)) + bundle + (b"\x01" + struct.pack(">I", len(otp)) + otp if otp else b"\x00")
                data = packed + os.urandom(ENVELOPE_SIZE - len(packed))
                down |= D_PREKEY
    elif flags & F_UPLOAD:
        if st.put_limit.allow(dest) and st.store.put_packet(dest, env, st.settings.packet_ttl_s, st.settings.mailbox_max_packets) is not None:
            st.notifier.notify(dest)
        else:
            down |= D_REJECTED
    out = bytes([down]) + pid + data
    assert len(out) == SLOT_DOWN
    return Response(out, media_type="application/octet-stream")
