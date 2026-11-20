"""Request authentication: Ed25519 (libsodium via PyNaCl) signature over a canonical string."""
import hashlib
import time

from fastapi import HTTPException, Request
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .limits.validation import b64d


def signing_message(method: str, path: str, ts: str, nonce: str, body: bytes) -> bytes:
    return (b"NOC1\n" + method.upper().encode() + b"\n" + path.encode() + b"\n" +
            ts.encode() + b"\n" + nonce.encode() + b"\n" + hashlib.sha256(body).digest())


class NonceCache:
    def __init__(self):
        self._seen: dict[str, int] = {}

    def check_and_add(self, nonce: str, now: int, ttl: int) -> bool:
        if len(self._seen) > 10000:
            self._seen = {n: e for n, e in self._seen.items() if e > now}
        if self._seen.get(nonce, 0) > now:
            return False
        self._seen[nonce] = now + ttl
        return True


def canonical(request: Request, body: bytes) -> bytes:
    h = request.headers
    return signing_message(request.method, request.url.path, h["x-ts"], h["x-nonce"], body)


async def authenticate(request: Request) -> tuple[bytes, bytes]:
    """Returns (device pubkey, body). Raises uniform 401 on any problem."""
    st = request.app.state
    h = request.headers
    try:
        pub = b64d(h.get("x-key", ""), 32)
        sig = b64d(h.get("x-sig", ""), 64)
        b64d(h.get("x-nonce", ""), 16)
        ts = h.get("x-ts", "")
        if not ts.isdigit() or len(ts) > 12:
            raise ValueError
        now = int(time.time())
        if abs(now - int(ts)) > st.settings.clock_skew_s:
            raise ValueError
        body = await request.body()
        msg = signing_message(request.method, request.url.path, ts, h["x-nonce"], body)
        VerifyKey(pub).verify(msg, sig)
    except (HTTPException, ValueError, KeyError, BadSignatureError):
        raise HTTPException(401)
    if not st.nonces.check_and_add(h["x-nonce"], now, st.settings.clock_skew_s * 2):
        raise HTTPException(401)
    if st.store.device_role(pub) is None:
        raise HTTPException(401)
    return pub, body
