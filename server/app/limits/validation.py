"""Strict input validation: format and size of everything that enters the server."""
import base64
import binascii
import re

from fastapi import HTTPException

_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


def b64d(value: str, length: int) -> bytes:
    """Decode unpadded base64url that must decode to exactly `length` bytes."""
    if not isinstance(value, str) or not _B64URL.match(value):
        raise HTTPException(400, "bad format")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        raise HTTPException(400, "bad format")
    if len(raw) != length:
        raise HTTPException(400, "bad format")
    return raw


def b64d_max(value: str, max_len: int) -> bytes:
    if not isinstance(value, str) or not _B64URL.match(value) or len(value) > max_len * 4 // 3 + 4:
        raise HTTPException(400, "bad format")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        raise HTTPException(400, "bad format")
    if not raw or len(raw) > max_len:
        raise HTTPException(400, "bad format")
    return raw


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class BodyLimit:
    """ASGI middleware: reject oversized bodies before they are buffered."""

    def __init__(self, app, max_body: int):
        self.app, self.max_body = app, max_body

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        for k, v in scope["headers"]:
            if k == b"content-length" and v.isdigit() and int(v) > self.max_body:
                return await self._reject(send)
        seen = 0
        too_big = False

        async def limited():
            nonlocal seen, too_big
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.max_body:
                    too_big = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return msg

        started = False

        async def guarded_send(msg):
            nonlocal started
            if too_big and not started:
                started = True
                return await self._reject(send)
            if not too_big:
                await send(msg)

        await self.app(scope, limited, guarded_send)

    @staticmethod
    async def _reject(send):
        await send({"type": "http.response.start", "status": 413, "headers": [(b"content-length", b"0")]})
        await send({"type": "http.response.body", "body": b""})
