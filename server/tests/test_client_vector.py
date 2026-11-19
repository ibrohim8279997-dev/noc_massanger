"""A request signed by the Kotlin client (protocol/vectors/auth.json) must verify with the server's own code."""
import base64
import json
import pathlib

from nacl.signing import VerifyKey

from app.auth import signing_message
from app.limits.validation import b64d


def test_kotlin_signature_verifies_with_server_code():
    v = json.loads((pathlib.Path(__file__).parents[2] / "protocol/vectors/auth.json").read_text())
    h = v["headers"]
    msg = signing_message(v["method"], v["path"], h["x-ts"], h["x-nonce"], v["body"].encode())
    VerifyKey(b64d(h["x-key"], 32)).verify(msg, b64d(h["x-sig"], 64))   # raises on mismatch
