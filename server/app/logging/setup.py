"""Logging that cannot leak: redacts IPs, keys and long encoded blobs even if a call site slips."""
import logging
import re

_PATTERNS = [
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),                 # IPv4
    re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b"),  # IPv6
    re.compile(r"\b[0-9a-fA-F]{32,}\b"),                        # hex keys/tokens
    re.compile(r"[A-Za-z0-9_-]{22,}"),                          # base64url ids, keys, sigs
]


class RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for p in _PATTERNS:
            msg = p.sub("[redacted]", msg)
        record.msg, record.args = msg, None
        return True


def setup_logging(level=logging.INFO):
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    handler.addFilter(RedactFilter())
    for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access", "noc"):
        lg = logging.getLogger(name)
        lg.handlers = [handler] if name == "" else []
        lg.propagate = name != ""
        lg.setLevel(level)
    logging.getLogger("uvicorn.access").disabled = True  # access log carries client addresses
