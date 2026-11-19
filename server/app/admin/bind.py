"""One-time superadmin binding token. Lives only in memory and on the server phone's screen."""
import hmac
import secrets


class BindState:
    MAX_FAILURES = 5

    def __init__(self):
        self.token: str | None = None
        self.failures = 0

    def issue(self) -> str:
        self.token = secrets.token_hex(32)
        self.failures = 0
        return self.token

    def active(self) -> bool:
        return self.token is not None and self.failures < self.MAX_FAILURES

    def consume(self, candidate: str) -> bool:
        if not self.active():
            return False
        ok = hmac.compare_digest(self.token.encode(), candidate.encode())
        if ok:
            self.token = None            # burns on first success
        else:
            self.failures += 1
        return ok
