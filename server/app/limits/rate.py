"""Tiny in-memory sliding-window limiter. Keys are mailbox ids / public keys, never network addresses."""
import time
from collections import defaultdict, deque


class Limiter:
    def __init__(self, max_events: int, window_s: float = 60.0, clock=time.monotonic):
        self.max, self.window, self.clock = max_events, window_s, clock
        self._ev: dict[bytes, deque] = defaultdict(deque)

    def allow(self, key: bytes) -> bool:
        now = self.clock()
        q = self._ev[key]
        while q and q[0] <= now - self.window:
            q.popleft()
        if len(q) >= self.max:
            return False
        q.append(now)
        if len(self._ev) > 20000:   # bound memory
            for k in [k for k, v in self._ev.items() if not v or v[-1] <= now - self.window]:
                del self._ev[k]
        return True
