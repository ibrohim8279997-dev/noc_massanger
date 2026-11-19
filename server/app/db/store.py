"""SQLCipher store. Only parameterized queries. No names, text or IP addresses are ever stored."""
import hashlib
import hmac
import os
import threading
import time

import sqlcipher3

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
  pubkey BLOB PRIMARY KEY CHECK(length(pubkey)=32),
  role TEXT NOT NULL CHECK(role IN ('superadmin','user')));
CREATE TABLE IF NOT EXISTS mailboxes(
  id BLOB PRIMARY KEY CHECK(length(id)=16),
  owner BLOB NOT NULL REFERENCES devices(pubkey) ON DELETE CASCADE,
  token_hash BLOB NOT NULL CHECK(length(token_hash)=32));
CREATE TABLE IF NOT EXISTS packets(
  id BLOB PRIMARY KEY CHECK(length(id)=16),
  mailbox_id BLOB NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  data BLOB NOT NULL,
  expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS packets_mb ON packets(mailbox_id);
CREATE INDEX IF NOT EXISTS packets_exp ON packets(expires);
CREATE TABLE IF NOT EXISTS prekey_bundles(
  owner BLOB PRIMARY KEY REFERENCES devices(pubkey) ON DELETE CASCADE,
  bundle BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS one_time_prekeys(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner BLOB NOT NULL REFERENCES devices(pubkey) ON DELETE CASCADE,
  data BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS otp_owner ON one_time_prekeys(owner);
"""


def _h(token: bytes) -> bytes:
    return hashlib.sha256(token).digest()


class Store:
    def __init__(self, path: str, key_hex: str, envelope_size: int):
        self._lock = threading.RLock()
        self._envelope = envelope_size
        self.conn = sqlcipher3.connect(path, check_same_thread=False, isolation_level=None)
        # key_hex is validated as 64 hex chars in Settings; PRAGMA cannot be parameterized
        self.conn.execute(f"PRAGMA key = \"x'{key_hex}'\"")
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA secure_delete = ON")
        self.conn.executescript(SCHEMA)  # also fails loudly if the key is wrong
        if path != ":memory:":
            os.chmod(path, 0o600)

    def _tx(self):
        return _Tx(self)

    # --- devices / admin -------------------------------------------------
    def device_role(self, pub: bytes):
        with self._lock:
            r = self.conn.execute("SELECT role FROM devices WHERE pubkey=?", (pub,)).fetchone()
            return r[0] if r else None

    def has_superadmin(self) -> bool:
        with self._lock:
            return self.conn.execute("SELECT 1 FROM devices WHERE role='superadmin'").fetchone() is not None

    def bind_superadmin(self, pub: bytes) -> bool:
        with self._tx() as c:
            if c.execute("SELECT 1 FROM devices WHERE role='superadmin'").fetchone():
                return False
            c.execute("INSERT OR REPLACE INTO devices(pubkey, role) VALUES(?, 'superadmin')", (pub,))
            return True

    def reset_superadmin(self):
        with self._tx() as c:
            c.execute("DELETE FROM devices WHERE role='superadmin'")

    def add_user(self, pub: bytes, role: str = "user") -> bool:
        with self._tx() as c:
            cur = c.execute("SELECT role FROM devices WHERE pubkey=?", (pub,)).fetchone()
            if cur and cur[0] == "superadmin":
                return False
            c.execute("INSERT OR REPLACE INTO devices(pubkey, role) VALUES(?, ?)", (pub, role))
            return True

    def delete_user(self, pub: bytes) -> bool:
        with self._tx() as c:
            cur = c.execute("SELECT role FROM devices WHERE pubkey=?", (pub,)).fetchone()
            if not cur or cur[0] == "superadmin":
                return False
            c.execute("DELETE FROM devices WHERE pubkey=?", (pub,))  # cascades: mailboxes, packets, prekeys
            return True

    def list_users(self):
        with self._lock:
            return [(bytes(p), r) for p, r in self.conn.execute("SELECT pubkey, role FROM devices ORDER BY rowid")]

    # --- prekeys ---------------------------------------------------------
    def put_prekeys(self, owner: bytes, bundle: bytes, one_time: list, cap: int) -> None:
        with self._tx() as c:
            c.execute("INSERT OR REPLACE INTO prekey_bundles(owner, bundle) VALUES(?, ?)", (owner, bundle))
            have = c.execute("SELECT COUNT(*) FROM one_time_prekeys WHERE owner=?", (owner,)).fetchone()[0]
            for blob in one_time[: max(0, cap - have)]:
                c.execute("INSERT INTO one_time_prekeys(owner, data) VALUES(?, ?)", (owner, blob))

    def take_prekeys(self, owner: bytes):
        with self._tx() as c:
            b = c.execute("SELECT bundle FROM prekey_bundles WHERE owner=?", (owner,)).fetchone()
            if not b:
                return None
            otp = c.execute("SELECT id, data FROM one_time_prekeys WHERE owner=? ORDER BY id LIMIT 1", (owner,)).fetchone()
            if otp:
                c.execute("DELETE FROM one_time_prekeys WHERE id=?", (otp[0],))
            return bytes(b[0]), (bytes(otp[1]) if otp else None)

    # --- mailboxes / packets ---------------------------------------------
    def create_mailbox(self, mid: bytes, owner: bytes, token: bytes, max_per_device: int) -> bool:
        with self._tx() as c:
            n = c.execute("SELECT COUNT(*) FROM mailboxes WHERE owner=?", (owner,)).fetchone()[0]
            if n >= max_per_device or c.execute("SELECT 1 FROM mailboxes WHERE id=?", (mid,)).fetchone():
                return False
            c.execute("INSERT INTO mailboxes(id, owner, token_hash) VALUES(?, ?, ?)", (mid, owner, _h(token)))
            return True

    def mailbox_exists(self, mid: bytes) -> bool:
        with self._lock:
            return self.conn.execute("SELECT 1 FROM mailboxes WHERE id=?", (mid,)).fetchone() is not None

    def check_token(self, mid: bytes, token: bytes) -> bool:
        with self._lock:
            r = self.conn.execute("SELECT token_hash FROM mailboxes WHERE id=?", (mid,)).fetchone()
        # compare against a dummy hash when the mailbox is unknown to keep timing flat
        stored = bytes(r[0]) if r else b"\0" * 32
        return hmac.compare_digest(stored, _h(token)) and r is not None

    def delete_mailbox(self, mid: bytes):
        with self._tx() as c:
            c.execute("DELETE FROM mailboxes WHERE id=?", (mid,))

    def put_packet(self, mid: bytes, data: bytes, ttl_s: int, max_packets: int) -> bytes | None:
        assert len(data) == self._envelope
        pid = os.urandom(16)
        with self._tx() as c:
            if not c.execute("SELECT 1 FROM mailboxes WHERE id=?", (mid,)).fetchone():
                return None
            n = c.execute("SELECT COUNT(*) FROM packets WHERE mailbox_id=?", (mid,)).fetchone()[0]
            if n >= max_packets:
                return None
            c.execute("INSERT INTO packets(id, mailbox_id, data, expires) VALUES(?, ?, ?, ?)",
                      (pid, mid, data, int(time.time()) + ttl_s))
        return pid

    def list_packets(self, mid: bytes, limit: int):
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, data FROM packets WHERE mailbox_id=? AND expires>? ORDER BY rowid LIMIT ?",
                (mid, int(time.time()), limit)).fetchall()
        return [(bytes(i), bytes(d)) for i, d in rows]

    def ack_packet(self, mid: bytes, pid: bytes) -> bool:
        with self._tx() as c:
            return c.execute("DELETE FROM packets WHERE id=? AND mailbox_id=?", (pid, mid)).rowcount > 0

    def purge_expired(self) -> int:
        with self._tx() as c:
            return c.execute("DELETE FROM packets WHERE expires<=?", (int(time.time()),)).rowcount

    def close(self):
        with self._lock:
            self.conn.close()


class _Tx:
    def __init__(self, store):
        self.s = store

    def __enter__(self):
        self.s._lock.acquire()
        self.s.conn.execute("BEGIN IMMEDIATE")
        return self.s.conn

    def __exit__(self, et, ev, tb):
        try:
            self.s.conn.execute("ROLLBACK" if et else "COMMIT")
        finally:
            self.s._lock.release()
