#!/usr/bin/env python3
"""Shows with your own eyes that the server database contains nothing readable.

Run it on the server phone (python from server/.venv), with the DB key you use to start the server:
    server/.venv/bin/python tools/verify_server_blind.py /path/noc.db "слово из сообщения" "другое слово"
Send those words in a chat first. The script opens the database WITH the key (so SQLCipher's file encryption is out
of the picture) and looks for the words in every table, as text and as bytes. A result of "not found" together with
high-entropy packets proves the server holds only end-to-end ciphertext: not even the operator with the key can read it.
    --words-file F   read the words from a UTF-8 file (one per line) instead of the command line
    --selftest   runs the same check on a throw-away database that DOES contain a marker, to prove the checker works.
"""
import getpass
import math
import os
import re
import sys
import tempfile

import sqlcipher3

try:
    sys.stdout.reconfigure(encoding="utf-8")        # Cyrillic must print as Cyrillic whatever the terminal locale is
except Exception:
    pass


def open_db(path, key_hex):
    c = sqlcipher3.connect(path)
    c.execute(f"PRAGMA key = \"x'{key_hex}'\"")
    c.execute("SELECT count(*) FROM sqlite_master")           # fails here if the key is wrong
    return c


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in (b.count(x) for x in set(b)))


def scan(conn, needles):
    needle_forms = []
    for w in needles:
        raw = w.encode()
        needle_forms.append((w, [raw, raw.lower(), raw.upper(), w.encode("utf-16-le"), w.encode("cp1251", "ignore")]))
    found, rows_seen = [], 0
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    for t in tables:
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({t})")]      # table names come from sqlite_master, not from the user
        for row in conn.execute(f"SELECT * FROM {t}"):
            rows_seen += 1
            for col, val in zip(cols, row):
                blob = bytes(val) if isinstance(val, (bytes, bytearray, memoryview)) else str(val).encode() if val is not None else b""
                for word, forms in needle_forms:
                    if any(f and f in blob for f in forms):
                        found.append((t, col, word))
    return tables, rows_seen, found


def packet_stats(conn):
    rows = [bytes(r[0]) for r in conn.execute("SELECT data FROM packets")] if conn.execute("SELECT name FROM sqlite_master WHERE name='packets'").fetchone() else []
    return len(rows), (min(entropy(r) for r in rows) if rows else None), (len({len(r) for r in rows}) if rows else None)


def report(path, key_hex, needles):
    conn = open_db(path, key_hex)
    tables, rows, found = scan(conn, needles)
    n, min_ent, lens = packet_stats(conn)
    print(f"tables: {', '.join(tables)}")
    print(f"rows looked at: {rows}")
    print(f"packets waiting on the server: {n}" + (f", every one {'the same length' if lens == 1 else 'of mixed length (!)'}, lowest entropy {min_ent:.3f} bits/byte (random data is ~7.99)" if n else ""))
    for w in needles:
        hits = [f"{t}.{c}" for t, c, ww in found if ww == w]
        print(f"  '{w}': " + ("FOUND in " + ", ".join(hits) + "  <-- the server can read this" if hits else "not found anywhere"))
    return not found


def selftest():
    from importlib import util
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "server"))
    from app.db.store import Store
    d = tempfile.mkdtemp(); key = "ab" * 32; db = os.path.join(d, "t.db")
    s = Store(db, key, 16384)
    s.add_user(b"\x01" * 32, "user"); s.create_mailbox(b"\x02" * 16, b"\x01" * 32, b"\x03" * 32, 5)
    s.put_packet(b"\x02" * 16, os.urandom(16384), 3600, 10)                                   # a realistic packet: random bytes
    s.put_packet(b"\x02" * 16, b"hello MARKER-SECRET-WORD " + os.urandom(16384 - 25), 3600, 10)   # a LEAKY packet: plaintext inside
    s.close()
    print("self-test: one packet is random, one deliberately contains the plaintext 'MARKER-SECRET-WORD'")
    ok = report(db, key, ["MARKER-SECRET-WORD", "не-встречается"])
    print("self-test " + ("FAILED: the checker did not see the marker" if ok else "OK: the checker found the marker and not the absent word"))
    return 0 if not ok else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    args = sys.argv[1:]
    words_file = None
    if "--words-file" in args:
        i = args.index("--words-file"); words_file = args[i + 1]; del args[i:i + 2]
    if len(args) < 1 or (len(args) < 2 and not words_file):
        print(__doc__); sys.exit(2)
    words = [l.rstrip("\n") for l in open(words_file, encoding="utf-8")] if words_file else args[1:]
    words = [w for w in words if w]
    key = os.environ.get("NOC_DB_KEY") or (open(os.environ["NOC_DB_KEY_FILE"]).read().strip() if os.environ.get("NOC_DB_KEY_FILE") else getpass.getpass("DB key (64 hex): ").strip())
    if not re.fullmatch(r"[0-9a-f]{64}", key):
        sys.exit("the key must be 64 hex characters")
    sys.exit(0 if report(args[0], key, words) else 1)
