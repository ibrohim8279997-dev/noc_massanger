import os
import re
from dataclasses import dataclass

ENVELOPE_SIZE = 16384          # every packet is exactly this long
MAX_BODY = ENVELOPE_SIZE + 4096  # hard cap for any request body
HEX_KEY_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Settings:
    db_path: str
    db_key_hex: str                    # 32 random bytes as hex; never stored next to the DB
    packet_ttl_s: int = 7 * 86400
    mailbox_max_packets: int = 1000
    max_mailboxes_per_device: int = 20
    max_one_time_prekeys: int = 100
    prekey_blob_max: int = 8192
    clock_skew_s: int = 60
    cleanup_interval_s: int = 60
    put_rate_per_min: int = 120          # per destination mailbox (senders are anonymous)
    prekey_rate_per_min: int = 30        # per prekey owner: stops draining one-time keys

    def __post_init__(self):
        if not HEX_KEY_RE.match(self.db_key_hex):
            raise ValueError("db key must be 64 lowercase hex chars")


def read_db_key() -> str:
    """Key comes from a file outside the data directory (NOC_DB_KEY_FILE) or is typed in."""
    path = os.environ.get("NOC_DB_KEY_FILE")
    if path:
        with open(path) as f:
            return f.read().strip()
    import getpass
    return getpass.getpass("DB key (64 hex): ").strip()


def from_env() -> Settings:
    return Settings(
        db_path=os.environ.get("NOC_DB_PATH", "noc.db"),
        db_key_hex=read_db_key(),
        packet_ttl_s=int(os.environ.get("NOC_PACKET_TTL_S", 7 * 86400)),
    )

# Constant-size exchange slot (cover traffic): every request and every response has exactly these sizes.
SLOT_UP = 1 + 16 + 32 + 16 + 16 + ENVELOPE_SIZE      # flags, recv mailbox, recv token, ack id, dest mailbox, envelope
SLOT_DOWN = 1 + 16 + ENVELOPE_SIZE                   # flags, packet id, packet
F_UPLOAD, F_ACK = 1, 2                               # up flags
D_HAS_PACKET, D_UNAUTH, D_REJECTED = 1, 2, 4         # down flags
