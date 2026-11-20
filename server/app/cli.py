"""Run on the server phone itself. No remote administration exists."""
import argparse
import secrets
import sys


from .admin.bind import BindState
from .config import ENVELOPE_SIZE, Settings, from_env
from .db.store import Store
from .logging.setup import setup_logging
from .main import create_app


def main():
    ap = argparse.ArgumentParser(prog="noc-server")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-key", help="print a new random DB key (store it OUTSIDE the data directory)")
    sub.add_parser("reset-superadmin", help="delete the superadmin record; next start issues a new token")
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")  # stage 3: only a Tor onion service points here
    s.add_argument("--port", type=int, default=8443)
    a = ap.parse_args()

    if a.cmd == "init-key":
        print(secrets.token_hex(32))
        return
    settings = from_env()
    if a.cmd == "reset-superadmin":
        st = Store(settings.db_path, settings.db_key_hex, ENVELOPE_SIZE)
        st.reset_superadmin()
        st.close()
        print("superadmin removed; restart the server to get a new binding token")
        return
    setup_logging()
    bind = BindState()
    probe = Store(settings.db_path, settings.db_key_hex, ENVELOPE_SIZE)
    needs_admin = not probe.has_superadmin()
    if probe.superadmin_without_pq():
        print('WARNING: the administrator has no ML-DSA key (created before this version). Run: python -m app.cli reset-superadmin, then bind again.', flush=True)
    from . import pq
    if not pq.available():
        print('ERROR: liboqs (ML-DSA-65) not found. Run tools/build-liboqs-host.sh (administration is refused without it).', flush=True)
    probe.close()
    if needs_admin:
        # printed to the console of this phone only, never to a logger or file
        print("ONE-TIME BINDING TOKEN (enter it in the app):\n" + bind.issue(), file=sys.stdout, flush=True)
    import uvicorn
    app = create_app(settings, bind)
    uvicorn.run(app, host=a.host, port=a.port, access_log=False, log_config=None)


if __name__ == "__main__":
    main()
