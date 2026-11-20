"""Real server processes: service-user isolation, key/data separation, physical-only binding token, loss recovery."""
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import time

import httpx
import pytest

from app import pq

from .conftest import Dev, b64

pytestmark = pytest.mark.skipif(os.geteuid() != 0 or not shutil.which("setpriv"), reason="needs root and setpriv")
SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Srv:
    def __init__(self, db, keyfile, run_as=None):
        self.port = free_port()
        cmd = [sys.executable, "-m", "app.cli", "serve", "--host", "127.0.0.1", "--port", str(self.port)]
        if run_as:
            cmd = ["setpriv", f"--reuid={run_as}", f"--regid={run_as}", "--clear-groups", "--no-new-privs"] + cmd
        env = dict(os.environ, NOC_DB_PATH=db, NOC_DB_KEY_FILE=keyfile, PYTHONUNBUFFERED="1")
        self.p = subprocess.Popen(cmd, cwd=SERVER_DIR, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.out, self.token = "", None
        end = time.time() + 20
        while time.time() < end:
            line = self.p.stdout.readline()
            self.out += line
            m = re.match(r"^[0-9a-f]{64}$", line.strip())
            if m:
                self.token = m.group(0)
            if "Application startup complete" in line:
                break
        self.base = f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.p.terminate()
        self.out += self.p.communicate(timeout=10)[0]


@pytest.fixture
def svc_dir():
    import tempfile
    tmp_path = __import__('pathlib').Path(tempfile.mkdtemp()); os.chmod(tmp_path, 0o755)
    if not shutil.which("useradd") and not os.path.exists("/usr/sbin/useradd"):
        pytest.skip("no useradd")
    subprocess.run("id noc >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin noc", shell=True, check=True)
    uid = pwd.getpwnam("noc")
    d = tmp_path / "noc-data"
    d.mkdir(); os.chown(d, uid.pw_uid, uid.pw_gid); os.chmod(d, 0o700)
    for p in (tmp_path, os.path.dirname(SERVER_DIR), SERVER_DIR):   # the service user must be able to read the code, nothing else
        os.chmod(p, os.stat(p).st_mode | 0o005)
    key = tmp_path / "elsewhere.key"
    key.write_text("cd" * 32); os.chmod(key, 0o644)
    return d, key


def uid_of(pid):
    return int(re.search(r"Uid:\s+(\d+)", open(f"/proc/{pid}/status").read()).group(1))


def test_server_runs_as_unprivileged_user_and_only_that_user_can_touch_the_database(svc_dir):
    d, key = svc_dir
    s = Srv(str(d / "noc.db"), str(key), run_as="noc")
    try:
        assert uid_of(s.p.pid) == pwd.getpwnam("noc").pw_uid                          # not root
        db = d / "noc.db"
        assert db.exists() and (db.stat().st_mode & 0o777) == 0o600 and db.stat().st_uid == pwd.getpwnam("noc").pw_uid
        # another unprivileged account cannot read it
        r = subprocess.run(["setpriv", "--reuid=nobody", "--regid=nogroup", "--clear-groups", "cat", str(db)], capture_output=True)
        assert r.returncode != 0
        # and the service user cannot read root's files or write outside its directory
        r = subprocess.run(["setpriv", "--reuid=noc", "--regid=noc", "--clear-groups", "ls", "/root"], capture_output=True)
        assert r.returncode != 0
        r = subprocess.run(["setpriv", "--reuid=noc", "--regid=noc", "--clear-groups", "touch", "/etc/noc-probe"], capture_output=True)
        assert r.returncode != 0
    finally:
        s.stop()


def test_database_key_is_not_next_to_the_data_and_the_file_is_ciphertext(svc_dir):
    d, key = svc_dir
    s = Srv(str(d / "noc.db"), str(key), run_as="noc")
    try:
        assert not open(d / "noc.db", "rb").read(16).startswith(b"SQLite format 3")
        assert [f.name for f in d.iterdir() if f.is_file()] == ["noc.db"]            # only the database; no key, no token, no logs next to it
        blob = b"".join(open(f, "rb").read() for f in d.iterdir() if f.is_file())
        assert key.read_text().strip().encode() not in blob and bytes.fromhex(key.read_text().strip()) not in blob
    finally:
        s.stop()


def test_binding_token_exists_only_on_the_console_and_a_lost_admin_needs_physical_reset(svc_dir):
    d, key = svc_dir
    db = str(d / "noc.db")
    s = Srv(db, str(key), run_as="noc")
    admin = Dev(admin=True)
    try:
        assert s.token and s.out.count(s.token) == 1                                    # shown once, on this console
        assert httpx.post(s.base + "/v1/admin/bind", json={"token": s.token, "pubkey": admin.pub_s, "pq_pubkey": b64(admin.pq[0])}).status_code == 204
        assert httpx.post(s.base + "/v1/admin/bind", json={"token": s.token, "pubkey": Dev(admin=True).pub_s, "pq_pubkey": b64(pq.keypair()[0])}).status_code == 404   # burnt
    finally:
        s.stop()
    assert s.token.encode() not in open(db, "rb").read()                                # never written to disk
    # restart with a superadmin present: no new token is issued
    s2 = Srv(db, str(key), run_as="noc")
    try:
        assert s2.token is None
        assert httpx.post(s2.base + "/v1/admin/bind", json={"token": "0" * 64, "pubkey": Dev(admin=True).pub_s, "pq_pubkey": b64(pq.keypair()[0])}).status_code == 404
    finally:
        s2.stop()
    # loss of the admin device: the record is removed by hand ON the phone, then a restart issues a fresh token
    env = dict(os.environ, NOC_DB_PATH=db, NOC_DB_KEY_FILE=str(key))
    r = subprocess.run(["setpriv", "--reuid=noc", "--regid=noc", "--clear-groups", sys.executable, "-m", "app.cli", "reset-superadmin"],
                       cwd=SERVER_DIR, env=env, capture_output=True, text=True)
    assert r.returncode == 0
    s3 = Srv(db, str(key), run_as="noc")
    try:
        assert s3.token and s3.token != s.token
        new_admin = Dev(admin=True)
        assert httpx.post(s3.base + "/v1/admin/bind", json={"token": s3.token, "pubkey": new_admin.pub_s, "pq_pubkey": b64(new_admin.pq[0])}).status_code == 204
        h = admin.headers("GET", "/v1/admin/users")                                      # the lost device's key is dead
        assert httpx.get(s3.base + "/v1/admin/users", headers=h).status_code == 401
    finally:
        s3.stop()
