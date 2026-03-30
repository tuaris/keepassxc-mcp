"""KeePassXC protocol client.

Handles TCP/Unix socket connection, NaCl encryption, identity persistence,
association, and all keepassxc-browser protocol actions.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import socket
import sys
import threading
import time

from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import random as nacl_random


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def log(msg: str) -> None:
    sys.stderr.write(f"[keepassxc-mcp] {msg}\n")
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# Identity persistence
# ---------------------------------------------------------------------------
IDENTITY_FILE = os.environ.get(
    "KEEPASSXC_IDENTITY",
    os.path.join(os.path.expanduser("~"), ".local", "share",
                 "keepassxc-mcp", "identity.json"))


def load_identity() -> dict | None:
    try:
        p = pathlib.Path(IDENTITY_FILE)
        if p.exists():
            data = json.loads(p.read_text())
            if data.get("id") and data.get("idKey") and data.get("secretKey"):
                return data
    except Exception:
        log("Warning: failed to load identity")
    return None


def save_identity(identity: dict) -> None:
    p = pathlib.Path(IDENTITY_FILE)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(identity, indent=2))
    os.chmod(str(p), 0o600)
    log(f"Identity saved to {IDENTITY_FILE}")


# ---------------------------------------------------------------------------
# Auto-detect Unix socket path
# ---------------------------------------------------------------------------
def detect_socket_path() -> str | None:
    """Try to find the KeePassXC browser integration socket."""
    candidates = []

    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        candidates.append(os.path.join(xdg, "kpxc_server"))

    tmpdir = os.environ.get("TMPDIR", "").rstrip("/")
    if tmpdir:
        candidates.append(os.path.join(tmpdir, "kpxc_server"))

    uid = os.getuid() if hasattr(os, "getuid") else None
    if uid is not None:
        candidates.append(f"/run/user/{uid}/kpxc_server")

    candidates.append("/tmp/kpxc_server")

    for path in candidates:
        if os.path.exists(path):
            return path
    return None


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
class KPXCClient:
    def __init__(self, host: str | None = None, port: int | None = None,
                 socket_path: str | None = None, timeout: float = 30):
        self.host = host
        self.port = port
        self.socket_path = socket_path
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.session_sk_obj: PrivateKey | None = None
        self.session_pk: bytes | None = None
        self.server_pk: bytes | None = None
        self.client_id: str = ""
        self.identity: dict | None = load_identity()
        self._lock = threading.Lock()
        self._new_session()

    @property
    def mode(self) -> str:
        return "tcp" if self.host else "unix"

    def _new_session(self):
        sk = PrivateKey.generate()
        self.session_sk_obj = sk
        self.session_pk = bytes(sk.public_key)
        self.client_id = b64e(nacl_random(24))
        self.server_pk = None

    # ---- connection --------------------------------------------------------

    def connect(self):
        if self.sock:
            return
        self._new_session()
        if self.mode == "tcp":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((self.host, self.port))
            log(f"Connected to TCP {self.host}:{self.port}")
        else:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect(self.socket_path)
            log(f"Connected to socket {self.socket_path}")

    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
            self.server_pk = None
            log("Disconnected")

    def _reconnect(self):
        self.disconnect()
        self.connect()

    # ---- low-level ---------------------------------------------------------

    def _send_recv(self, msg: dict, timeout: float | None = None) -> dict:
        timeout = timeout or self.timeout
        raw = json.dumps(msg) + "\n"
        self.sock.sendall(raw.encode())
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = max(deadline - time.time(), 0.1)
            self.sock.settimeout(remaining)
            try:
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise ConnectionError("Connection closed")
                buf += chunk
                try:
                    return json.loads(buf.decode())
                except json.JSONDecodeError:
                    continue
            except socket.timeout:
                continue
        raise TimeoutError(f"No response within {timeout}s")

    # ---- crypto ------------------------------------------------------------

    def _encrypt(self, payload: dict) -> tuple[str, str]:
        nonce = nacl_random(24)
        pt = json.dumps(payload).encode()
        ct = Box(self.session_sk_obj, PublicKey(self.server_pk)).encrypt(
            pt, nonce).ciphertext
        return b64e(ct), b64e(nonce)

    def _decrypt(self, msg_b64: str, nonce_b64: str) -> dict:
        pt = Box(self.session_sk_obj, PublicKey(self.server_pk)).decrypt(
            b64d(msg_b64), b64d(nonce_b64))
        return json.loads(pt.decode())

    # ---- protocol ----------------------------------------------------------

    def exchange_keys(self):
        self.connect()
        nonce = b64e(nacl_random(24))
        resp = self._send_recv({
            "action": "change-public-keys",
            "publicKey": b64e(self.session_pk),
            "nonce": nonce,
            "clientID": self.client_id,
        })
        if resp.get("success") != "true":
            raise RuntimeError(f"Key exchange failed: {resp}")
        self.server_pk = b64d(resp["publicKey"])
        log("Key exchange complete")

    def send_encrypted(self, action: str, payload: dict = {},
                       timeout: float | None = None) -> dict:
        if not self.server_pk:
            self.exchange_keys()
        message, nonce = self._encrypt({"action": action, **payload})
        resp = self._send_recv({
            "action": action, "message": message,
            "nonce": nonce, "clientID": self.client_id,
        }, timeout=timeout)
        if resp.get("error") and not resp.get("message"):
            raise RuntimeError(
                f"KeePassXC error: {resp['error']} "
                f"(code: {resp.get('errorCode', '?')})")
        if resp.get("message") and resp.get("nonce"):
            return self._decrypt(resp["message"], resp["nonce"])
        return resp

    def request(self, action: str, payload: dict = {},
                timeout: float | None = None) -> dict:
        """send_encrypted with one reconnect retry."""
        try:
            return self.send_encrypted(action, payload, timeout)
        except (ConnectionError, BrokenPipeError, ConnectionResetError,
                OSError) as e:
            log(f"Connection lost ({e}) — reconnecting")
            self._reconnect()
            return self.send_encrypted(action, payload, timeout)

    # ---- association -------------------------------------------------------

    def associate(self) -> str:
        if not self.server_pk:
            self.exchange_keys()
        id_sk = PrivateKey.generate()
        id_pk = bytes(id_sk.public_key)
        result = self.send_encrypted("associate", {
            "key": b64e(self.session_pk),
            "idKey": b64e(id_pk),
        }, timeout=120)
        if result.get("success") != "true":
            raise RuntimeError(f"Association failed: {result}")
        identity = {
            "id": result["id"],
            "idKey": b64e(id_pk),
            "secretKey": b64e(bytes(id_sk)),
        }
        save_identity(identity)
        self.identity = identity
        log(f'Associated as "{result["id"]}"')
        return result["id"]

    def test_associate(self) -> bool:
        if not self.identity:
            return False
        try:
            result = self.send_encrypted("test-associate", {
                "id": self.identity["id"],
                "key": self.identity["idKey"],
            })
            return result.get("success") == "true"
        except Exception:
            return False

    def ensure_associated(self):
        if not self.server_pk:
            self.exchange_keys()
        if self.identity:
            if self.test_associate():
                log(f'Association "{self.identity["id"]}" valid')
                return
            log("Stored association invalid — re-associating")
        self.associate()

    def ensure_ready(self):
        """ensure_associated with reconnect on stale socket."""
        try:
            self.ensure_associated()
        except (ConnectionError, BrokenPipeError, ConnectionResetError,
                OSError, TimeoutError) as e:
            log(f"Connection lost during readiness check ({e}) — reconnecting")
            self._reconnect()
            self.ensure_associated()

    # ---- high-level API ----------------------------------------------------

    def get_logins(self, url: str, submit_url: str | None = None) -> dict:
        with self._lock:
            self.ensure_ready()
            payload: dict = {
                "url": url,
                "keys": [{"id": self.identity["id"],
                           "key": self.identity["idKey"]}],
            }
            if submit_url:
                payload["submitUrl"] = submit_url
            return self.request("get-logins", payload)

    def get_totp(self, uuid: str) -> dict:
        with self._lock:
            self.ensure_ready()
            return self.request("get-totp", {"uuid": uuid})

    def set_login(self, params: dict) -> dict:
        with self._lock:
            self.ensure_ready()
            return self.request("set-login", {
                **params, "id": self.identity["id"]})

    def generate_password(self) -> dict:
        with self._lock:
            if not self.server_pk:
                self.exchange_keys()
            nonce = b64e(nacl_random(24))
            resp = self._send_recv({
                "action": "generate-password",
                "nonce": nonce,
                "clientID": self.client_id,
            }, timeout=60)
            if resp.get("message") and resp.get("nonce"):
                return self._decrypt(resp["message"], resp["nonce"])
            if resp.get("error"):
                raise RuntimeError(f"KeePassXC error: {resp['error']}")
            return resp

    def lock_database(self) -> dict:
        with self._lock:
            self.ensure_ready()
            try:
                return self.request("lock-database")
            except RuntimeError as e:
                if "Database not opened" in str(e):
                    return {"success": "true", "locked": True}
                raise

    def get_database_groups(self) -> dict:
        with self._lock:
            self.ensure_ready()
            return self.request("get-database-groups")

    def get_databasehash(self) -> dict:
        with self._lock:
            self.ensure_ready()
            return self.request("get-databasehash")
