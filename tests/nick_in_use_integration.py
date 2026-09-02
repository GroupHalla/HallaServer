#!/usr/bin/env python3
"""End-to-end test for the nickname ownership rules on hello.

Contract under test:
1. A nickname already in use by ANOTHER online identity is REFUSED with the
   `name_in_use` error (connection closed). Before this fix the newcomer
   stole the nickname and the innocent client was kicked instead.
2. Reconnecting with the SAME identity (same UID) still replaces the old
   session (zombie cleanup unchanged).
3. An empty nickname keeps being refused with `bad_nick` (clients must ask
   for a name before connecting).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import select
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time


def make_identity(work: Path, name: str) -> tuple[Path, Path, bytes, str]:
    identity = work / "identities" / name
    identity.mkdir(parents=True, exist_ok=True)
    private_key = identity / "identity.pem"
    public_key = identity / "identity.der"
    if not private_key.exists():
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(
            ["openssl", "pkey", "-in", str(private_key), "-pubout",
             "-outform", "DER", "-out", str(public_key)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    der = public_key.read_bytes()
    uid = base64.b64encode(hashlib.sha256(der).digest()).decode()
    # v6: o login exige dhPub/dhSig — a variante crua conecta com o par também.
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location(
        "e2ee_v6", Path(__file__).resolve().parent / "e2ee_v6.py")
    _e2ee = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_e2ee)
    v6 = _e2ee.V6Identity(identity)
    return private_key, identity, der, uid, v6


def sign(private_key: Path, identity: Path, nonce_b64: str) -> str:
    nonce = identity / "nonce.bin"
    signature = identity / "signature.bin"
    nonce.write_bytes(base64.b64decode(nonce_b64))
    subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-inkey", str(private_key),
         "-rawin", "-in", str(nonce), "-out", str(signature)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return base64.b64encode(signature.read_bytes()).decode()


class Client:
    def __init__(self, host: str, port: int, work: Path,
                 nickname: str, protocol: int = 6,
                 admin_password: str = "") -> None:
        private_key, identity, der, uid, self.v6 = make_identity(work, nickname)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        last_error: Exception | None = None
        for _ in range(100):
            try:
                raw = socket.create_connection((host, port), timeout=0.5)
                self.socket = context.wrap_socket(raw, server_hostname="HallaServer")
                break
            except Exception as error:
                last_error = error
                time.sleep(0.1)
        else:
            raise AssertionError(f"server unavailable: {last_error}")
        self.socket.settimeout(5)
        self.stream = self.socket.makefile("rwb", buffering=0)

        self.send({
            "t": "hello", "proto": protocol, "uid": uid,
            "idPub": base64.b64encode(der).decode(), "nick": nickname,
            "adminPass": admin_password,
            "ver": "nick-in-use", "platform": "Linux",
            "dhPub": self.v6.hello_fields()["dhPub"],
            "dhSig": self.v6.hello_fields()["dhSig"],
        })
        challenge = self.receive("identity_challenge")
        self.send({
            "t": "identity_proof",
            "sig": sign(private_key, identity, challenge["nonce"]),
        })
        self.welcome = self.receive("welcome")
        self.id = self.welcome["selfId"]

    def send(self, message: dict) -> None:
        self.stream.write(json.dumps(message, separators=(",", ":")).encode() + b"\n")

    def receive(self, message_type: str, predicate=lambda _message: True) -> dict:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            line = self.stream.readline()
            if not line:
                raise AssertionError("server closed the connection")
            message = json.loads(line)
            if message.get("t") == message_type and predicate(message):
                return message
        raise AssertionError(f"timeout waiting for {message_type}")

    def quiet_collect(self, seconds: float) -> list[dict]:
        """Collects messages arriving within the window without tripping a
        socket timeout mid-read (select-guarded)."""
        collected: list[dict] = []
        deadline = time.monotonic() + seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readable, _, _ = select.select([self.socket], [], [], remaining)
            if not readable:
                break
            line = self.stream.readline()
            if not line:
                break
            collected.append(json.loads(line))
        return collected

    def close(self) -> None:
        try:
            self.stream.close()
        finally:
            self.socket.close()


def connect_raw(host: str, port: int, work: Path, identity_name: str, requested_nick: str):
    """Opens a TLS connection and sends the hello with the requested nick.
    Completes the identity handshake when challenged; immediate errors
    (e.g. bad_nick arrives BEFORE the challenge) are stored in
    holder.pending_error."""
    private_key, identity, der, uid, v6 = make_identity(work, identity_name)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, port), timeout=5)
    sock = context.wrap_socket(raw, server_hostname="HallaServer")
    sock.settimeout(5)
    stream = sock.makefile("rwb", buffering=0)

    holder = Client.__new__(Client)
    holder.socket = sock
    holder.stream = stream
    holder.pending_error = None
    holder.send({
        "t": "hello", "proto": 6, "uid": uid,
        "idPub": base64.b64encode(der).decode(), "nick": requested_nick,
        "ver": "nick-in-use", "platform": "Linux",
        "dhPub": v6.hello_fields()["dhPub"],
        "dhSig": v6.hello_fields()["dhSig"],
    })
    first = json.loads(stream.readline())
    if first.get("t") == "error":
        holder.pending_error = first
        return holder
    assert first.get("t") == "identity_challenge", first
    holder.send({
        "t": "identity_proof",
        "sig": sign(private_key, identity, first["nonce"]),
    })
    return holder


def free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="build/halla-server")
    args = parser.parse_args()
    server = Path(args.server).resolve()
    if not server.is_file():
        raise SystemExit(f"server executable not found: {server}")

    work = Path(tempfile.mkdtemp(prefix="halla-nick-in-use-"))
    port = free_port()
    config = work / "halla-server.ini"
    config.write_text(
        "[server]\nname=Nick In Use Integration\n"
        f"port={port}\nmaxClients=8\nadminPassword=NickAdminSecret\n"
        "[query]\nport=0\n[database]\ntype=sqlite\n",
        encoding="utf-8")
    log_path = work / "server.log"
    log = log_path.open("wb")
    process = subprocess.Popen(
        [str(server), "--config", str(config)], cwd=work,
        stdout=log, stderr=subprocess.STDOUT)
    clients: list[Client] = []
    try:
        admin = Client("127.0.0.1", port, work, "NickAdmin",
                       admin_password="NickAdminSecret")
        clients.append(admin)

        # A second, DIFFERENT identity takes the nickname "SecondIdentity".
        second = Client("127.0.0.1", port, work, "SecondIdentity")
        clients.append(second)
        admin.receive("user_joined")

        # ----------------------------------------------------- name_in_use
        # A third identity tries the SAME nickname: must be refused.
        thief = connect_raw("127.0.0.1", port, work, "ThiefIdentity", "SecondIdentity")
        refused = thief.receive("error", lambda m: m.get("code") == "name_in_use")
        assert refused, "expected name_in_use error"
        deadline = time.monotonic() + 5
        closed = False
        while time.monotonic() < deadline:
            line = thief.stream.readline()
            if not line:
                closed = True
                break
        assert closed, "server did not close the refused connection"
        thief.close()

        # The innocent holder keeps the nickname and stays connected.
        stray = second.quiet_collect(0.5)
        assert not any(m.get("t") in ("kicked", "user_left") for m in stray), (
            f"innocent client was disturbed: {stray}")
        second.send({"t": "ping", "ts": int(time.time() * 1000)})
        second.receive("pong")

        # ------------------------------------------------ empty nickname
        # bad_nick chega ANTES do desafio de identidade.
        empty = connect_raw("127.0.0.1", port, work, "EmptyNick", "")
        assert empty.pending_error is not None, "expected an immediate error"
        assert empty.pending_error.get("code") == "bad_nick", empty.pending_error
        empty.close()

        # --------------------------------------- same-identity reconnect
        # Reconnecting the same UID still replaces the previous session.
        again = Client("127.0.0.1", port, work, "SecondIdentity")
        clients.append(again)
        assert again.id > 0, "same-identity reconnect must succeed"
        kicked = second.receive("kicked")  # old session gets the boot
        assert kicked.get("reason") == "Nova sessão iniciada", kicked

        for client in reversed(clients):
            client.close()
        clients.clear()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        log.close()
        print("Nick in use integration OK")
    except Exception:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        log.close()
        print(log_path.read_text(errors="replace")[-4000:])
        shutil.rmtree(work, ignore_errors=True)
        for client in clients:
            try:
                client.close()
            except Exception:
                pass
        raise


if __name__ == "__main__":
    main()
