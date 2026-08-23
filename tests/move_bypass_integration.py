#!/usr/bin/env python3
"""End-to-end test for admin move bypassing the target's channel permissions.

Covers the "puxar para canal restrito" contract:
- a channel denying `join` for the Normal group rejects self-joins;
- an admin (or privilege-key identity) CAN move a Normal client into that
  channel via move_other — the mover's authority replaces the target's own
  join/view permissions;
- hierarchy, channel full and unknown channel still behave.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time


class Client:
    def __init__(self, host: str, port: int, work: Path,
                 nickname: str, protocol: int = 5,
                 admin_password: str = "") -> None:
        identity = work / "identities" / nickname
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

        der = public_key.read_bytes()
        uid = base64.b64encode(hashlib.sha256(der).digest()).decode()
        self.uid = uid
        self.send({
            "t": "hello", "proto": protocol, "uid": uid,
            "idPub": base64.b64encode(der).decode(), "nick": nickname,
            "adminPass": admin_password,
            "ver": "move-bypass-integration", "platform": "Linux",
        })
        challenge = self.receive("identity_challenge")
        nonce = identity / "nonce.bin"
        signature = identity / "signature.bin"
        nonce.write_bytes(base64.b64decode(challenge["nonce"]))
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(private_key),
             "-rawin", "-in", str(nonce), "-out", str(signature)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.send({
            "t": "identity_proof",
            "sig": base64.b64encode(signature.read_bytes()).decode(),
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

    def channel_of_self(self) -> int:
        for chan in self.welcome["channels"]:
            if self.id in chan.get("users", []):
                return chan["id"]
        return 0

    def close(self) -> None:
        try:
            self.stream.close()
        finally:
            self.socket.close()


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

    work = Path(tempfile.mkdtemp(prefix="halla-move-bypass-"))
    port = free_port()
    config = work / "halla-server.ini"
    config.write_text(
        "[server]\nname=Move Bypass Integration\n"
        f"port={port}\nmaxClients=6\nadminPassword=MoveAdminSecret\n"
        "[query]\nport=0\n[database]\ntype=sqlite\n",
        encoding="utf-8")
    log_path = work / "server.log"
    log = log_path.open("wb")
    process = subprocess.Popen(
        [str(server), "--config", str(config)], cwd=work,
        stdout=log, stderr=subprocess.STDOUT)
    clients: list[Client] = []
    try:
        admin = Client("127.0.0.1", port, work, "MoveAdmin",
                       admin_password="MoveAdminSecret")
        clients.append(admin)

        # Canal restrito: cargo Normal (id 2) com join NEGADO.
        admin.send({
            "t": "chan_create", "name": "Sala Restrita", "type": 2, "parent": 0,
            "groupPerms": {"2": {"join": 0}},
        })
        created = admin.receive(
            "chan_update",
            lambda message: message.get("chan", {}).get("name") == "Sala Restrita")
        restricted = created["chan"]["id"]

        normal = Client("127.0.0.1", port, work, "NormalMortal")
        clients.append(normal)
        admin.receive("user_joined")

        # 1) O cargo Normal não consegue entrar por conta própria.
        normal.send({"t": "move", "channel": restricted})
        denied = normal.receive("error")
        assert denied["code"] == "no_permission", denied

        # 2) O administrador PUXA o cliente para o canal restrito: as
        #    permissões do alvo não participam; a autoridade é de quem move.
        admin.send({"t": "move_other", "id": normal.id, "channel": restricted})
        moved = admin.receive(
            "user_moved",
            lambda message: message.get("id") == normal.id
                            and message.get("channel") == restricted)
        assert moved["channel"] == restricted, moved
        normal.receive(
            "user_moved",
            lambda message: message.get("id") == normal.id
                            and message.get("channel") == restricted)

        # 3) Canal inexistente continua sendo recusado.
        admin.send({"t": "move_other", "id": normal.id, "channel": 99999})
        invalid = admin.receive("error")
        assert invalid["code"] == "invalid_channel", invalid

        # 4) Sem hierarquia suficiente, um Normal não move outro Normal.
        normal.send({"t": "move_other", "id": admin.id, "channel": 1})
        forbidden = normal.receive("error")
        assert forbidden["code"] in ("no_permission", "hierarchy"), forbidden

        for client in reversed(clients):
            client.close()
        clients.clear()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        log.close()
        print("Move bypass integration OK")
    except Exception:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        log.close()
        print(log_path.read_text(encoding="utf-8", errors="replace"))
        raise
    finally:
        for client in reversed(clients):
            try:
                client.close()
            except Exception:
                pass
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        if not log.closed:
            log.close()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
