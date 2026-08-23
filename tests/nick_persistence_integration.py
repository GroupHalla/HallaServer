#!/usr/bin/env python3
"""End-to-end test for server-side nickname persistence.

Covers the "apelido por servidor" contract:
- self rename persists for the identity (UID) and survives reconnect;
- admin rename of another client (nick with target id) persists too;
- clients without the moderation permission cannot rename others;
- the stored nickname survives a full server restart (SQLite registry).
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
            "ver": "nick-persistence-integration", "platform": "Linux",
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

    def self_name(self) -> str:
        for user in self.welcome["users"]:
            if user["id"] == self.id:
                return user["name"]
        raise AssertionError("self user missing from welcome")

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


def start_server(server: Path, config: Path, work: Path, log):
    return subprocess.Popen(
        [str(server), "--config", str(config)], cwd=work,
        stdout=log, stderr=subprocess.STDOUT)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="build/halla-server")
    args = parser.parse_args()
    server = Path(args.server).resolve()
    if not server.is_file():
        raise SystemExit(f"server executable not found: {server}")

    work = Path(tempfile.mkdtemp(prefix="halla-nick-persistence-"))
    port = free_port()
    config = work / "halla-server.ini"
    config.write_text(
        "[server]\nname=Nick Persistence Integration\n"
        f"port={port}\nmaxClients=6\nadminPassword=NickAdminSecret\n"
        "[query]\nport=0\n[database]\ntype=sqlite\n",
        encoding="utf-8")
    log_path = work / "server.log"
    log = log_path.open("wb")
    process = start_server(server, config, work, log)
    clients: list[Client] = []
    try:
        # 1) Login inicial com apelido qualquer e renomeação própria.
        owner = Client("127.0.0.1", port, work, "NicknameHolder")
        clients.append(owner)
        assert owner.self_name() == "NicknameHolder", owner.welcome
        owner.send({"t": "nick", "name": "RenomeadoPorMim"})
        renamed = owner.receive(
            "user_nick",
            lambda message: message.get("id") == owner.id
                            and message.get("name") == "RenomeadoPorMim")
        assert renamed["name"] == "RenomeadoPorMim", renamed

        admin = Client("127.0.0.1", port, work, "NickAdmin",
                       admin_password="NickAdminSecret")
        clients.append(admin)
        owner.receive("user_joined")

        intruder = Client("127.0.0.1", port, work, "NoPermClient")
        clients.append(intruder)
        owner.receive("user_joined")

        # 2) Cliente sem permissão de moderação não renomeia terceiros.
        intruder.send({"t": "nick", "id": owner.id, "name": "SequestreiONome"})
        denied = intruder.receive("error")
        assert denied["code"] == "no_permission", denied

        # 3) Administrador renomeia outro cliente; todos veem o broadcast.
        admin.send({"t": "nick", "id": owner.id, "name": "NomeDoAdministrador"})
        forced = owner.receive(
            "user_nick",
            lambda message: message.get("id") == owner.id
                            and message.get("name") == "NomeDoAdministrador")
        assert forced["name"] == "NomeDoAdministrador", forced
        intruder.receive(
            "user_nick",
            lambda message: message.get("id") == owner.id
                            and message.get("name") == "NomeDoAdministrador")

        # 4) Reconexão com outro nick no hello: o servidor restaura o salvo.
        owner.close()
        clients.remove(owner)
        time.sleep(0.3)  # dá tempo do servidor processar a desconexão
        returning = Client("127.0.0.1", port, work, "NicknameHolder")
        clients.append(returning)
        assert returning.self_name() == "NomeDoAdministrador", returning.welcome

        # 5) Reinício completo do servidor: o apelido segue no banco.
        for client in reversed(clients):
            client.close()
        clients.clear()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        log.close()
        log = log_path.open("ab")
        process = start_server(server, config, work, log)
        revived = Client("127.0.0.1", port, work, "NicknameHolder")
        clients.append(revived)
        assert revived.self_name() == "NomeDoAdministrador", revived.welcome
        revived.close()
        clients.remove(revived)
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        log.close()
        print("Nickname persistence integration OK")
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
