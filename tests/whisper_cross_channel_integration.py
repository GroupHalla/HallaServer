#!/usr/bin/env python3
"""End-to-end test for cross-channel whisper (protocolo v6).

Contexto histórico: o sussurro cross-canal dependia do servidor replicar a
chave do canal do remetente para o alvo via channel_key (v5 — o servidor
conhecia as chaves). No v6 o servidor não conhece chave alguma: o áudio do
sussurro continua cifrado com a chave do canal do REMETENTE, e quem
embrulha essa chave para o alvo (e2e_key) é o próprio cliente remetente.

Este teste cobre o que continua sendo contrato do servidor:
- whisper_ok com o count correto (rota de áudio cross-canal mantida);
- NENHUM channel_key sai do servidor (v6: impossível — ele não tem chaves).
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


class Client:
    def __init__(self, host: str, port: int, work: Path,
                 nickname: str, protocol: int = 6,
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
        # v6 E2EE: par X25519 + binding assinado (o login recusa sem eles).
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location(
            "e2ee_v6", Path(__file__).resolve().parent / "e2ee_v6.py")
        _e2ee = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_e2ee)
        self.v6 = _e2ee.V6Identity(identity)

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
        # Latest channel_key per channel id observed by this client.
        self.latest_channel_key: dict[int, str] = {}
        self.send({
            "t": "hello", "proto": protocol, "uid": uid,
            "idPub": base64.b64encode(der).decode(), "nick": nickname,
            "adminPass": admin_password,
            "ver": "whisper-cross-channel", "platform": "Linux",
            "dhPub": self.v6.hello_fields()["dhPub"],
            "dhSig": self.v6.hello_fields()["dhSig"],
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
        # Seed the latest-key map from the welcome snapshot.
        for chan_id, key in self.welcome.get("channelKeys", {}).items():
            self.latest_channel_key[int(chan_id)] = key

    def send(self, message: dict) -> None:
        self.stream.write(json.dumps(message, separators=(",", ":")).encode() + b"\n")

    def receive(self, message_type: str, predicate=lambda _message: True) -> dict:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            line = self.stream.readline()
            if not line:
                raise AssertionError("server closed the connection")
            message = json.loads(line)
            # Track channel_key updates opportunistically so the test always
            # sees the freshest key regardless of when the rotation happened.
            if message.get("t") == "channel_key":
                self.latest_channel_key[int(message["channel"])] = message["key"]
            if message.get("t") == message_type and predicate(message):
                return message
        raise AssertionError(f"timeout waiting for {message_type}")

    def drain(self, seconds: float = 0.8) -> list[dict]:
        """Coleta tudo que chega na janela (select: readline só com dados
        prontos — timeout no meio do readline inutiliza o stream SSL)."""
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

    work = Path(tempfile.mkdtemp(prefix="halla-whisper-xchan-"))
    port = free_port()
    config = work / "halla-server.ini"
    config.write_text(
        "[server]\nname=Whisper Cross-Channel Integration\n"
        f"port={port}\nmaxClients=6\nadminPassword=WhisperAdminSecret\n"
        "[query]\nport=0\n[database]\ntype=sqlite\n",
        encoding="utf-8")
    log_path = work / "server.log"
    log = log_path.open("wb")
    process = subprocess.Popen(
        [str(server), "--config", str(config)], cwd=work,
        stdout=log, stderr=subprocess.STDOUT)
    clients: list[Client] = []
    try:
        admin = Client("127.0.0.1", port, work, "WhisperAdmin",
                       admin_password="WhisperAdminSecret")
        clients.append(admin)

        # Default channel id 1 always exists (server's auto-spawned root).
        # Create a second, non-linked channel so the two clients end up in
        # different channel components.
        admin.send({"t": "chan_create", "name": "Sala B", "type": 2, "parent": 0})
        created = admin.receive(
            "chan_update",
            lambda message: message.get("chan", {}).get("name") == "Sala B")
        channel_b = created["chan"]["id"]

        normal = Client("127.0.0.1", port, work, "WhisperTarget")
        clients.append(normal)
        admin.receive("user_joined")
        # normal never receives its own user_joined (server broadcasts to
        # OTHER clients only); the user_moved(channel=1) it does receive
        # for itself is consumed by the predicate below.

        # Normal user moves into the new (non-linked) channel B. After this
        # move the two clients are in different channel components — no key
        # material crosses components via the server (v6: o servidor não tem
        # chaves; o sussurro de quem está em A continua cifrado com a chave do
        # canal do remetente, e quem EMBRULHA essa chave para o alvo é o
        # cliente remetente, via e2e_key).
        normal.send({"t": "move", "channel": channel_b})
        normal.receive("user_moved",
                       lambda m: m.get("id") == normal.id
                       and m.get("channel") == channel_b)
        admin.receive("user_moved",
                      lambda m: m.get("id") == normal.id
                      and m.get("channel") == channel_b)

        # Admin whispers to the normal user. v6: whisper_ok normal, e NENHUM
        # channel_key — a entrega da chave do canal do remetente ao alvo é
        # responsabilidade do cliente remetente (e2e_key), não do servidor.
        admin.send({"t": "whisper", "ids": [normal.id]})
        admin.receive("whisper_ok", lambda m: m.get("count") == 1)

        stray = normal.drain(0.8)
        assert not any(m.get("t") == "channel_key" for m in stray), (
            f"servidor v6 distribuiu chave no sussurro: {stray}")

        # A rota de áudio do sussurro (relay UDP) continua entregando os
        # frames do remetente ao alvo cross-canal — o contrato de áudio que
        # existia antes; a chave para decifrá-los chega por e2e_key, do
        # próprio remetente.

        # Clearing the whisper must still return whisper_ok with count=0.
        admin.send({"t": "whisper", "ids": []})
        admin.receive("whisper_ok", lambda m: m.get("count") == 0)

        for client in reversed(clients):
            client.close()
        clients.clear()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        log.close()
        print("Whisper cross-channel integration OK")
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
