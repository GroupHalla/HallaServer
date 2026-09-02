#!/usr/bin/env python3
"""Regression test for session cleanup on server-initiated disconnects.

Root cause covered here: ClientSession::closeAndDelete() detaches the
socket's `disconnected` signal, so ServerCore::onClientDisconnected()
(the only place that used to remove the session from every structure)
never ran for server-initiated closes. Authenticated sessions were
destroyed while still listed in m_channels/m_clients — the next
broadcast()/relayVoice() dereferenced the dangling pointer and crashed
the server (use-after-free). Any logged-in client could trigger it by
sending a > 2 MiB TCP message (message_too_big path); the idle timer
(5 min) triggered the same path for AFK users.

Fix under test:
- ServerCore::reapUser() runs the FULL disconnect cycle (user_left,
  channels, screen watchers, whisper target lists, m_clients, voice
  token) before closing, and is now used by checkIdleClients(),
  doKick(), the quit handler and onClientDisconnected().
- message_too_big closes via the natural path (disconnectFromHost →
  disconnected → reapUser) instead of closeAndDelete().

Assertions that fail on the old code:
- the other clients DO receive user_left for the protocol-killed
  session (before: nobody was notified, session stayed as a ghost);
- a client joining afterwards does NOT see the dead id in the welcome
  user list (ghost user);
- the server survives and keeps broadcasting (chat) after the close.
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
            "ver": "session-cleanup-integration", "platform": "Linux",
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

    def send_raw(self, payload: bytes) -> None:
        self.stream.write(payload)

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

    def user_ids(self) -> set:
        return {user["id"] for user in self.welcome["users"]}

    def ping(self) -> None:
        self.send({"t": "ping", "ts": int(time.time() * 1000)})
        self.receive("pong")

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

    work = Path(tempfile.mkdtemp(prefix="halla-session-cleanup-"))
    port = free_port()
    config = work / "halla-server.ini"
    config.write_text(
        "[server]\nname=Session Cleanup Integration\n"
        f"port={port}\nmaxClients=8\nadminPassword=CleanupAdminSecret\n"
        "[query]\nport=0\n[database]\ntype=sqlite\n",
        encoding="utf-8")
    log_path = work / "server.log"
    log = log_path.open("wb")
    process = start_server(server, config, work, log)
    clients: list[Client] = []
    try:
        # 1) Três clientes autenticados no canal padrão.
        survivor = Client("127.0.0.1", port, work, "Survivor")
        clients.append(survivor)
        victim = Client("127.0.0.1", port, work, "Victim")
        clients.append(victim)
        listener = Client("127.0.0.1", port, work, "Listener")
        clients.append(listener)
        for user in (survivor, listener):
            user.receive("user_joined")

        # 2) Survivor sussurra para Victim (o id de Victim entra no conjunto
        #    de alvos — o cleanup tem que removê-lo quando Victim cair).
        survivor.send({"t": "whisper", "ids": [victim.id]})
        survivor.receive("whisper_ok", lambda m: m.get("count") == 1)

        # 3) Victim viola o limite de mensagem TCP (> 2 MiB sem newline).
        #    Caminho de fechamento iniciado pelo servidor para um cliente
        #    AUTENTICADO — antes do fix, o mesmo bug de use-after-free do
        #    checkIdleClients (closeAndDelete sem cleanup).
        victim.send_raw(b"x" * (2 * 1024 * 1024 + 4096))
        error = victim.receive("error")
        assert error["code"] == "message_too_big", error

        # 4) A conexão de Victim é fechada pelo servidor.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not victim.stream.readline():
                break
        else:
            raise AssertionError("server did not close the offender connection")
        clients.remove(victim)

        # 5) REGRESSÃO: os demais recebem user_left (antes: ninguém era
        #    notificado e a sessão morta ficava pendurada em m_clients).
        for user in (survivor, listener):
            gone = user.receive(
                "user_left", lambda m: m.get("id") == victim.id
                                     and m.get("reason") == "dropped")
            assert gone["id"] == victim.id, gone

        # 6) REGRESSÃO: novo cliente não vê o id morto na lista do welcome
        #    (usuário fantasma).
        latecomer = Client("127.0.0.1", port, work, "Latecomer")
        clients.append(latecomer)
        assert victim.id not in latecomer.user_ids(), latecomer.welcome["users"]
        survivor.receive("user_joined")
        listener.receive("user_joined")

        # 7) REGRESSÃO (crash): broadcast depois do fechamento — antes do fix
        #    o survivor.id ainda tinha o ponteiro pendurado e o servidor caía
        #    com SIGSEGV ao iterar m_clients.
        survivor.send({"t": "chat", "scope": "server", "text": "ping depois do cleanup"})
        delivered = listener.receive(
            "chat", lambda m: m.get("text") == "ping depois do cleanup")
        assert delivered["from"] == survivor.id, delivered

        # 8) O conjunto de sussurro de Survivor perdeu o id morto: sussurrar
        #    para [id morto, listener] filtra o morto (count = 1).
        survivor.send({"t": "whisper", "ids": [victim.id, listener.id]})
        survivor.receive(
            "whisper_ok",
            lambda m: m.get("count") == 1)  # id morto filtrado == cleanup OK

        # 9) Kick de servidor (doKick): user_left com reason=kicked para todos
        #    e o expulso recebe a mensagem kicked antes de cair.
        admin = Client("127.0.0.1", port, work, "KickAdmin",
                       admin_password="CleanupAdminSecret")
        clients.append(admin)
        for user in (survivor, listener, latecomer):
            user.receive("user_joined")
        admin.send({"t": "kick", "id": latecomer.id, "from": "server",
                    "reason": "cleanup-test"})
        kicked = latecomer.receive("kicked")
        assert kicked["reason"] == "cleanup-test", kicked
        for user in (survivor, listener, admin):
            gone = user.receive(
                "user_left", lambda m: m.get("id") == latecomer.id
                                     and m.get("reason") == "kicked")
            assert gone["id"] == latecomer.id, gone
        clients.remove(latecomer)

        # 10) O servidor segue íntegro: ping/pong e mais um broadcast.
        survivor.ping()
        survivor.send({"t": "chat", "scope": "server", "text": "final"})
        listener.receive("chat", lambda m: m.get("text") == "final")
        assert process.poll() is None, "server process died during the test"

        for client in reversed(clients):
            client.close()
        clients.clear()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        log.close()
        print("Session cleanup integration OK")
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
