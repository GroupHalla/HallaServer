#!/usr/bin/env python3
"""End-to-end test for protocol-v5 plugin_data routing and limits."""

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
                 nickname: str, protocol: int = 5) -> None:
        identity = work / nickname
        identity.mkdir(parents=True)
        private_key = identity / "identity.pem"
        public_key = identity / "identity.der"
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
        self.send({
            "t": "hello", "proto": protocol, "uid": uid,
            "idPub": base64.b64encode(der).decode(), "nick": nickname,
            "ver": "plugin-data-integration", "platform": "Linux",
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


def encoded(data: bytes) -> str:
    return base64.b64encode(data).decode()


def plugin_message(target: int, topic: str, data: bytes,
                   ids: list[int] | None = None) -> dict:
    message = {
        "t": "plugin_data", "plugin": "community.positional",
        "target": target, "topic": topic, "data": encoded(data),
    }
    if ids is not None:
        message["ids"] = ids
    return message


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="build/halla-server")
    args = parser.parse_args()
    server = Path(args.server).resolve()
    if not server.is_file():
        raise SystemExit(f"server executable not found: {server}")

    work = Path(tempfile.mkdtemp(prefix="halla-plugin-data-"))
    port = free_port()
    config = work / "halla-server.ini"
    config.write_text(
        "[server]\nname=Plugin Data Integration\n"
        f"port={port}\nmaxClients=4\nadminPassword=\n"
        "[query]\nport=0\n[database]\ntype=sqlite\n",
        encoding="utf-8")
    log_path = work / "server.log"
    log = log_path.open("wb")
    process = subprocess.Popen(
        [str(server), "--config", str(config)], cwd=work,
        stdout=log, stderr=subprocess.STDOUT)
    clients: list[Client] = []
    try:
        sender = Client("127.0.0.1", port, work, "PositionSender")
        clients.append(sender)
        receiver = Client("127.0.0.1", port, work, "PositionReceiver")
        clients.append(receiver)
        sender.receive("user_joined")
        legacy = Client("127.0.0.1", port, work, "LegacyClient", protocol=4)
        clients.append(legacy)
        sender.receive("user_joined")
        receiver.receive("user_joined")

        sender.send(plugin_message(0, "position.v1", b"xyz-position"))
        channel = receiver.receive("plugin_data")
        assert channel["from"] == sender.id
        assert channel["plugin"] == "community.positional"
        assert channel["topic"] == "position.v1"
        assert base64.b64decode(channel["data"]) == b"xyz-position"

        receiver.send(plugin_message(1, "radio.v1", b"police", [sender.id]))
        direct = sender.receive("plugin_data")
        assert direct["from"] == receiver.id
        assert base64.b64decode(direct["data"]) == b"police"

        sender.send(plugin_message(2, "server.v1", b"broadcast"))
        broadcast = receiver.receive("plugin_data")
        assert broadcast["topic"] == "server.v1"

        sender.send(plugin_message(0, "too-big", b"x" * 8193))
        too_big = sender.receive("error")
        assert too_big["code"] == "plugin_data_too_big", too_big

        invalid = plugin_message(0, "invalid-id", b"")
        invalid["plugin"] = "INVALID PLUGIN"
        sender.send(invalid)
        bad_id = sender.receive("error")
        assert bad_id["code"] == "bad_plugin_data", bad_id

        legacy.send(plugin_message(0, "legacy", b"unsupported"))
        unsupported = legacy.receive("error")
        assert unsupported["code"] == "plugin_data_unsupported", unsupported

        for client in reversed(clients):
            client.close()
        clients.clear()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        log.close()
        print("Plugin-data v5 integration OK")
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
