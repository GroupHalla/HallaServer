#!/usr/bin/env python3
"""End-to-end test for cross-channel whisper key distribution.

Covers the contract broken before this fix:
- A whisperer in channel A, target in channel B (A and B not linked).
- Before the fix, the target's welcome only carried keys for B (and B's
  linked component). The whisperer's UDP frames are encrypted with A's
  channel key, which the target does NOT possess — audio is silently
  undecryptable, whisper appears "dead".
- After the fix, handleWhisper pushes the whisperer's current channel
  key to every whisper target via `channel_key`. The client already
  tries every known key when decrypting, so this restores audio.
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
        # Latest channel_key per channel id observed by this client.
        self.latest_channel_key: dict[int, str] = {}
        self.send({
            "t": "hello", "proto": protocol, "uid": uid,
            "idPub": base64.b64encode(der).decode(), "nick": nickname,
            "adminPass": admin_password,
            "ver": "whisper-cross-channel", "platform": "Linux",
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
        # move, removeFromChannels(normal) rotates channel 1's key (so admin
        # gets a fresh key K_admin), and addToChannel(normal, B) rotates
        # channel B's key. The two clients no longer share any channel key.
        normal.send({"t": "move", "channel": channel_b})
        normal.receive("user_moved",
                       lambda m: m.get("id") == normal.id
                       and m.get("channel") == channel_b)
        admin.receive("user_moved",
                      lambda m: m.get("id") == normal.id
                      and m.get("channel") == channel_b)

        # Admin's current key for channel 1 — the value the whisper handler
        # must replicate to the target. The latest_channel_key map is kept
        # up-to-date by the receive() loop above, so it already reflects
        # every channel_key the server pushed after the recent rotations.
        assert 1 in admin.latest_channel_key, admin.latest_channel_key
        admin_chan1_key = admin.latest_channel_key[1]

        # Admin whispers to the normal user. handleWhisper must deliver a
        # channel_key for channel 1 to the target carrying admin's current
        # key — otherwise the target cannot decrypt the whisper frames.
        admin.send({"t": "whisper", "ids": [normal.id]})
        admin.receive("whisper_ok", lambda m: m.get("count") == 1)

        delivered = normal.receive(
            "channel_key",
            lambda m: m.get("channel") == 1)

        assert delivered["key"] == admin_chan1_key, (
            f"key mismatch: delivered={delivered['key']!r} "
            f"vs admin_chan1_key={admin_chan1_key!r}")

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
