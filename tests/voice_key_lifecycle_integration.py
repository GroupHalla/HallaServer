#!/usr/bin/env python3
"""End-to-end tests for the voice channel-key lifecycle.

Covers three contracts broken before these fixes:

1. `move` must deliver the destination channel's key to the mover.
   Before, handleMove appended the user to the destination channel without
   rotating/redistributing keys: the mover kept encrypting with the PREVIOUS
   channel's key and nobody in the destination could decrypt the voice
   ("audio stops until the server restarts").

2. Key rotation (any join/leave in the whisperer's channel) must reach
   whisper targets OUTSIDE the channel component. Before, only in-component
   users received the rotated key, so a whisper went silent after the first
   join/leave in the sender's channel.

3. Re-sending an identical whisper set must not push channel_key to the
   targets again (old desktop clients re-sent whisper on every user_state,
   flooding the server and tripping the rate limit).
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
            "ver": "voice-key-lifecycle", "platform": "Linux",
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
            if message.get("t") == "channel_key":
                self.latest_channel_key[int(message["channel"])] = message["key"]
            if message.get("t") == message_type and predicate(message):
                return message
        raise AssertionError(f"timeout waiting for {message_type}")

    def quiet_for(self, seconds: float, channel: int | None = None) -> list[dict]:
        """Collects every message arriving within the window (short socket
        timeout). With `channel`, returns only channel_key messages for that
        channel. Used to assert that NOTHING (e.g. no duplicate or stale
        channel_key) is pushed."""
        self.socket.settimeout(seconds)
        collected: list[dict] = []
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                line = self.stream.readline()
            except (TimeoutError, socket.timeout, OSError):
                break
            if not line:
                break
            message = json.loads(line)
            if message.get("t") == "channel_key":
                self.latest_channel_key[int(message["channel"])] = message["key"]
                if channel is not None and int(message["channel"]) != channel:
                    continue
            collected.append(message)
        self.socket.settimeout(5)
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

    work = Path(tempfile.mkdtemp(prefix="halla-voice-keylife-"))
    port = free_port()
    config = work / "halla-server.ini"
    config.write_text(
        "[server]\nname=Voice Key Lifecycle Integration\n"
        f"port={port}\nmaxClients=8\nadminPassword=KeyLifeAdminSecret\n"
        "[query]\nport=0\n[database]\ntype=sqlite\n",
        encoding="utf-8")
    log_path = work / "server.log"
    log = log_path.open("wb")
    process = subprocess.Popen(
        [str(server), "--config", str(config)], cwd=work,
        stdout=log, stderr=subprocess.STDOUT)
    clients: list[Client] = []
    try:
        admin = Client("127.0.0.1", port, work, "KeyAdmin",
                       admin_password="KeyLifeAdminSecret")
        clients.append(admin)

        # Non-linked channel B for cross-channel scenarios.
        admin.send({"t": "chan_create", "name": "Sala B", "type": 2, "parent": 0})
        created = admin.receive(
            "chan_update",
            lambda message: message.get("chan", {}).get("name") == "Sala B")
        channel_b = created["chan"]["id"]

        mover = Client("127.0.0.1", port, work, "Mover")
        clients.append(mover)
        admin.receive("user_joined")

        # ------------------------------------------------------------- part 1
        # MOVE delivers the destination channel key to the mover. Before the
        # fix the mover kept the previous channel's key: its voice was
        # encrypted with a key nobody in the destination channel had.
        mover.send({"t": "move", "channel": channel_b})
        mover.receive("user_moved",
                      lambda m: m.get("id") == mover.id
                      and m.get("channel") == channel_b)
        admin.receive("user_moved",
                      lambda m: m.get("id") == mover.id
                      and m.get("channel") == channel_b)
        assert channel_b in mover.latest_channel_key, (
            "mover never received the destination channel key: "
            f"{mover.latest_channel_key}")

        # ------------------------------------------------------------- part 2
        # Whisper target OUTSIDE the channel keeps receiving rotated keys.
        # Admin (channel 1) whispers to mover (channel B).
        admin.send({"t": "whisper", "ids": [mover.id]})
        admin.receive("whisper_ok", lambda m: m.get("count") == 1)
        delivered = mover.receive(
            "channel_key", lambda m: m.get("channel") == 1)
        assert delivered["key"] == admin.latest_channel_key[1], (
            "initial whisper key mismatch")

        # Rotation trigger: a third user connects and joins channel 1
        # (admin's channel). The whisper target must receive the NEW key.
        third = Client("127.0.0.1", port, work, "ThirdUser")
        clients.append(third)
        admin.receive("user_joined")
        rotated = mover.receive(
            "channel_key",
            lambda m: m.get("channel") == 1
            and m.get("key") != delivered["key"])
        assert rotated["key"] == admin.latest_channel_key[1], (
            f"whisper target kept a stale key: {rotated['key']} vs "
            f"{admin.latest_channel_key[1]}")

        # Members of a channel must always converge on the same key after a
        # join: third moves into B and both B members share the rotated key.
        third.send({"t": "move", "channel": channel_b})
        third.receive("user_moved",
                      lambda m: m.get("id") == third.id
                      and m.get("channel") == channel_b)
        mover.receive("user_moved",
                      lambda m: m.get("id") == third.id
                      and m.get("channel") == channel_b)
        assert channel_b in third.latest_channel_key, (
            f"third never received channel B key: {third.latest_channel_key}")
        assert mover.latest_channel_key[channel_b] == third.latest_channel_key[channel_b], (
            "channel B members hold different keys after a move: "
            f"{mover.latest_channel_key[channel_b]} vs "
            f"{third.latest_channel_key[channel_b]}")

        # ------------------------------------------------------------- part 3
        # Identical whisper re-send: whisper_ok yes, duplicate channel_key no.
        admin.send({"t": "whisper", "ids": [mover.id]})
        admin.receive("whisper_ok", lambda m: m.get("count") == 1)
        stray = mover.quiet_for(0.8, channel=1)
        assert not stray, (
            f"identical whisper re-send pushed keys again: {stray}")

        # Changing the set DOES push keys again (target re-resolution).
        admin.send({"t": "whisper", "ids": []})
        admin.receive("whisper_ok", lambda m: m.get("count") == 0)
        admin.send({"t": "whisper", "ids": [mover.id]})
        admin.receive("whisper_ok", lambda m: m.get("count") == 1)
        mover.receive("channel_key", lambda m: m.get("channel") == 1)

        # ------------------------------------------------------------- part 4
        # Whisper target disconnect: whisperer's set is pruned, so a later
        # rotation delivers keys ONLY to component users (no dead ids), and
        # a fresh whisper to the reconnected target carries the live key.
        mover.close()
        clients.remove(mover)
        admin.receive("user_left", lambda m: m.get("id") == mover.id)
        mover2 = Client("127.0.0.1", port, work, "Mover")  # same identity, new session id
        clients.append(mover2)
        admin.receive("user_joined")
        mover2.send({"t": "move", "channel": channel_b})
        mover2.receive("user_moved",
                       lambda m: m.get("id") == mover2.id
                       and m.get("channel") == channel_b)
        admin.receive("user_moved",
                      lambda m: m.get("id") == mover2.id
                      and m.get("channel") == channel_b)
        # mover2's own move already delivered channel B's key; consume it.
        # Rotation in channel 1 (mover2 left it when moving to B) must NOT
        # reach mover2 anymore: the whisper set was pruned on disconnect.
        stray2 = mover2.quiet_for(0.8, channel=1)
        assert not stray2, (
            f"pruned whisper still delivered keys: {stray2}")
        # New whisper against the live session id carries the current key.
        admin.send({"t": "whisper", "ids": [mover2.id]})
        admin.receive("whisper_ok", lambda m: m.get("count") == 1)
        delivered2 = mover2.receive(
            "channel_key", lambda m: m.get("channel") == 1)
        assert delivered2["key"] == admin.latest_channel_key[1], (
            f"post-reconnect whisper key mismatch: {delivered2['key']} vs "
            f"{admin.latest_channel_key[1]}")

        for client in reversed(clients):
            client.close()
        clients.clear()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        log.close()
        print("Voice key lifecycle integration OK")
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
