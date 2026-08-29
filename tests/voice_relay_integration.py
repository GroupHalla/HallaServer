#!/usr/bin/env python3
"""End-to-end tests for the UDP voice relay routing and its caches.

The relay runs on the hot path of every voice packet (≈50/s per speaker).
This release added two caches that must never change WHO hears WHAT:

- user -> channel cache (channelOfUser used to be a linear scan of every
  channel per packet, per sender AND per recipient);
- linked-component cache (voiceComponentOf used to re-run a BFS over the
  channel graph per packet; now invalidated by a topology revision counter
  bumped on chan create/delete/link/unlink).

The contracts exercised here, with real UDP voice packets:

1. same-channel delivery: a listener in the speaker's channel receives the
   frames (HALL | fromId | seq | payload relayed verbatim — the server never
   decodes audio);
2. channel isolation: a client in another channel receives NOTHING;
3. link: after chan_link the outsider starts receiving (component cache
   invalidated and recomputed with the new topology);
4. unlink: after chan_link link=false the outsider stops receiving while the
   same-channel listener keeps receiving;
5. move: a listener that moves away stops receiving (user->channel cache
   follows the move);
6. chan_delete: users dumped back into the default channel by the direct
   m_channels[1].users append must receive again — this path bypasses
   addToChannel, so the cache fallback scan must still find their channel.
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
import struct
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
            "ver": "voice-relay-it", "platform": "Linux",
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

        # UDP endpoint: bind once, learn the voice port/token from the welcome.
        voice = self.welcome.get("voice", {})
        self.udp_port = int(voice.get("udp", 0))
        self.voice_token = bytes.fromhex(voice.get("token", ""))
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.udp.settimeout(0.35)
        self.seq = 0

    # ---- TCP helpers -------------------------------------------------------
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

    # ---- UDP voice helpers -------------------------------------------------
    def register_endpoint(self) -> None:
        """One packet so the relay learns this client's UDP endpoint."""
        self.send_voice(b"\x00")

    def send_voice(self, payload: bytes) -> None:
        if not payload:
            raise ValueError("empty payload is dropped by the relay")
        self.seq = (self.seq + 1) & 0xFFFF
        packet = b"HAL4" + self.voice_token + struct.pack("<H", self.seq) + payload
        self.udp.sendto(packet, ("127.0.0.1", self.udp_port))

    def drain_udp(self) -> None:
        while True:
            try:
                self.udp.recv(65536)
            except socket.timeout:
                return

    def collect_voice(self, from_id: int, timeout: float = 0.5) -> list[bytes]:
        """Relayed frames (payload bytes) sent by from_id within timeout."""
        deadline = time.monotonic() + timeout
        frames: list[bytes] = []
        self.udp.settimeout(max(0.05, timeout / 6))
        while time.monotonic() < deadline:
            try:
                data, _addr = self.udp.recvfrom(65536)
            except socket.timeout:
                continue
            if len(data) < 10 or data[:4] != b"HALL":
                continue
            sender = struct.unpack("<I", data[4:8])[0]
            if sender == from_id:
                frames.append(data[10:])
        return frames

    def close(self) -> None:
        try:
            self.stream.close()
        finally:
            self.socket.close()
        self.udp.close()


def free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def expect(label: str, condition: bool) -> None:
    status = "OK " if condition else "FAIL"
    print(f"  [{status}] {label}")
    if not condition:
        raise AssertionError(label)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="build/halla-server")
    args = parser.parse_args()
    server = Path(args.server).resolve()
    if not server.is_file():
        raise SystemExit(f"server executable not found: {server}")

    work = Path(tempfile.mkdtemp(prefix="halla-relay-it-"))
    port = free_port()
    config = work / "halla-server.ini"
    config.write_text(
        "[server]\nname=Voice Relay Integration\n"
        f"port={port}\nmaxClients=8\nadminPassword=RelayAdminSecret\n"
        "[query]\nport=0\n[database]\ntype=sqlite\n",
        encoding="utf-8")
    log_path = work / "server.log"
    log = log_path.open("wb")
    process = subprocess.Popen(
        [str(server), "--config", str(config)], cwd=work,
        stdout=log, stderr=subprocess.STDOUT)
    clients: list[Client] = []
    try:
        admin = Client("127.0.0.1", port, work, "RelayAdmin",
                       admin_password="RelayAdminSecret")
        clients.append(admin)
        alfa = Client("127.0.0.1", port, work, "Alfa")
        bravo = Client("127.0.0.1", port, work, "Bravo")
        charlie = Client("127.0.0.1", port, work, "Charlie")
        clients += [alfa, bravo, charlie]

        # Everybody's UDP endpoint must be known by the relay before any
        # assertion, otherwise "not received" could mean "not registered".
        for client in clients:
            client.register_endpoint()
        time.sleep(0.15)

        # A second channel, NOT linked to the default one.
        admin.send({"t": "chan_create", "name": "Sala B", "type": 2, "parent": 0})
        created = admin.receive(
            "chan_update", lambda m: m.get("chan", {}).get("name") == "Sala B")
        channel_b = created["chan"]["id"]

        charlie.send({"t": "move", "channel": channel_b})
        charlie.receive("user_moved",
                        lambda m: m.get("id") == charlie.id
                        and m.get("channel") == channel_b)
        for watcher in (admin, alfa, bravo):
            watcher.receive("user_moved",
                            lambda m: m.get("id") == charlie.id
                            and m.get("channel") == channel_b)
        time.sleep(0.2)
        for client in clients:
            client.drain_udp()

        print("phase 1 — same channel receives, other channel isolated")
        marker1 = b"RELAY-ONE-"
        for i in range(6):
            alfa.send_voice(marker1 + str(i).encode())
        got_bravo = bravo.collect_voice(alfa.id)
        got_charlie = charlie.collect_voice(alfa.id)
        expect("Bravo (same channel) received Alfa's frames", len(got_bravo) >= 3)
        expect("frames relayed verbatim",
               all(frame.startswith(marker1) for frame in got_bravo))
        expect("Charlie (other channel) received nothing", not got_charlie)

        print("phase 2 — link: component cache must pick the new topology")
        admin.send({"t": "chan_link", "ids": [1, channel_b], "link": True})
        admin.receive("chan_update",
                      lambda m: m.get("chan", {}).get("id") == 1
                      and channel_b in m.get("chan", {}).get("linked", []))
        time.sleep(0.2)
        for client in clients:
            client.drain_udp()
        marker2 = b"RELAY-TWO-"
        for i in range(6):
            alfa.send_voice(marker2 + str(i).encode())
        got_bravo = bravo.collect_voice(alfa.id)
        got_charlie = charlie.collect_voice(alfa.id)
        expect("Bravo still receives after link", len(got_bravo) >= 3)
        expect("Charlie receives through the link", len(got_charlie) >= 3)

        print("phase 3 — unlink: cache invalidated again")
        admin.send({"t": "chan_link", "ids": [1, channel_b], "link": False})
        admin.receive("chan_update",
                      lambda m: m.get("chan", {}).get("id") == 1
                      and channel_b not in m.get("chan", {}).get("linked", []))
        time.sleep(0.2)
        for client in clients:
            client.drain_udp()
        marker3 = b"RELAY-THREE-"
        for i in range(6):
            alfa.send_voice(marker3 + str(i).encode())
        got_bravo = bravo.collect_voice(alfa.id)
        got_charlie = charlie.collect_voice(alfa.id)
        expect("Bravo still receives after unlink", len(got_bravo) >= 3)
        expect("Charlie isolated again after unlink", not got_charlie)

        print("phase 4 — move: user->channel cache follows the mover")
        bravo.send({"t": "move", "channel": channel_b})
        bravo.receive("user_moved",
                      lambda m: m.get("id") == bravo.id
                      and m.get("channel") == channel_b)
        for watcher in (admin, alfa, charlie):
            watcher.receive("user_moved",
                            lambda m: m.get("id") == bravo.id
                            and m.get("channel") == channel_b)
        time.sleep(0.2)
        for client in clients:
            client.drain_udp()
        marker4 = b"RELAY-FOUR-"
        for i in range(6):
            alfa.send_voice(marker4 + str(i).encode())
        got_bravo = bravo.collect_voice(alfa.id)
        got_charlie = charlie.collect_voice(alfa.id)
        expect("Bravo (moved away) no longer receives", not got_bravo)
        expect("Charlie (now same channel) receives", len(got_charlie) >= 3)

        print("phase 5 — chan_delete dumps users into channel 1 via direct append")
        admin.send({"t": "chan_delete", "id": channel_b})
        for mover in (bravo, charlie):
            mover.receive("user_moved",
                          lambda m, who=mover.id: m.get("id") == who
                          and m.get("channel") == 1)
        time.sleep(0.2)
        for client in clients:
            client.drain_udp()
        marker5 = b"RELAY-FIVE-"
        for i in range(6):
            alfa.send_voice(marker5 + str(i).encode())
        got_bravo = bravo.collect_voice(alfa.id)
        got_charlie = charlie.collect_voice(alfa.id)
        expect("Bravo receives again after channel deletion", len(got_bravo) >= 3)
        expect("Charlie receives again after channel deletion", len(got_charlie) >= 3)

        print("voice relay integration: ALL CHECKS PASSED")
    finally:
        for client in clients:
            client.close()
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        log.close()
        if process.returncode in (0, None, -signal.SIGTERM):
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"server log kept at {log_path}")


if __name__ == "__main__":
    main()
