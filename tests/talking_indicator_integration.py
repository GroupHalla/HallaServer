#!/usr/bin/env python3
"""End-to-end test for personalized talking/whisper indicators.

Before the fix, `user_state { talking, whispering }` was broadcast globally:
clients saw the "talking" icon of users in channels they could NOT hear, and
whispering was flagged for everyone instead of only the whisper targets.

The contract now:
- talking=true only for clients that hear the speaker's channel voice
  (same channel or linked component) while the speaker is NOT whispering;
- whispering=true (with talking=true, rendered orange by clients) only for
  the whisper targets;
- everyone else receives false/false (including same-channel non-targets
  while the speaker whispers — the relay sends them no audio either);
- the welcome users array carries the same personalized flags;
- moving between channels while talking recalculates the indicators.
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
        self.send({
            "t": "hello", "proto": protocol, "uid": uid,
            "idPub": base64.b64encode(der).decode(), "nick": nickname,
            "adminPass": admin_password,
            "ver": "talking-indicator", "platform": "Linux",
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

    def expect_user_state(self, user_id: int, talking: bool, whispering: bool) -> None:
        """Waits for the personalized user_state of user_id with exactly the
        expected flags (whisper cues and channel_key traffic may interleave)."""
        def match(message: dict) -> bool:
            if message.get("t") != "user_state" or message.get("id") != user_id:
                return False
            return (message.get("talking") is talking
                    and message.get("whispering") is whispering)
        self.receive("user_state", match)

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

    work = Path(tempfile.mkdtemp(prefix="halla-talking-indicator-"))
    port = free_port()
    config = work / "halla-server.ini"
    config.write_text(
        "[server]\nname=Talking Indicator Integration\n"
        f"port={port}\nmaxClients=8\nadminPassword=TalkingAdminSecret\n"
        "[query]\nport=0\n[database]\ntype=sqlite\n",
        encoding="utf-8")
    log_path = work / "server.log"
    log = log_path.open("wb")
    process = subprocess.Popen(
        [str(server), "--config", str(config)], cwd=work,
        stdout=log, stderr=subprocess.STDOUT)
    clients: list[Client] = []
    try:
        admin = Client("127.0.0.1", port, work, "TalkAdmin",
                       admin_password="TalkingAdminSecret")
        clients.append(admin)

        # Non-linked channel B for cross-channel scenarios.
        admin.send({"t": "chan_create", "name": "Sala B", "type": 2, "parent": 0})
        created = admin.receive(
            "chan_update",
            lambda message: message.get("chan", {}).get("name") == "Sala B")
        channel_b = created["chan"]["id"]

        same_chan = Client("127.0.0.1", port, work, "SameChannel")
        clients.append(same_chan)
        admin.receive("user_joined")

        other = Client("127.0.0.1", port, work, "OtherChannel")
        clients.append(other)
        admin.receive("user_joined")

        other.send({"t": "move", "channel": channel_b})
        other.receive("user_moved",
                      lambda m: m.get("id") == other.id
                      and m.get("channel") == channel_b)
        admin.receive("user_moved",
                      lambda m: m.get("id") == other.id
                      and m.get("channel") == channel_b)

        # ------------------------------------------------- normal channel talk
        # admin talks in channel 1: same_chan SEES it, other (channel B) does not.
        admin.send({"t": "talking", "on": True})
        same_chan.expect_user_state(admin.id, talking=True, whispering=False)
        other.expect_user_state(admin.id, talking=False, whispering=False)

        # ------------------------------------------------- whisper to other
        # admin whispers to `other` while talking: the target sees the whisper
        # (talking+whispering -> orange); same-channel members see NOTHING
        # (relay sends them no audio while the sender whispers).
        admin.send({"t": "whisper", "ids": [other.id]})
        admin.receive("whisper_ok", lambda m: m.get("count") == 1)
        other.expect_user_state(admin.id, talking=True, whispering=True)
        same_chan.expect_user_state(admin.id, talking=False, whispering=False)

        # ------------------------------------------------- whisper released
        # back to channel voice: same_chan sees green, other goes dark.
        admin.send({"t": "whisper", "ids": []})
        admin.receive("whisper_ok", lambda m: m.get("count") == 0)
        same_chan.expect_user_state(admin.id, talking=True, whispering=False)
        other.expect_user_state(admin.id, talking=False, whispering=False)

        # ------------------------------------------------- stop talking
        admin.send({"t": "talking", "on": False})
        same_chan.expect_user_state(admin.id, talking=False, whispering=False)
        other.expect_user_state(admin.id, talking=False, whispering=False)

        # ------------------------------------------------- personalized welcome
        # admin talks in channel 1 and a NEW client connects (lands in channel
        # 1): its welcome must show admin talking=true. Then admin moves to B
        # while talking and another new client connects: welcome shows false.
        admin.send({"t": "talking", "on": True})
        same_chan.expect_user_state(admin.id, talking=True, whispering=False)

        joiner1 = Client("127.0.0.1", port, work, "JoinerOne")
        clients.append(joiner1)
        admin.receive("user_joined")
        joiner1_state = next(u for u in joiner1.welcome["users"]
                             if u["id"] == admin.id)
        assert joiner1_state["talking"] is True, joiner1_state
        assert joiner1_state["whispering"] is False, joiner1_state

        # admin (still talking) moves to channel B: everyone recalculates.
        admin.send({"t": "move", "channel": channel_b})
        admin.receive("user_moved",
                      lambda m: m.get("id") == admin.id
                      and m.get("channel") == channel_b)
        same_chan.expect_user_state(admin.id, talking=False, whispering=False)
        joiner1.expect_user_state(admin.id, talking=False, whispering=False)
        other.expect_user_state(admin.id, talking=True, whispering=False)

        joiner2 = Client("127.0.0.1", port, work, "JoinerTwo")
        clients.append(joiner2)
        admin.receive("user_joined")
        joiner2_state = next(u for u in joiner2.welcome["users"]
                             if u["id"] == admin.id)
        assert joiner2_state["talking"] is False, joiner2_state
        assert joiner2_state["whispering"] is False, joiner2_state

        # Whisper from B to joiner1 (channel 1): target sees orange again.
        admin.send({"t": "whisper", "ids": [joiner1.id]})
        admin.receive("whisper_ok", lambda m: m.get("count") == 1)
        joiner1.expect_user_state(admin.id, talking=True, whispering=True)
        other.expect_user_state(admin.id, talking=False, whispering=False)

        for client in reversed(clients):
            client.close()
        clients.clear()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        log.close()
        print("Talking indicator integration OK")
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
