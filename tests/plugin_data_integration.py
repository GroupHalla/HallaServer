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
                 nickname: str, protocol: int = 6,
                 admin_password: str = "") -> None:
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
            "ver": "plugin-data-integration", "platform": "Linux",
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
        f"port={port}\nmaxClients=6\nadminPassword=PluginAdminSecret\n"
        "allowScreenShare=true\nscreenshareWidth=1920\nscreenshareHeight=1080\n"
        "screenshareFps=60\nscreenshareBitrateKbps=8000\n"
        "[query]\nport=0\n[database]\ntype=sqlite\n",
        encoding="utf-8")
    log_path = work / "server.log"
    log = log_path.open("wb")
    process = subprocess.Popen(
        [str(server), "--config", str(config)], cwd=work,
        stdout=log, stderr=subprocess.STDOUT)
    clients: list[Client] = []
    try:
        sender = Client("127.0.0.1", port, work, "PositionAdmin",
                        admin_password="PluginAdminSecret")
        clients.append(sender)
        receiver = Client("127.0.0.1", port, work, "PositionReceiver")
        clients.append(receiver)
        sender.receive("user_joined")
        legacy = Client("127.0.0.1", port, work, "LegacyClient", protocol=4)
        clients.append(legacy)
        sender.receive("user_joined")
        receiver.receive("user_joined")
        outsider = Client("127.0.0.1", port, work, "OtherChannel")
        clients.append(outsider)
        sender.receive("user_joined")

        limits = sender.welcome["server"]
        assert limits["screenshare_w"] == 1920
        assert limits["screenshare_h"] == 1080
        assert limits["screenshare_fps"] == 60
        assert limits["screenshare_bitrate"] == 8000
        sender.send({"t": "webrtc_stream_start", "width": 3840, "height": 2160,
                     "fps": 60, "bitrate": 32000})
        quality_error = sender.receive("error")
        assert quality_error["code"] == "screenshare_quality", quality_error
        sender.send({"t": "webrtc_stream_start", "width": 1920, "height": 1080,
                     "fps": 60, "bitrate": 8000})
        receiver.receive("user_screenshare_state",
            lambda message: message.get("id") == sender.id and message.get("on") is True)
        sender.send({"t": "webrtc_stream_stop"})

        # Normal mantém o caso legítimo no canal atual.
        receiver.send(plugin_message(0, "position.v1", b"xyz-position"))
        channel = sender.receive("plugin_data")
        assert channel["from"] == receiver.id
        assert channel["plugin"] == "community.positional"
        assert channel["topic"] == "position.v1"
        assert base64.b64decode(channel["data"]) == b"xyz-position"

        receiver.send(plugin_message(1, "radio.v1", b"police", [sender.id]))
        direct = sender.receive("plugin_data")
        assert direct["from"] == receiver.id
        assert base64.b64decode(direct["data"]) == b"police"

        # Broadcast global é negado ao cargo Normal.
        receiver.send(plugin_message(2, "server.v1", b"forbidden"))
        denied = receiver.receive("error")
        assert denied["code"] == "no_permission", denied

        # Cria outro canal e move um cliente para comprovar isolamento target=1.
        sender.send({"t": "chan_create", "name": "Plugin Isolated",
                     "type": 2, "parent": 0})
        created = sender.receive(
            "chan_update",
            lambda message: message.get("chan", {}).get("name") == "Plugin Isolated")
        isolated_channel = created["chan"]["id"]
        outsider.send({"t": "move", "channel": isolated_channel})
        outsider.receive(
            "user_moved",
            lambda message: message.get("id") == outsider.id
                            and message.get("channel") == isolated_channel)

        receiver.send(plugin_message(1, "cross-channel", b"blocked", [outsider.id]))
        scope_error = receiver.receive("error")
        assert scope_error["code"] == "plugin_data_scope", scope_error

        # Administrador explicitamente autorizado ainda pode usar target=2.
        sender.send(plugin_message(2, "server.v1", b"broadcast"))
        broadcast = receiver.receive("plugin_data")
        assert broadcast["topic"] == "server.v1"
        cross_channel_broadcast = outsider.receive("plugin_data")
        assert cross_channel_broadcast["topic"] == "server.v1"

        # O criador de canal temporário recebe somente os poderes locais
        # delegados: senha, bitrate, máximo de clientes e kick de canal.
        receiver.send({"t": "chan_create", "name": "Owned Temporary",
                       "type": 0, "parent": 0, "bitrate": 96, "max": 2})
        temp_created = receiver.receive(
            "chan_update",
            lambda message: message.get("chan", {}).get("name") == "Owned Temporary")
        temp_channel = temp_created["chan"]["id"]
        assert temp_created["chan"]["tempOwner"] == receiver.uid
        outsider.send({"t": "move", "channel": temp_channel})
        outsider.receive("user_moved",
            lambda message: message.get("id") == outsider.id
                            and message.get("channel") == temp_channel)

        receiver.send({"t": "chan_edit", "id": temp_channel,
                       "pass": "temporary-secret", "bitrate": 128, "max": 3})
        temp_updated = receiver.receive(
            "chan_update",
            lambda message: message.get("chan", {}).get("id") == temp_channel
                            and message.get("chan", {}).get("bitrate") == 128)
        assert temp_updated["chan"]["pw"] is True
        assert temp_updated["chan"]["max"] == 3

        receiver.send({"t": "chan_edit", "id": temp_channel,
                       "name": "Forbidden rename"})
        limited = receiver.receive("error")
        assert limited["code"] == "temporary_owner_limit", limited

        receiver.send({"t": "kick", "id": outsider.id,
                       "from": "channel", "reason": "owner test"})
        kicked = outsider.receive("kicked")
        assert kicked["ban"] is False
        receiver.receive("user_moved",
            lambda message: message.get("id") == outsider.id
                            and message.get("channel") == 1)

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

        # Regressão: o banco persistia "Servidor Halla"/nome anterior e
        # sobrescrevia uma edição posterior em [server]. O INI modificado deve
        # vencer no próximo start, sem perder a persistência administrativa.
        configured_name = "Halla Comunidade Brasileira - Servidor Principal 2026"
        config.write_text(
            config.read_text(encoding="utf-8").replace(
                "name=Plugin Data Integration", f"name={configured_name}"),
            encoding="utf-8")
        log = log_path.open("ab")
        process = subprocess.Popen(
            [str(server), "--config", str(config)], cwd=work,
            stdout=log, stderr=subprocess.STDOUT)
        verifier = Client("127.0.0.1", port, work, "ConfigVerifier")
        clients.append(verifier)
        assert verifier.welcome["server"]["name"] == configured_name, verifier.welcome
        verifier.close()
        clients.remove(verifier)
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        log.close()
        print("Plugin-data v5 and server-name config integration OK")
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
