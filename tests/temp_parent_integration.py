#!/usr/bin/env python3
"""End-to-end regression test for the temporary-channel parent policy."""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import time


class ProtocolClient:
    def __init__(self, host: str, port: int, identity_dir: Path,
                 nickname: str, admin_password: str = "") -> None:
        identity_dir.mkdir(parents=True, exist_ok=True)
        self.private_key = identity_dir / "identity.pem"
        self.public_key = identity_dir / "identity.der"
        if not self.private_key.exists() or not self.public_key.exists():
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.private_key)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(
                ["openssl", "pkey", "-in", str(self.private_key), "-pubout",
                 "-outform", "DER", "-out", str(self.public_key)],
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
        hello = {
            "t": "hello",
            "proto": 4,
            "idPub": base64.b64encode(self.public_key.read_bytes()).decode(),
            "nick": nickname,
            "ver": "temporary-parent-integration",
            "platform": "Linux",
        }
        if admin_password:
            hello["adminPass"] = admin_password
        self.send(hello)
        challenge = self.receive("identity_challenge")
        nonce = identity_dir / "nonce.bin"
        signature = identity_dir / "signature.bin"
        nonce.write_bytes(base64.b64decode(challenge["nonce"]))
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(self.private_key),
             "-rawin", "-in", str(nonce), "-out", str(signature)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.send({
            "t": "identity_proof",
            "sig": base64.b64encode(signature.read_bytes()).decode(),
        })
        self.welcome = self.receive("welcome")

    def close(self) -> None:
        try:
            self.stream.close()
        finally:
            self.socket.close()

    def send(self, obj: dict) -> None:
        payload = json.dumps(obj, separators=(",", ":")).encode() + b"\n"
        self.stream.write(payload)

    def next_object(self) -> dict:
        line = self.stream.readline()
        if not line:
            raise AssertionError("server closed the protocol connection")
        return json.loads(line)

    def receive(self, message_type: str, predicate=lambda _obj: True) -> dict:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            obj = self.next_object()
            if obj.get("t") == message_type and predicate(obj):
                return obj
        raise AssertionError(f"timed out waiting for {message_type}")

    def receive_channel(self, name: str) -> dict:
        update = self.receive(
            "chan_update", lambda obj: obj.get("chan", {}).get("name") == name)
        return update["chan"]


def free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="build/halla-server")
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()

    server = Path(args.server).resolve()
    if not server.is_file():
        raise SystemExit(f"server executable not found: {server}")

    temporary = tempfile.mkdtemp(prefix="halla-temp-parent-")
    work = Path(temporary)
    log_path = work / "server.log"
    port = free_port()
    admin_password = "temporary-parent-integration-admin"
    privilege_key = "HL3-TEMP-PARENT-TEST"
    (work / "halla-server.ini").write_text(
        "[server]\n"
        "name=Temporary Parent Integration\n"
        f"port={port}\n"
        f"adminPassword={admin_password}\n"
        f"privilegeKeys={privilege_key}\n"
        "[query]\nport=0\n"
        "[database]\ntype=sqlite\n",
        encoding="utf-8")

    # Simula uma instalação anterior à coluna temp_channel_parent. O startup
    # precisa migrar a tabela sem perder o canal padrão existente.
    database_path = work / "halla-data.db"
    database = sqlite3.connect(database_path)
    database.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)")
    database.execute("INSERT INTO settings VALUES ('name','Legacy server')")
    database.execute(
        "CREATE TABLE channels ("
        "id INTEGER PRIMARY KEY, parentId INT, name TEXT, topic TEXT, desc TEXT, "
        "password TEXT, isDefault INT, type INT, moderated INT, codec INT, "
        "codecQuality INT, maxClients INT, ntalk INT, bitrate INT, "
        "group_perms TEXT, no_symbol INT, order_index INT, "
        "linked_channels TEXT, group_position_reqs TEXT)")
    database.execute(
        "INSERT INTO channels VALUES "
        "(1,0,'Legacy default','','','',1,2,0,4,6,-1,0,96,'{}',0,0,'[]','{}')")
    database.commit()
    database.close()

    log = log_path.open("wb")
    process = subprocess.Popen(
        [str(server), "--config", str(work / "halla-server.ini")],
        stdout=log, stderr=subprocess.STDOUT)
    admin: ProtocolClient | None = None
    normal: ProtocolClient | None = None
    try:
        admin = ProtocolClient(
            "127.0.0.1", port, work / "admin-identity", "RoutingAdmin", admin_password)
        assert admin.welcome["myPerms"].get("*") is True
        assert any(channel.get("name") == "Legacy default"
                   for channel in admin.welcome.get("channels", []))

        base = {"parent": 0, "codec": 4, "quality": 6, "max": -1}
        admin.send({
            "t": "chan_create", "name": "Temporary destination A",
            "type": 2, "tempParent": True, **base,
        })
        destination_a = admin.receive_channel("Temporary destination A")
        assert destination_a["tempParent"] is True

        # Mesmo o administrador não consegue escolher outro pai para um canal
        # temporário quando um destino global está configurado.
        admin.send({
            "t": "chan_create", "name": "Forced temporary A",
            "type": 0, **base,
        })
        temporary_a = admin.receive_channel("Forced temporary A")
        assert temporary_a["parent"] == destination_a["id"]

        # Ao definir B, A deve ser limpo e B deve se tornar o único destino.
        admin.send({
            "t": "chan_create", "name": "Temporary destination B",
            "type": 2, "tempParent": True,
            "groupPerms": {
                "2": {"channel_create": 1, "chan_create_temp": 1},
            },
            **base,
        })
        cleared_a = False
        destination_b = None
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and (not cleared_a or destination_b is None):
            channel = admin.receive("chan_update")["chan"]
            if channel.get("id") == destination_a["id"]:
                cleared_a = channel.get("tempParent") is False
            if channel.get("name") == "Temporary destination B":
                destination_b = channel
        assert cleared_a and destination_b and destination_b["tempParent"] is True

        normal = ProtocolClient(
            "127.0.0.1", port, work / "normal-identity", "RoutingUser")
        assert normal.welcome["myPerms"].get("*") is not True

        # Um usuário sem chanEdit não pode remover a configuração global.
        normal.send({
            "t": "chan_edit", "id": destination_b["id"], "tempParent": False,
        })
        denied = normal.receive("error")
        assert denied.get("code") == "no_permission", denied

        # A privilege key precisa atualizar as permissões imediatamente e o
        # privilégio individual persistido deve reaparecer no próximo welcome.
        normal.send({"t": "privkey", "key": privilege_key})
        granted = normal.receive("privilege_granted")
        assert granted.get("individual") is True
        assert granted.get("myPerms", {}).get("*") is True, granted
        normal.close()
        normal = ProtocolClient(
            "127.0.0.1", port, work / "normal-identity", "RoutingUser")
        assert normal.welcome.get("myPerms", {}).get("*") is True
        normal.send({
            "t": "chan_edit", "id": destination_b["id"], "tempParent": False,
        })
        disabled = normal.receive(
            "chan_update", lambda obj: obj.get("chan", {}).get("id") == destination_b["id"])
        assert disabled["chan"].get("tempParent") is False
        normal.send({
            "t": "chan_edit", "id": destination_b["id"], "tempParent": True,
        })
        enabled = normal.receive(
            "chan_update", lambda obj: obj.get("chan", {}).get("id") == destination_b["id"])
        assert enabled["chan"].get("tempParent") is True

        # O cliente tenta forçar A como pai. O servidor deve ignorar o parent
        # enviado e colocar o novo temporário em B.
        normal.send({
            "t": "chan_create", "name": "Forced temporary B",
            "parent": destination_a["id"], "type": 0,
            "codec": 4, "quality": 6, "max": -1,
        })
        temporary_b = normal.receive_channel("Forced temporary B")
        assert temporary_b["parent"] == destination_b["id"]
        assert temporary_b["parent"] != destination_a["id"]

        normal.close()
        normal = None
        admin.close()
        admin = None
        process.send_signal(signal.SIGTERM)
        return_code = process.wait(timeout=10)
        assert return_code == 0, f"server exited with {return_code}"
        log.close()

        database = sqlite3.connect(database_path)
        columns = {row[1] for row in database.execute("PRAGMA table_info(channels)")}
        assert "temp_channel_parent" in columns
        configured = database.execute(
            "SELECT name,temp_channel_parent FROM channels "
            "WHERE temp_channel_parent=1").fetchall()
        assert configured == [("Temporary destination B", 1)], configured
        temporary_count = database.execute(
            "SELECT COUNT(*) FROM channels WHERE name LIKE 'Forced temporary %'").fetchone()[0]
        assert temporary_count == 0
        database.close()
        print("Temporary-channel parent integration OK")
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
        if normal is not None:
            normal.close()
        if admin is not None:
            admin.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        if not log.closed:
            log.close()
        if args.keep_workdir:
            print(f"Integration workdir kept at {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
