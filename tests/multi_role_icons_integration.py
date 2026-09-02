#!/usr/bin/env python3
"""End-to-end test for multiple role icons next to the nickname.

Before the fix, ServerCore::applyGroup kept only the FIRST non-empty group
icon (`firstIcon`) of a user's assigned groups: a member of two roles that
both had icons (e.g. "4.png" for GPV and "rota.png" for ROTA) received
`icon = "4.png"` and the Desktop client — which already splits the field on
[,;] and renders one icon per role — could only ever show a single role icon.

The contract now:
- the `icon` field of user_group broadcasts and of the welcome users array
  lists EVERY assigned group icon, comma-separated, in hierarchy order
  (highest position first — the same order the old single icon used);
- groups without icons contribute nothing (no empty entries);
- two roles sharing the same icon show it once (no duplicates);
- a role icon containing "," or ";" cannot break the list: group_set strips
  the separators from the stored value;
- removing a role re-broadcasts the reduced icon list.

Icon names for uploaded images never contain separators anyway
(sanitizeFileName only allows letters, digits, ".", "_", "-" and space) —
this test also locks the defensive strip for emoji/text icons.
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
            "ver": "multi-role-icons", "platform": "Linux",
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

    def expect_user_group_icon(self, user_id: int, icon: str) -> None:
        """Waits for the user_group of user_id carrying exactly `icon`
        (group_list/other broadcasts may interleave)."""
        def match(message: dict) -> bool:
            return (message.get("t") == "user_group"
                    and message.get("id") == user_id
                    and message.get("icon") == icon)
        self.receive("user_group", match)

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

    work = Path(tempfile.mkdtemp(prefix="halla-multi-role-icons-"))
    port = free_port()
    config = work / "halla-server.ini"
    config.write_text(
        "[server]\nname=Multi Role Icons Integration\n"
        f"port={port}\nmaxClients=8\nadminPassword=IconsAdminSecret\n"
        "[query]\nport=0\n[database]\ntype=sqlite\n",
        encoding="utf-8")
    log_path = work / "server.log"
    log = log_path.open("wb")
    process = subprocess.Popen(
        [str(server), "--config", str(config)], cwd=work,
        stdout=log, stderr=subprocess.STDOUT)
    clients: list[Client] = []
    try:
        admin = Client("127.0.0.1", port, work, "IconAdmin",
                       admin_password="IconsAdminSecret")
        clients.append(admin)

        # Two roles with icons at different hierarchy positions, plus one
        # role without an icon (must contribute nothing to the field).
        admin.send({"t": "group_set", "name": "Asa", "icon": "4.png",
                    "position": 500, "order": 5})
        asa = admin.receive(
            "group_set_ok", lambda m: m.get("group", {}).get("name") == "Asa")["group"]
        admin.send({"t": "group_set", "name": "Rota", "icon": "rota.png",
                    "position": 300, "order": 6})
        rota = admin.receive(
            "group_set_ok", lambda m: m.get("group", {}).get("name") == "Rota")["group"]
        admin.send({"t": "group_set", "name": "SemIcone",
                    "position": 200, "order": 7})
        sem_icone = admin.receive(
            "group_set_ok", lambda m: m.get("group", {}).get("name") == "SemIcone")["group"]

        member = Client("127.0.0.1", port, work, "Farley")
        clients.append(member)
        admin.receive("user_joined")

        # ------------------------------------------- one role: single icon
        admin.send({"t": "client_set_group", "id": member.id,
                    "gid": asa["id"], "op": "add"})
        admin.expect_user_group_icon(member.id, "4.png")

        # ----------------------------- two roles with icons: BOTH in the field
        # Hierarchy order: Asa (position 500) before Rota (position 300) — the
        # same order the old single-icon logic used to pick `firstIcon`.
        admin.send({"t": "client_set_group", "id": member.id,
                    "gid": rota["id"], "op": "add"})
        admin.expect_user_group_icon(member.id, "4.png,rota.png")

        # -------------------- role without icon between them: no empty entries
        admin.send({"t": "client_set_group", "id": member.id,
                    "gid": sem_icone["id"], "op": "add"})
        admin.expect_user_group_icon(member.id, "4.png,rota.png")

        # ----------------------------------------- welcome carries the list
        joiner = Client("127.0.0.1", port, work, "Joiner")
        clients.append(joiner)
        admin.receive("user_joined")
        member_state = next(u for u in joiner.welcome["users"]
                            if u["id"] == member.id)
        assert member_state["icon"] == "4.png,rota.png", member_state

        # ------------------------------------------- duplicates collapse
        admin.send({"t": "group_set", "name": "RotaDois", "icon": "rota.png",
                    "position": 250, "order": 8})
        rota_dois = admin.receive(
            "group_set_ok", lambda m: m.get("group", {}).get("name") == "RotaDois")["group"]
        admin.send({"t": "client_set_group", "id": member.id,
                    "gid": rota_dois["id"], "op": "add"})
        admin.expect_user_group_icon(member.id, "4.png,rota.png")

        # --------------------- separators cannot sneak in via group_set icon
        admin.send({"t": "group_set", "name": "Separador",
                    "icon": "a,b;c.png", "position": 150, "order": 9})
        separador = admin.receive(
            "group_set_ok", lambda m: m.get("group", {}).get("name") == "Separador")["group"]
        assert separador["icon"] == "abc.png", separador
        admin.send({"t": "client_set_group", "id": member.id,
                    "gid": separador["id"], "op": "add"})
        admin.expect_user_group_icon(member.id, "4.png,rota.png,abc.png")

        # ---------------------------------- removing a role shrinks the list
        admin.send({"t": "client_set_group", "id": member.id,
                    "gid": asa["id"], "op": "remove"})
        admin.expect_user_group_icon(member.id, "rota.png,abc.png")

        for client in reversed(clients):
            client.close()
        clients.clear()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        log.close()
        print("Multi role icons integration OK")
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
    else:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
