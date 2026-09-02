#!/usr/bin/env python3
"""End-to-end tests for the E2EE key lifecycle (protocolo v6).

O servidor v6 NÃO conhece chaves de conteúdo. Contratos cobertos:

1. O welcome NÃO entrega channelKeys e o servidor NUNCA envia channel_key —
   quem gera/embrulha chaves de grupo são os clientes (mestre = menor UID).
   Regredir nisto devolveria o servidor ao modelo de confiança da "falsa
   promessa" de E2EE.

2. Relay opaco de e2e_key: bytes "enc" atravessam sem validação alguma (o
   servidor não consegue abrir), com "from" preenchido pelo próprio relay.

3. e2e_key_request rota SÓ para membros do componente (ou todos, no escopo
   servidor/canal 0); não-membro recebe no_permission — a chave de um canal
   não pode ser pedida por quem está fora dele.

4. Chat e2ee: texto opaco (base64) passa intacto até 1600 caracteres; acima
   disso, bad_text — o limite cobre plaintext de 1024 em base64 com folga.

(A criptografia de ponta a ponta de verdade — envelope, eleição de mestre,
chat de grupo — é o e2ee_v6_integration.py, que usa o módulo `cryptography`.)
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
        self.send({
            "t": "hello", "proto": protocol, "uid": uid,
            "idPub": base64.b64encode(der).decode(), "nick": nickname,
            "adminPass": admin_password,
            "ver": "e2ee-key-lifecycle", "platform": "Linux",
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

    def drain(self, seconds: float = 0.8) -> list[dict]:
        """Coleta tudo que chega na janela sem deixar o timeout disparar no
        meio de um readline (readline após timeout inutiliza o stream SSL)."""
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

    work = Path(tempfile.mkdtemp(prefix="halla-e2ee-keylife-"))
    port = free_port()
    config = work / "halla-server.ini"
    config.write_text(
        "[server]\nname=E2EE Key Lifecycle Integration\n"
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

        # ------------------------------------------------------------- part 1
        # O welcome NÃO traz chaves (o servidor não as conhece) e nenhum
        # channel_key chega — nem após join/leave/move/whisper.
        assert "channelKeys" not in admin.welcome, (
            "welcome entregou channelKeys: o servidor v6 não conhece chaves")
        # Diretório público no user object: o próprio admin está lá com o trio.
        users = {u["id"]: u for u in admin.welcome.get("users", [])}
        me = users.get(admin.id, {})
        assert me.get("idPub") and me.get("dhPub") and me.get("dhSig"), (
            "user object sem o trio idPub/dhPub/dhSig")
        assert base64.b64decode(me["dhPub"]) == admin.v6.dh_pub, (
            "dhPub publicado diverge do enviado no hello")

        # Non-linked channel B for cross-channel scenarios.
        admin.send({"t": "chan_create", "name": "Sala B", "type": 2, "parent": 0})
        created = admin.receive(
            "chan_update",
            lambda message: message.get("chan", {}).get("name") == "Sala B")
        channel_b = created["chan"]["id"]

        mover = Client("127.0.0.1", port, work, "Mover")
        clients.append(mover)
        admin.receive("user_joined")

        # ------------------------------------------------------------- part 2
        # Relay opaco de e2e_key: bytes preservados, "from" preenchido pelo
        # servidor. Envelope propositalmente SEM sentido criptográfico — o
        # servidor não valida (não consegue abrir).
        opaque_envelope = base64.b64encode(bytes(range(96))).decode()
        admin.send({"t": "e2e_key", "to": mover.id, "enc": opaque_envelope})
        relayed = mover.receive(
            "e2e_key", lambda m: m.get("enc") == opaque_envelope)
        assert relayed["from"] == admin.id, (
            f"relay não anotou o from: {relayed}")

        # Destinatário inexistente: not_found (o relay confere o destino).
        admin.send({"t": "e2e_key", "to": 999, "enc": opaque_envelope})
        admin.receive("error", lambda m: m.get("code") == "not_found")

        # ------------------------------------------------------------- part 3
        # e2e_key_request: rota para membros do componente. Mover entra em B,
        # pede a chave de B → quem está em B (ninguém além dele por ora — o
        # pedido simplesmente não tem respondente, mas o SERVIDOR entrega o
        # request aos membros: admin pede de FORA e leva no_permission).
        mover.send({"t": "move", "channel": channel_b})
        mover.receive("user_moved",
                      lambda m: m.get("id") == mover.id
                      and m.get("channel") == channel_b)
        admin.receive("user_moved",
                      lambda m: m.get("id") == mover.id
                      and m.get("channel") == channel_b)

        # Admin (fora de B) pedindo a chave de B: recusado.
        admin.send({"t": "e2e_key_request", "channel": channel_b})
        admin.receive("error", lambda m: m.get("code") == "no_permission")

        # Mover (dentro de B) pede: o request vai aos MEMBROS do componente
        # (apenas o próprio mover está lá, e o servidor exclui o solicitante
        # — ninguém recebe, e nada explode).
        mover.send({"t": "e2e_key_request", "channel": channel_b})
        quiet = admin.drain(0.8)
        assert not any(m.get("t") == "e2e_key_request" for m in quiet), (
            "request de membro vazou para quem está fora do componente")

        # Membro de B recebe o request de outro membro.
        third = Client("127.0.0.1", port, work, "ThirdUser")
        clients.append(third)
        admin.receive("user_joined")
        third.send({"t": "move", "channel": channel_b})
        third.receive("user_moved",
                      lambda m: m.get("id") == third.id
                      and m.get("channel") == channel_b)
        mover.receive("user_moved",
                      lambda m: m.get("id") == third.id
                      and m.get("channel") == channel_b)
        mover.send({"t": "e2e_key_request", "channel": channel_b})
        request = third.receive(
            "e2e_key_request", lambda m: m.get("channel") == channel_b)
        assert request["from"] == mover.id, request

        # Escopo servidor (canal 0): TODOS os conectados recebem o pedido.
        mover.send({"t": "e2e_key_request", "channel": 0})
        admin.receive("e2e_key_request", lambda m: m.get("from") == mover.id)
        third.receive("e2e_key_request", lambda m: m.get("from") == mover.id)

        # ------------------------------------------------------------- part 4
        # Chat e2ee: opaco, com limite folgado; acima do limite, bad_text.
        blob = base64.b64encode(bytes(64)).decode()
        admin.send({"t": "chat", "scope": "server", "text": blob, "e2ee": True})
        delivered_chat = mover.receive(
            "chat", lambda m: m.get("scope") == "server"
            and m.get("text") == blob and m.get("e2ee") is True)
        assert delivered_chat["fromName"] == "KeyAdmin", delivered_chat

        oversized = "A" * 1601
        admin.send({"t": "chat", "scope": "server", "text": oversized, "e2ee": True})
        admin.receive("error", lambda m: m.get("code") == "bad_text")

        # ------------------------------------------------------------- part 5
        # join/leave/move/whisper NÃO geram channel_key do servidor — o
        # membro que precisa da chave pede (e2e_key_request) ou recebe o
        # envelope de outro cliente.
        admin.send({"t": "whisper", "ids": [mover.id]})
        admin.receive("whisper_ok", lambda m: m.get("count") == 1)
        stray = mover.drain(0.8)
        assert not any(m.get("t") == "channel_key" for m in stray), (
            f"servidor v6 enviou channel_key: {stray}")

        third.close()
        clients.remove(third)
        admin.receive("user_left", lambda m: m.get("id") == third.id)
        stray2 = mover.drain(0.8)
        assert not any(m.get("t") == "channel_key" for m in stray2), (
            "rotação de leave ainda empurra channel_key no v6")

        for client in reversed(clients):
            client.close()
        clients.clear()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        log.close()
        print("E2EE key lifecycle integration OK")
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
