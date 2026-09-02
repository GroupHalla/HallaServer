#!/usr/bin/env python3
"""End-to-end do E2EE real (protocolo v6) — criptografia de verdade.

Diferente dos outros testes de integração (que verificam o RELAY opaco do
servidor), este exerce o modelo completo com a criptografia client-side
implementada em tests/e2ee_v6.py (X25519 + HKDF-SHA256 + AES-256-GCM +
Ed25519 — os algoritmos e domínios EXATOS de src/core/E2eeCrypto.cpp do
Desktop; o `cryptography` do Python faz o papel da biblioteca do cliente):

1. Login v6: hello com dhPub/dhSig — o servidor valida o binding Ed25519
   (bad_identity sem ele). Um hello SEM dhPub é recusado: a promessa de E2EE
   não admite sessão sem chave.
2. Diretório: welcome publica idPub/dhPub/dhSig por usuário; a verificação
   local (uid == SHA-256(idPub), dhSig válida) passa para todos.
3. Eleição de mestre + envelope: o menor UID do componente gera a chave de
   grupo e embrulha (X25519 efêmera + HKDF + AES-GCM) para cada membro via
   e2e_key — cada um abre o SEU envelope e converge na MESMA chave/época.
4. Chat de grupo: membro cifra com a chave do escopo (AAD por domínio), o
   servidor entrega o texto opaco intacto e os demais decifram.
5. Chat privado par-a-par: A→B decifra; C (terceiro) não decifra.
6. Envelope para terceiro não abre (o AEAD rejeita — confidencialidade de
   destinatário vem do ECDH).
7. identity_get devolve o trio de um usuário que saiu (necessário para
   cifrar offline para quem não está online).
8. SAS: as duas pontas derivam o MESMO código de 9 dígitos.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time

import e2ee_v6 as e2
assert e2.HAVE_CRYPTO, (
    "este teste exige o módulo `cryptography` (pip install cryptography) — "
    "ele implementa o lado cliente do E2EE")


class Client:
    def __init__(self, host: str, port: int, work: Path,
                 nickname: str, admin_password: str = "") -> None:
        identity = work / "identities" / nickname
        identity.mkdir(parents=True, exist_ok=True)
        self.v6 = e2.V6Identity(identity)

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
            "t": "hello", "nick": nickname, "uid": self.v6.uid,
            "idPub": base64.b64encode(self.v6.id_pub).decode(),
            "adminPass": admin_password,
            "ver": "e2ee-v6-integration", "platform": "Linux",
        }
        hello.update(self.v6.hello_fields())
        self.send(hello)
        challenge = self.receive("identity_challenge")
        self.send({
            "t": "identity_proof",
            "sig": base64.b64encode(
                self.v6.sign_ed25519(base64.b64decode(challenge["nonce"]))).decode(),
        })
        self.welcome = self.receive("welcome")
        self.id = self.welcome["selfId"]

    # ------------------------------------------------------------- helpers
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


def verify_directory_entry(user: dict) -> tuple[bytes, bytes, bytes]:
    """Verificação LOCAL de uma entrada do diretório (idem NetSession)."""
    id_pub = base64.b64decode(user["idPub"])
    dh_pub = base64.b64decode(user["dhPub"])
    dh_sig = base64.b64decode(user["dhSig"])
    assert e2.uid_for_id_pub(id_pub) == user["uid"], "uid não bate com idPub"
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    # a pública vem em SPKI DER — o verify do contrato usa exatamente isso
    Ed25519PublicKey.from_public_bytes(id_pub[12:44] if len(id_pub) == 44 else id_pub) \
        .verify(dh_sig, e2.DH_BINDING_DOMAIN + dh_pub)
    return id_pub, dh_pub, dh_sig


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="build/halla-server")
    args = parser.parse_args()
    server = Path(args.server).resolve()
    if not server.is_file():
        raise SystemExit(f"server executable not found: {server}")

    work = Path(tempfile.mkdtemp(prefix="halla-e2ee-v6-"))
    port = free_port()
    config = work / "halla-server.ini"
    config.write_text(
        "[server]\nname=E2EE v6 Integration\n"
        f"port={port}\nmaxClients=8\nadminPassword=E2eeAdminSecret\n"
        "[query]\nport=0\n[database]\ntype=sqlite\n",
        encoding="utf-8")
    log_path = work / "server.log"
    log = log_path.open("wb")
    process = subprocess.Popen(
        [str(server), "--config", str(config)], cwd=work,
        stdout=log, stderr=subprocess.STDOUT)
    clients: list[Client] = []
    try:
        # ------------------------------------------------------------ login
        alice = Client("127.0.0.1", port, work, "Alice",
                       admin_password="E2eeAdminSecret")
        clients.append(alice)

        # Hello SEM dhPub/dhSig → bad_identity (o servidor exige o par).
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat)
        broken_key = Ed25519PrivateKey.generate()
        broken_der = broken_key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        broken_socket = context.wrap_socket(raw, server_hostname="HallaServer")
        broken_socket.settimeout(5)
        broken_stream = broken_socket.makefile("rwb", buffering=0)
        broken_stream.write(json.dumps({
            "t": "hello", "proto": 6,
            "uid": base64.b64encode(
                __import__("hashlib").sha256(broken_der).digest()).decode(),
            "idPub": base64.b64encode(broken_der).decode(),
            "nick": "SemPar", "ver": "e2ee-v6-integration", "platform": "Linux",
        }, separators=(",", ":")).encode() + b"\n")
        challenge_line = broken_stream.readline()
        assert json.loads(challenge_line).get("t") == "identity_challenge"
        broken_stream.write(json.dumps({
            "t": "identity_proof",
            "sig": base64.b64encode(
                broken_key.sign(base64.b64decode(
                    json.loads(challenge_line)["nonce"]))).decode(),
        }, separators=(",", ":")).encode() + b"\n")
        error_line = broken_stream.readline()
        error = json.loads(error_line)
        assert error.get("t") == "error" and error.get("code") == "bad_identity", error
        assert "criptografia" in error.get("msg", ""), error
        broken_stream.close()
        broken_socket.close()

        # ------------------------------------------------------- diretório
        bob = Client("127.0.0.1", port, work, "Bob")
        clients.append(bob)
        alice.receive("user_joined")

        # O welcome do alice não contém o bob (conectou depois) — o mapa
        # precisa das duas visões: a do alice + o user_joined que ele viu.
        users = {u["id"]: u for u in alice.welcome.get("users", [])}
        users.update({u["id"]: u for u in bob.welcome.get("users", [])})
        for client in (alice, bob):
            entry = users[client.id]
            id_pub, dh_pub, _ = verify_directory_entry(entry)
            assert id_pub == client.v6.id_pub and dh_pub == client.v6.dh_pub

        # ------------------------------------- mestre + envelope + grupo
        # Mestre do escopo servidor (canal 0) = menor UID entre os conectados.
        master, other = sorted([alice, bob], key=lambda c: c.v6.uid)
        group_key = bytes(32)  # determinístico aqui; na vida real CSPRNG
        epoch = int(time.time() * 1000)
        plain = e2.encode_group_key_plain(epoch, group_key, [0])
        for client in (alice, bob):
            if client is master:
                continue
            envelope = e2.envelope_wrap(client.v6.dh_pub, e2.DOMAIN_KEY_WRAP, plain)
            master.send({"t": "e2e_key", "to": client.id,
                         "enc": base64.b64encode(envelope).decode()})
            received = client.receive(
                "e2e_key", lambda m: m.get("from") == master.id)
            got = e2.envelope_unwrap(
                client.v6.dh_priv,
                e2.DOMAIN_KEY_WRAP, base64.b64decode(received["enc"]))
            got_epoch, got_key, got_channels = e2.decode_group_key_plain(got)
            assert (got_epoch, got_key, got_channels) == (epoch, group_key, [0]), \
                "envelope aberto com conteúdo diferente do embrulhado"

        # Envelope para um DH pub VÁLIDO mas ERRADO: o wrap funciona (chave
        # de verdade, só não é a do Bob) — o Bob não consegue abrir (o ECDH
        # dele deriva outra chave; o AEAD rejeita).
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        wrong_pub = X25519PrivateKey.generate().public_key().public_bytes_raw()
        wrong = e2.envelope_wrap(wrong_pub, e2.DOMAIN_KEY_WRAP, plain)
        try:
            e2.envelope_unwrap(bob.v6.dh_priv, e2.DOMAIN_KEY_WRAP, wrong)
            raise AssertionError("envelope aberto pelo destinatário errado")
        except Exception as exc:
            assert "InvalidTag" in type(exc).__name__ or "decrypt" in str(exc).lower()

        # ---------------------------------------------------- chat de grupo
        nonce = bytes(12)
        blob = nonce + e2.aead_seal(group_key, nonce, e2.chat_aad("server"),
                                    "olá do grupo".encode())
        master.send({"t": "chat", "scope": "server", "text":
                     base64.b64encode(blob).decode(), "e2ee": True})
        delivered = other.receive(
            "chat", lambda m: m.get("scope") == "server" and m.get("e2ee") is True)
        got = base64.b64decode(delivered["text"])
        text = e2.aead_open(group_key, got[:12], e2.chat_aad("server"), got[12:])
        assert text == "olá do grupo".encode(), text

        # Adulteração no caminho: o AEAD do destinatário rejeita (aqui,
        # localmente — o servidor entregaria intacto o que recebeu).
        tampered = bytearray(blob)
        tampered[13] ^= 0x01
        try:
            e2.aead_open(group_key, bytes(tampered[:12]), e2.chat_aad("server"),
                         bytes(tampered[12:]))
            raise AssertionError("ciphertext adulterado foi aceito")
        except Exception:
            pass

        # ------------------------------------------------ chat privado A→B
        priv_blob = e2.pairwise_encrypt(
            alice.v6.dh_priv, bob.v6.dh_pub,
            e2.chat_aad("private"), "secreto entre nós".encode())
        alice.send({"t": "chat", "scope": "private", "to": bob.id,
                    "text": base64.b64encode(priv_blob).decode(), "e2ee": True})
        priv = bob.receive(
            "chat", lambda m: m.get("scope") == "private"
            and m.get("from") == alice.id)
        plain_b = e2.pairwise_decrypt(
            bob.v6.dh_priv, alice.v6.dh_pub, e2.chat_aad("private"),
            base64.b64decode(priv["text"]))
        assert plain_b == "secreto entre nós".encode()

        # Terceiro (Charlie) conecta e NÃO decifra a conversa privada.
        charlie = Client("127.0.0.1", port, work, "Charlie")
        clients.append(charlie)
        try:
            e2.pairwise_decrypt(charlie.v6.dh_priv, alice.v6.dh_pub,
                                e2.chat_aad("private"), base64.b64decode(priv["text"]))
            raise AssertionError("terceiro decifrou conversa privada")
        except Exception:
            pass

        # ------------------------------------------- identity_get (offline)
        charlie.close()
        clients.remove(charlie)
        alice.receive("user_left", lambda m: m.get("id") == charlie.id)
        alice.send({"t": "identity_get", "uid": charlie.v6.uid})
        data = alice.receive("identity_data",
                             lambda m: m.get("uid") == charlie.v6.uid)
        got_id, got_dh, _ = verify_directory_entry({
            "uid": charlie.v6.uid, "idPub": data["idPub"],
            "dhPub": data["dhPub"], "dhSig": data["dhSig"]})
        assert got_id == charlie.v6.id_pub and got_dh == charlie.v6.dh_pub

        # ---------------------------------------------------------------- SAS
        code_ab = e2.sas_code(alice.v6.id_pub, bob.v6.id_pub)
        code_ba = e2.sas_code(bob.v6.id_pub, alice.v6.id_pub)
        assert code_ab == code_ba and len(code_ab.split()) == 3, code_ab

        for client in reversed(clients):
            client.close()
        clients.clear()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        log.close()
        print("E2EE v6 integration OK")
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
