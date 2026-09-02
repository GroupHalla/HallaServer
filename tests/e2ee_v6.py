"""e2ee_v6.py — utilidades de cliente v6 para os testes de integração.

Protocolo v6: o servidor não conhece chaves de conteúdo. O login exige, além
do par Ed25519 da identidade, um par X25519 por sessão de teste com o binding
assinado: dhSig = Ed25519(idPriv, "HALLA-DH-V1" || dhPub). O handshake usa a
MESMA sequência do cliente Desktop (openssl CLI para gerar/assinar — nenhuma
dependência nova no ambiente de teste).

Para os testes que exercitam a criptografia de ponta a ponta de verdade
(envelope e2e_key, chat de grupo), o módulo `cryptography` (se importável)
fornece o lado cliente completo: X25519 ECDH, HKDF-SHA256, AES-256-GCM e
Ed25519 — os algoritmos e domínios EXATOS de src/core/E2eeCrypto.cpp do
Desktop. Sem `cryptography`, apenas o handshake funciona (suficiente para os
testes de relay opaco).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import subprocess
from pathlib import Path

import os

PROTO_V6 = 6

# Domínios — devem casar byte a byte com src/core/E2eeCrypto.cpp (Desktop) e
# com o servidor (src/ServerCore.cpp, kDhBindingDomain).
DH_BINDING_DOMAIN = b"HALLA-DH-V1"
DOMAIN_KEY_WRAP = b"HALLA-E2EKEY-V1"
DOMAIN_CHAT = b"HALLA-CHAT-V1"
DOMAIN_POKE = b"HALLA-POKE-V1"
DOMAIN_OFFLINE = b"HALLA-OFFLINE-V1"
SAS_PREFIX = b"HALLA-SAS-V1"

# Header SPKI de X25519 (RFC 8410): os 32 bytes crus da pública vêm depois.
X25519_SPKI_PREFIX = bytes.fromhex("302a300506032b656e032100")


def openssl(*args: str) -> bytes:
    result = subprocess.run(["openssl", *args], check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return result.stdout


class V6Identity:
    """Identidade de teste completa: Ed25519 (id) + X25519 (E2EE) + binding."""

    def __init__(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        self.dir = directory
        self.ed_private = directory / "identity.pem"
        self.dh_private = directory / "dh.pem"
        if not self.ed_private.exists():
            openssl("genpkey", "-algorithm", "ED25519", "-out", str(self.ed_private))
        if not self.dh_private.exists():
            openssl("genpkey", "-algorithm", "X25519", "-out", str(self.dh_private))

        # idPub em SPKI DER (mesma serialização do cliente) e uid derivado.
        self.id_pub: bytes = openssl(
            "pkey", "-in", str(self.ed_private), "-pubout", "-outform", "DER")
        self.uid: str = base64.b64encode(hashlib.sha256(self.id_pub).digest()).decode()

        # dhPub: SPKI DER (44 bytes) → 32 bytes crus.
        dh_spki: bytes = openssl(
            "pkey", "-in", str(self.dh_private), "-pubout", "-outform", "DER")
        assert dh_spki[:12] == X25519_SPKI_PREFIX and len(dh_spki) == 44, dh_spki
        self.dh_pub: bytes = dh_spki[12:]

        # dhPriv: PKCS#8 DER (48 bytes = header 16 + chave 32) → 32 bytes crus
        # — o mesmo formato que o cofre do cliente guarda.
        dh_pkcs8: bytes = openssl(
            "pkey", "-in", str(self.dh_private), "-outform", "DER")
        assert len(dh_pkcs8) == 48, dh_pkcs8
        self.dh_priv: bytes = dh_pkcs8[16:]

        # dhSig = Ed25519(idPriv, "HALLA-DH-V1" || dhPub) — recalculável.
        self.dh_sig: bytes = self.sign_ed25519(DH_BINDING_DOMAIN + self.dh_pub)

    def sign_ed25519(self, data: bytes) -> bytes:
        """Assina `data` com a Ed25519 da identidade (nonce de login, binding)."""
        payload = self.dir / "_sign_input.bin"
        payload.write_bytes(data)
        try:
            return openssl("pkeyutl", "-sign", "-rawin",
                           "-inkey", str(self.ed_private), "-in", str(payload))
        finally:
            payload.unlink(missing_ok=True)

    # ---------------- hello/proof do protocolo v6 ----------------
    def hello_fields(self) -> dict:
        return {
            "proto": PROTO_V6,
            "dhPub": base64.b64encode(self.dh_pub).decode(),
            "dhSig": base64.b64encode(self.dh_sig).decode(),
        }


try:  # parte opcional: cripto de verdade (envelopes/chat) com `cryptography`
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTO = True
except ImportError:  # testes de relay opaco seguem sem
    HAVE_CRYPTO = False


def raw_x25519_public(spki_der: bytes) -> bytes:
    assert spki_der[:12] == X25519_SPKI_PREFIX and len(spki_der) == 44
    return spki_der[12:]


def x25519_shared(my_priv_raw: bytes, their_pub_raw: bytes) -> bytes:
    """ECDH X25519 sobre chaves crus (32 bytes cada)."""
    key = X25519PrivateKey.from_private_bytes(my_priv_raw)
    peer = X25519PublicKey.from_public_bytes(their_pub_raw)
    return key.exchange(peer)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF (RFC 5869) — idêntico ao E2ee::hkdfSha256 do Desktop."""
    if not salt:
        salt = bytes(32)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def aead_seal(key: bytes, nonce: bytes, aad: bytes, plain: bytes) -> bytes:
    """AES-256-GCM → ciphertext||tag (layout do Desktop)."""
    return AESGCM(key).encrypt(nonce, plain, aad if aad else None)


def aead_open(key: bytes, nonce: bytes, aad: bytes, ct_tag: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ct_tag, aad if aad else None)


def encode_group_key_plain(epoch_ms: int, key: bytes, channels: list[int]) -> bytes:
    """Plaintext do envelope: época(8 BE)|chave(32)|n(4 BE)|canais(4 BE)."""
    out = epoch_ms.to_bytes(8, "big") + key
    out += len(channels).to_bytes(4, "big")
    for channel in channels:
        out += channel.to_bytes(4, "big")
    return out


def decode_group_key_plain(plain: bytes) -> tuple[int, bytes, list[int]]:
    if len(plain) < 8 + 32 + 4:
        raise ValueError("envelope curto demais")
    epoch = int.from_bytes(plain[:8], "big")
    key = plain[8:40]
    count = int.from_bytes(plain[40:44], "big")
    if len(plain) != 44 + count * 4:
        raise ValueError("tamanho inconsistente")
    channels = [int.from_bytes(plain[44 + i * 4:48 + i * 4], "big")
                for i in range(count)]
    return epoch, key, channels


def envelope_wrap(recipient_dh_pub: bytes, aad: bytes, plain: bytes) -> bytes:
    """X25519 efêmera → destinatário: ephPub(32)|nonce(12)|ct|tag."""
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes_raw()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_dh_pub))
    wrap_key = hkdf_sha256(shared, aad, aad, 32)
    nonce = os.urandom(12)
    return eph_pub + nonce + AESGCM(wrap_key).encrypt(nonce, plain, aad)


def envelope_unwrap(my_dh_priv: bytes, aad: bytes, envelope: bytes) -> bytes:
    if len(envelope) < 32 + 12 + 16:
        raise ValueError("envelope truncado")
    eph_pub = envelope[:32]
    nonce = envelope[32:44]
    ct_tag = envelope[44:]
    shared = x25519_shared(my_dh_priv, eph_pub)
    wrap_key = hkdf_sha256(shared, aad, aad, 32)
    return AESGCM(wrap_key).decrypt(nonce, ct_tag, aad)


def pairwise_key(my_priv: bytes, their_pub: bytes, domain: bytes) -> bytes:
    shared = x25519_shared(my_priv, their_pub)
    return hkdf_sha256(shared, domain, domain, 32)


def pairwise_encrypt(my_priv: bytes, their_pub: bytes, domain: bytes,
                     plain: bytes) -> bytes:
    key = pairwise_key(my_priv, their_pub, domain)
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plain, domain)


def pairwise_decrypt(my_priv: bytes, their_pub: bytes, domain: bytes,
                     blob: bytes) -> bytes:
    key = pairwise_key(my_priv, their_pub, domain)
    return AESGCM(key).decrypt(blob[:12], blob[12:], domain)


def chat_aad(scope: str) -> bytes:
    return DOMAIN_CHAT + b"|" + scope.encode()


def sas_code(id_pub_a: bytes, id_pub_b: bytes) -> str:
    digest = hashlib.sha256(
        SAS_PREFIX + min(id_pub_a, id_pub_b) + max(id_pub_a, id_pub_b)).digest()
    value = int.from_bytes(digest[-4:], "big") % 1_000_000_000
    digits = f"{value:09d}"
    return f"{digits[:3]} {digits[3:6]} {digits[6:]}"


def uid_for_id_pub(id_pub_spki_der: bytes) -> str:
    return base64.b64encode(hashlib.sha256(id_pub_spki_der).digest()).decode()
