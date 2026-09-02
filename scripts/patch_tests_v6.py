#!/usr/bin/env python3
"""Adapta os testes de integração ao protocolo v6.

Cada teste tinha o mesmo Client inline com handshake v5 (Ed25519 via openssl
CLI, hello proto=5). O v6 exige: proto=6 + dhPub/dhSig (X25519 com binding
Ed25519) no hello — sem isso o servidor recusa com bad_identity/bad_proto.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "tests"

# Bloco X25519+binding a inserir após a geração da Ed25519 (identação de 8
# espaços, como no corpo do Client.__init__ dos testes).
DH_BLOCK = '''        # v6 E2EE: par X25519 + binding assinado (o login recusa sem eles).
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location(
            "e2ee_v6", Path(__file__).resolve().parent / "e2ee_v6.py")
        _e2ee = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_e2ee)
        self.v6 = _e2ee.V6Identity(identity)
'''


def patch(path: Path) -> bool:
    src = path.read_text(encoding="utf-8")
    orig = src

    # 1. default do parâmetro protocol e literal "proto": 5
    src = src.replace("protocol: int = 5,", "protocol: int = 6,")
    src = src.replace('"t": "hello", "proto": 5,', '"t": "hello", "proto": 6,')

    # 2. insere o par X25519 logo após a geração da pública Ed25519
    key_gen_tail = '''                 "-outform", "DER", "-out", str(public_key)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
'''
    if key_gen_tail in src and "self.v6" not in src:
        src = src.replace(key_gen_tail, key_gen_tail + DH_BLOCK, 1)

    # 3. hello ganha dhPub/dhSig (padrão: self.send({ ... "proto": protocol, ...}))
    hello_pattern = re.compile(
        r'(self\.send\(\{\s*\n\s*"t":\s*"hello",\s*"proto":\s*protocol,\s*.*?)(\n\s*\}\))',
        re.S)
    m = hello_pattern.search(src)
    if m and "dhPub" not in src:
        head, tail = m.group(1), m.group(2)
        src = (src[:m.start()]
               + head + ',\n            "dhPub": self.v6.hello_fields()["dhPub"],'
                 + '\n            "dhSig": self.v6.hello_fields()["dhSig"],'
               + tail + src[m.end():])

    if src != orig:
        path.write_text(src, encoding="utf-8")
        return True
    return False


def main() -> None:
    for path in sorted(ROOT.glob("*_integration.py")):
        changed = patch(path)
        print(f"{'PATCHED ' if changed else 'skip     '} {path.name}")


if __name__ == "__main__":
    main()
