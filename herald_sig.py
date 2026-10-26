#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Ed25519 sign/verify (RFC 8032), pure Python stdlib — the Herald
# verify interface Proving consumes for mandates, pins, and arms.

"""Ed25519 sign/verify (RFC 8032), pure Python stdlib.

Spec §9: signatures are Herald key machinery (Ed25519 house
pattern); P0 uses Herald TEST keys / fixtures behind this same
verify interface — no second crypto path is built. Signing here
exists only so fixtures and tests can mint Herald-shaped records;
the bridge itself only verifies (plus its own pack seal, §11.2).
Deterministic per RFC 8032. Verified against the RFC 8032 §7.1
test vector in tests/test_proving.py.
"""
import hashlib

_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _sha512(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_B = (_xrecover(_BY), _BY)


def _edwards(p, q):
    x1, y1 = p
    x2, y2 = q
    denom = pow(1 + _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    x3 = (x1 * y2 + x2 * y1) * denom % _Q
    denom2 = pow(1 - _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    y3 = (y1 * y2 + x1 * x2) * denom2 % _Q
    return x3, y3


def _scalarmult(p, e):
    if e == 0:
        return (0, 1)
    q = _scalarmult(p, e // 2)
    q = _edwards(q, q)
    if e & 1:
        q = _edwards(q, p)
    return q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _encodepoint(p) -> bytes:
    x, y = p
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    out = bytearray(32)
    for i in range(256):
        if bits[i]:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _decodepoint(s: bytes):
    y = sum(2 ** i * ((s[i // 8] >> (i % 8)) & 1) for i in range(255))
    sign = (s[31] >> 7) & 1
    x = _xrecover(y)
    if (x & 1) != sign:
        x = _Q - x
    return x, y


def _hint(m: bytes) -> int:
    return int.from_bytes(_sha512(m), "little")


def keypair_from_seed(seed: bytes):
    """(private_seed_hex, public_key_bytes) from a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _sha512(seed)
    a = 2 ** 254 + sum(2 ** i * ((h[i // 8] >> (i % 8)) & 1)
                       for i in range(3, 254))
    return seed.hex(), _encodepoint(_scalarmult(_B, a))


def sign(seed: bytes, msg: bytes) -> bytes:
    h = _sha512(seed)
    a = 2 ** 254 + sum(2 ** i * ((h[i // 8] >> (i % 8)) & 1)
                       for i in range(3, 254))
    pk = _encodepoint(_scalarmult(_B, a))
    r = _hint(h[32:64] + msg) % _L
    r_enc = _encodepoint(_scalarmult(_B, r))
    s_val = (r + _hint(r_enc + pk + msg) * a) % _L
    return r_enc + _encodeint(s_val)


def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    if len(sig) != 64 or len(pk) != 32:
        return False
    try:
        r_point = _decodepoint(sig[:32])
        a_point = _decodepoint(pk)
        s_val = _decodeint(sig[32:])
    except Exception:
        return False
    if s_val >= _L:
        return False
    h = _hint(sig[:32] + pk + msg) % _L
    return _scalarmult(_B, s_val) == _edwards(
        r_point, _scalarmult(a_point, h))


# Eclipse Proving MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
