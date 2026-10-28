"""Validate the SRP-6a server role with a reference client written from RFC 5054.

HAP's parameters (3072-bit group, SHA-512) have no published end-to-end vector,
so we drive the server with an independent client implementation and confirm the
mutual proofs line up, and that a wrong password is rejected.
"""

import hashlib
import os

import pytest

from pylibairplay.pairing import srp
from pylibairplay.pairing.srp import N, g


def _H_int(*c):
    h = hashlib.sha512()
    for x in c:
        h.update(x)
    return int.from_bytes(h.digest(), "big")


def _pad(x):
    return x.to_bytes((N.bit_length() + 7) // 8, "big")


def _client(username, password, salt, B):
    """A minimal RFC 5054 client; returns (A, M1, K)."""
    a = int.from_bytes(os.urandom(32), "big")
    A = pow(g, a, N)
    k = _H_int(_pad(N), _pad(g))
    x = _H_int(salt, hashlib.sha512(username + b":" + password).digest())
    u = _H_int(_pad(A), _pad(B))
    S = pow((B - k * pow(g, x, N)) % N, a + u * x, N)
    K = hashlib.sha512(_pad(S)).digest()
    hn = int.from_bytes(hashlib.sha512(_pad(N)).digest(), "big")
    hg = int.from_bytes(hashlib.sha512(g.to_bytes(1,"big")).digest(), "big")
    hxor = (hn ^ hg).to_bytes(64, "big")
    M1 = hashlib.sha512(hxor + hashlib.sha512(username).digest() + salt + _pad(A) + _pad(B) + K).digest()
    return A, M1, K


def test_successful_pairing():
    user, pw = b"Pair-Setup", b"3939"
    server = srp.SrpServer(user, pw)
    A, M1, K = _client(user, pw, server.salt, server.B)
    server.set_A(A)
    M2 = server.verify(M1)
    assert server.session_key == K
    # client verifies server proof M2 = H(A | M1 | K)
    assert M2 == hashlib.sha512(_pad(A) + M1 + K).digest()


def test_wrong_password_rejected():
    user = b"Pair-Setup"
    server = srp.SrpServer(user, b"1234")
    A, M1, _ = _client(user, b"9999", server.salt, server.B)
    server.set_A(A)
    with pytest.raises(ValueError):
        server.verify(M1)


def test_rejects_zero_A():
    server = srp.SrpServer(b"Pair-Setup", b"0000")
    with pytest.raises(ValueError):
        server.set_A(N)  # A mod N == 0
