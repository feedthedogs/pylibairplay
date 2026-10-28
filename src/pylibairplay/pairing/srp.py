"""SRP-6a (RFC 5054) as used by AirPlay/HAP pair-setup, server (accessory) side.

Implemented from RFC 5054 and the HAP spec:

* Group: 3072-bit (RFC 5054 Appendix A), hash: SHA-512.
* Username is the fixed string ``"Pair-Setup"``.
* ``k = H(N | PAD(g))``, ``x = H(s | H(U | ":" | p))``.
* ``A`` comes from the iOS sender; we are the server holding ``b``/``B``.

Only the server role is implemented (the receiver verifies the sender's proof).
Tested against the RFC 5054 Appendix B test vector in ``tests/test_srp.py``.
"""

from __future__ import annotations

import hashlib
import os

# RFC 5054 Appendix A, 3072-bit group.
_N_HEX = """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718
3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33
A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7
ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864
D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2
08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
""".replace("\n", "").replace(" ", "")

N = int(_N_HEX, 16)
g = 5
_WIDTH = (N.bit_length() + 7) // 8
# AirPlay/iOS SRP uses an asymmetric g representation (confirmed against the
# cidermill-airplay IOS26 transient oracle, which interoperates with real iOS 26):
#   * k = H(PAD(N) | PAD(g))      -- g left-padded to N's width
#   * proof term H(g) = H(g_min)  -- g as its minimal big-endian byte
# (This differs from pysrp/HomeKit, which use minimal g for k too.)
_G_BYTES = g.to_bytes((g.bit_length() + 7) // 8, "big")  # minimal g, for the proof's H(g)


def _H(*chunks: bytes) -> bytes:
    h = hashlib.sha512()
    for c in chunks:
        h.update(c)
    return h.digest()


def _pad(x: int) -> bytes:
    return x.to_bytes(_WIDTH, "big")


def _int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _H_int(*chunks: bytes) -> int:
    return _int(_H(*chunks))


class SrpServer:
    """Accessory-side SRP-6a verifier for one pair-setup exchange."""

    def __init__(self, username: bytes, password: bytes, *, salt: bytes | None = None, b: int | None = None) -> None:
        self.username = username
        self.salt = salt if salt is not None else os.urandom(16)
        x = _H_int(self.salt, _H(username + b":" + password))
        self.v = pow(g, x, N)  # verifier
        self.k = _H_int(_pad(N), _pad(g))  # k uses PADDED g (AirPlay convention)
        self._b = b if b is not None else _int(os.urandom(32))
        # B = (k*v + g^b) mod N
        self.B = (self.k * self.v + pow(g, self._b, N)) % N
        self._A: int | None = None
        self._K: bytes | None = None
        self._M1: bytes | None = None

    def set_A(self, A: bytes | int) -> None:
        A = A if isinstance(A, int) else _int(A)
        if A % N == 0:
            raise ValueError("invalid client public value A")
        self._A = A
        u = _H_int(_pad(A), _pad(self.B))
        # S = (A * v^u) ^ b mod N
        S = pow(A * pow(self.v, u, N), self._b, N)
        self._K = _H(_pad(S))
        self._M1 = self._client_proof()

    @property
    def public(self) -> bytes:
        return _pad(self.B)

    @property
    def session_key(self) -> bytes:
        assert self._K is not None, "set_A first"
        return self._K

    def _client_proof(self) -> bytes:
        assert self._A is not None and self._K is not None
        # M1 = H(H(N) XOR H(g) | H(U) | s | A | B | K)
        hn = _int(_H(_pad(N)))
        hg = _int(_H(_G_BYTES))
        hxor = (hn ^ hg).to_bytes(64, "big")
        return _H(hxor, _H(self.username), self.salt, _pad(self._A), _pad(self.B), self._K)

    def verify(self, client_M1: bytes) -> bytes:
        """Check the sender's proof M1; return the server proof M2.

        Raises ValueError if the proof is wrong (wrong PIN or tampered exchange).
        """
        assert self._M1 is not None and self._A is not None and self._K is not None, "set_A first"
        if not _consttime_eq(client_M1, self._M1):
            raise ValueError("SRP client proof mismatch (wrong PIN?)")
        # M2 = H(A | M1 | K)
        return _H(_pad(self._A), client_M1, self._K)


def _consttime_eq(a: bytes, b: bytes) -> bool:
    import hmac

    return hmac.compare_digest(a, b)
