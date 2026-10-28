"""Full PIN pair-setup (M1-M6) + credential-backed pair-verify round-trip.

Uses an in-test HAP controller built from the same primitives to exercise the
server's M5/M6 identity exchange, credential storage, and that a subsequent
pair-verify succeeds using the stored credential. (Cross-implementation
correctness vs iOS is covered by the cidermill oracle during development; this
guards our own code against regressions.)
"""

import hashlib
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from pylibairplay import keys
from pylibairplay.pairing import tlv8
from pylibairplay.pairing.setup import PairSetupServer, PairVerifyServer, _setup_nonce, _verify_nonce
from pylibairplay.pairing.srp import N, g
from pylibairplay.pairing.tlv8 import Tag


def _pad(x):
    return x.to_bytes((N.bit_length() + 7) // 8, "big")


def _Hi(*c):
    h = hashlib.sha512()
    for x in c:
        h.update(x)
    return int.from_bytes(h.digest(), "big")


def _srp_client(salt, B, pin=b"3939"):
    a = int.from_bytes(os.urandom(32), "big")
    A = pow(g, a, N)
    k = _Hi(_pad(N), _pad(g))  # AirPlay: k pads g; proof's H(g) uses minimal g
    x = _Hi(salt, hashlib.sha512(b"Pair-Setup:" + pin).digest())
    u = _Hi(_pad(A), _pad(B))
    S = pow((B - k * pow(g, x, N)) % N, a + u * x, N)
    K = hashlib.sha512(_pad(S)).digest()
    hn = int.from_bytes(hashlib.sha512(_pad(N)).digest(), "big")
    hg = int.from_bytes(hashlib.sha512(g.to_bytes(1, "big")).digest(), "big")
    M1 = hashlib.sha512(
        (hn ^ hg).to_bytes(64, "big") + hashlib.sha512(b"Pair-Setup").digest() + salt + _pad(A) + _pad(B) + K
    ).digest()
    return _pad(A), M1, K


def test_pin_setup_stores_credential_and_verify_succeeds():
    acc = Ed25519PrivateKey.generate()
    dev = b"AA:BB:CC:DD:EE:FF"
    srv = PairSetupServer(pin=b"3939", identity=acc, device_id=dev)

    # M1 -> M2
    m2 = tlv8.decode(srv.handle(tlv8.encode({Tag.STATE: b"\x01", Tag.METHOD: b"\x00"})))
    B = int.from_bytes(m2[Tag.PUBLIC_KEY], "big")
    salt = m2[Tag.SALT]
    A, M1, K = _srp_client(salt, B)
    # M3 -> M4
    tlv8.decode(srv.handle(tlv8.encode({Tag.STATE: b"\x03", Tag.PUBLIC_KEY: A, Tag.PROOF: M1})))

    # M5: controller sends its identity, signed and encrypted.
    ctrl_ltsk = Ed25519PrivateKey.generate()
    ctrl_ltpk = ctrl_ltsk.public_key().public_bytes_raw()
    ctrl_id = b"client-uuid"
    ctrl_x = keys.hkdf_sha512(K, keys.PAIR_SETUP_CONTROLLER_SIGN_SALT, keys.PAIR_SETUP_CONTROLLER_SIGN_INFO, 32)
    sig = ctrl_ltsk.sign(ctrl_x + ctrl_id + ctrl_ltpk)
    sub = tlv8.encode({Tag.IDENTIFIER: ctrl_id, Tag.PUBLIC_KEY: ctrl_ltpk, Tag.SIGNATURE: sig})
    enc_key = keys.hkdf_sha512(K, keys.PAIR_SETUP_SALT, keys.PAIR_SETUP_INFO, 32)
    enc = ChaCha20Poly1305(enc_key).encrypt(_setup_nonce(b"PS-Msg05"), sub, None)
    m6 = tlv8.decode(srv.handle(tlv8.encode({Tag.STATE: b"\x05", Tag.ENCRYPTED_DATA: enc})))

    assert srv.completed and srv.controller_id == ctrl_id and srv.controller_ltpk == ctrl_ltpk
    # M6: accessory identity is present and decryptable.
    acc_sub = tlv8.decode(ChaCha20Poly1305(enc_key).decrypt(_setup_nonce(b"PS-Msg06"), m6[Tag.ENCRYPTED_DATA], None))
    assert acc_sub[Tag.PUBLIC_KEY] == acc.public_key().public_bytes_raw()

    # Now pair-verify with the stored credential must complete.
    store = {srv.controller_id: srv.controller_ltpk}
    v = PairVerifyServer(identity=acc, device_id=dev, peer_resolver=lambda cid: store.get(cid))
    ce = X25519PrivateKey.generate()
    ce_pub = ce.public_key().public_bytes_raw()
    vm2 = tlv8.decode(v.handle(tlv8.encode({Tag.STATE: b"\x01", Tag.PUBLIC_KEY: ce_pub})))
    se_pub = vm2[Tag.PUBLIC_KEY]
    shared = ce.exchange(X25519PublicKey.from_public_bytes(se_pub))
    sk = keys.hkdf_sha512(shared, keys.PAIR_VERIFY_SALT, keys.PAIR_VERIFY_INFO, 32)
    csig = ctrl_ltsk.sign(ce_pub + ctrl_id + se_pub)
    csub = tlv8.encode({Tag.IDENTIFIER: ctrl_id, Tag.SIGNATURE: csig})
    cenc = ChaCha20Poly1305(sk).encrypt(_verify_nonce(b"PV-Msg03"), csub, None)
    v.handle(tlv8.encode({Tag.STATE: b"\x03", Tag.ENCRYPTED_DATA: cenc}))
    assert v.completed and v.shared_secret == shared
