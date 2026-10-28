"""Pair-verify server driven by a HAP client built on the same primitives."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from pylibairplay import keys
from pylibairplay.pairing import tlv8
from pylibairplay.pairing.tlv8 import Tag
from pylibairplay.pairing.setup import PairVerifyServer, _verify_nonce


def test_pair_verify_with_known_peer():
    server_id = Ed25519PrivateKey.generate()
    client_id = Ed25519PrivateKey.generate()
    client_pub = client_id.public_key().public_bytes_raw()
    server = PairVerifyServer(identity=server_id, device_id=b"AA:BB:CC:DD:EE:FF",
                              peer_resolver=lambda _id: client_pub)
    # client M1
    ce = X25519PrivateKey.generate()
    ce_pub = ce.public_key().public_bytes_raw()
    m2 = tlv8.decode(server.handle(tlv8.encode({Tag.STATE: b"\x01", Tag.PUBLIC_KEY: ce_pub})))
    assert m2[Tag.STATE] == b"\x02"
    se_pub = m2[Tag.PUBLIC_KEY]
    shared = ce.exchange(X25519PublicKey.from_public_bytes(se_pub))
    sk = keys.hkdf_sha512(shared, keys.PAIR_VERIFY_SALT, keys.PAIR_VERIFY_INFO, 32)
    # decrypt+verify server identity
    srv_sub = tlv8.decode(ChaCha20Poly1305(sk).decrypt(_verify_nonce(b"PV-Msg02"),
                                                        m2[Tag.ENCRYPTED_DATA], None))
    Ed25519PublicKey.from_public_bytes(server_id.public_key().public_bytes_raw()).verify(
        srv_sub[Tag.SIGNATURE], se_pub + b"AA:BB:CC:DD:EE:FF" + ce_pub)
    # client M3: sign and encrypt its identity
    sig = client_id.sign(ce_pub + b"client-id" + se_pub)
    sub = tlv8.encode({Tag.IDENTIFIER: b"client-id", Tag.SIGNATURE: sig})
    enc = ChaCha20Poly1305(sk).encrypt(_verify_nonce(b"PV-Msg03"), sub, None)
    m4 = tlv8.decode(server.handle(tlv8.encode({Tag.STATE: b"\x03", Tag.ENCRYPTED_DATA: enc})))
    assert m4[Tag.STATE] == b"\x04"
    assert server.shared_secret == shared
