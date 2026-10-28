"""Exercise the transient pair-setup state machine end to end with a HAP client."""
import hashlib, os
from pylibairplay.pairing import tlv8, setup
from pylibairplay.pairing.tlv8 import Tag
from pylibairplay.pairing.setup import PairSetupServer, FLAG_TRANSIENT, SRP_USERNAME
from pylibairplay.pairing.srp import N, g


def _pad(x):
    return x.to_bytes((N.bit_length() + 7) // 8, "big")

def _H_int(*c):
    h = hashlib.sha512()
    for x in c: h.update(x)
    return int.from_bytes(h.digest(), "big")


def test_transient_pair_setup_succeeds():
    pin = b"3939"
    server = PairSetupServer(pin=pin)
    # M1 -> M2
    m2 = tlv8.decode(server.handle(tlv8.encode({
        Tag.STATE: b"\x01", Tag.METHOD: b"\x00",
        Tag.FLAGS: FLAG_TRANSIENT.to_bytes(4, "little")})))
    assert m2[Tag.STATE] == b"\x02"
    B = int.from_bytes(m2[Tag.PUBLIC_KEY], "big")
    salt = m2[Tag.SALT]
    # client SRP
    a = int.from_bytes(os.urandom(32), "big"); A = pow(g, a, N)
    k = _H_int(_pad(N), _pad(g))
    x = _H_int(salt, hashlib.sha512(SRP_USERNAME + b":" + pin).digest())
    u = _H_int(_pad(A), _pad(B))
    S = pow((B - k * pow(g, x, N)) % N, a + u * x, N)
    K = hashlib.sha512(_pad(S)).digest()
    hn = int.from_bytes(hashlib.sha512(_pad(N)).digest(), "big")
    hg = int.from_bytes(hashlib.sha512(g.to_bytes(1,"big")).digest(), "big")
    M1 = hashlib.sha512((hn ^ hg).to_bytes(64, "big") + hashlib.sha512(SRP_USERNAME).digest()
                        + salt + _pad(A) + _pad(B) + K).digest()
    # M3 -> M4
    m4 = tlv8.decode(server.handle(tlv8.encode({
        Tag.STATE: b"\x03", Tag.PUBLIC_KEY: _pad(A), Tag.PROOF: M1})))
    assert m4[Tag.STATE] == b"\x04"
    assert m4[Tag.PROOF] == hashlib.sha512(_pad(A) + M1 + K).digest()
    assert server.transient is True
    assert server.pairing_secret == K  # SRP key becomes the pairing secret


def test_m2_echoes_client_flags():
    """iOS's M4->M5 decision tests bit 9 of (serverM2Flags XOR ownFlags); the
    receiver must echo the client's M1 Flags (0x13) so bit 9 agrees and the client
    proceeds to M5."""
    server = PairSetupServer(pin=b"3939")
    flags = (FLAG_TRANSIENT | 0x200).to_bytes(4, "little")  # bit 9 set
    m2 = tlv8.decode(server.handle(tlv8.encode({
        Tag.STATE: b"\x01", Tag.METHOD: b"\x00", Tag.FLAGS: flags})))
    assert m2.get(Tag.FLAGS) == flags  # echoed verbatim


def test_m2_omits_flags_when_client_sends_none():
    """When the client sends no Flags TLV, the receiver sends none either (the bit-9
    test then already evaluates to 'proceed')."""
    server = PairSetupServer(pin=b"3939")
    m2 = tlv8.decode(server.handle(tlv8.encode({Tag.STATE: b"\x01"})))
    assert Tag.FLAGS not in m2


def test_wrong_pin_raises():
    server = PairSetupServer(pin=b"0000")
    m2 = tlv8.decode(server.handle(tlv8.encode({Tag.STATE: b"\x01"})))
    B = int.from_bytes(m2[Tag.PUBLIC_KEY], "big"); salt = m2[Tag.SALT]
    a = int.from_bytes(os.urandom(32), "big"); A = pow(g, a, N)
    import pytest
    with pytest.raises(setup.PairingError):
        server.handle(tlv8.encode({Tag.STATE: b"\x03", Tag.PUBLIC_KEY: _pad(A),
                                   Tag.PROOF: b"\x00" * 64}))


def test_m4_carries_mfi_certificate_and_signature():
    """With MFi credentials the M4 gains an encrypted {Certificate, Signature} sub-TLV
    (nonce PS-Msg04) whose signature covers the HKDF challenge from the SRP key."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from pylibairplay import keys
    from pylibairplay.mfi import MFiCredentials

    seen = []
    creds = MFiCredentials(certificate=b"CERT" * 100, sign=lambda c: seen.append(c) or b"SIG:" + c)
    pin = b"3939"
    server = PairSetupServer(pin=pin, mfi=creds)
    m2 = tlv8.decode(server.handle(tlv8.encode({
        Tag.STATE: b"\x01", Tag.FLAGS: FLAG_TRANSIENT.to_bytes(4, "little")})))
    B = int.from_bytes(m2[Tag.PUBLIC_KEY], "big"); salt = m2[Tag.SALT]
    a = int.from_bytes(os.urandom(32), "big"); A = pow(g, a, N)
    k = _H_int(_pad(N), _pad(g))
    x = _H_int(salt, hashlib.sha512(SRP_USERNAME + b":" + pin).digest())
    u = _H_int(_pad(A), _pad(B))
    K = hashlib.sha512(_pad(pow((B - k * pow(g, x, N)) % N, a + u * x, N))).digest()
    hn = int.from_bytes(hashlib.sha512(_pad(N)).digest(), "big")
    hg = int.from_bytes(hashlib.sha512(g.to_bytes(1, "big")).digest(), "big")
    M1 = hashlib.sha512((hn ^ hg).to_bytes(64, "big") + hashlib.sha512(SRP_USERNAME).digest()
                        + salt + _pad(A) + _pad(B) + K).digest()
    m4 = tlv8.decode(server.handle(tlv8.encode({
        Tag.STATE: b"\x03", Tag.PUBLIC_KEY: _pad(A), Tag.PROOF: M1})))
    enc_key = keys.hkdf_sha512(K, keys.PAIR_SETUP_SALT, keys.PAIR_SETUP_INFO, 32)
    sub = tlv8.decode(ChaCha20Poly1305(enc_key).decrypt(
        b"\x00\x00\x00\x00PS-Msg04", m4[Tag.ENCRYPTED_DATA], None))
    challenge = keys.hkdf_sha512(K, keys.MFI_PAIR_SETUP_SALT, keys.MFI_PAIR_SETUP_INFO, 32)
    assert sub[Tag.CERTIFICATE] == b"CERT" * 100
    assert sub[Tag.SIGNATURE] == b"SIG:" + challenge and seen == [challenge]


def test_m4_has_no_extra_without_mfi():
    server = PairSetupServer(pin=b"3939")
    server.handle(tlv8.encode({Tag.STATE: b"\x01"}))
    assert server.mfi is None


def _self_signed(key, hash_alg=None):
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hash_alg or hashes.SHA256()))


def _write_creds(tmp_path, key):
    from cryptography.hazmat.primitives import serialization

    (tmp_path / "k.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (tmp_path / "c.pem").write_bytes(_self_signed(key).public_bytes(serialization.Encoding.PEM))
    return str(tmp_path / "c.pem"), str(tmp_path / "k.pem")


def test_mfi_rsa1024_signature_matches_ios_scheme(tmp_path):
    """128-byte signature = RSA PKCS#1 v1.5 over SHA-1(challenge)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from pylibairplay.mfi import MFiCredentials

    creds = MFiCredentials.from_pem_files(*_write_creds(tmp_path, rsa.generate_private_key(65537, 1024)))
    assert len(creds.sign(b"x" * 32)) == 128
    creds.check(b"x" * 32)


def test_mfi_ec_signature_is_raw_rfc4754(tmp_path):
    """Non-RSA-1024 signatures are SHA-256 + ECDSA as raw r||s (64 bytes for P-256), not DER."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from pylibairplay.mfi import MFiCredentials

    creds = MFiCredentials.from_pem_files(*_write_creds(tmp_path, ec.generate_private_key(ec.SECP256R1())))
    sig = creds.sign(b"y" * 32)
    assert len(sig) == 64 and sig[0] != 0x30
    creds.check(b"y" * 32)


def test_mfi_check_rejects_wrong_key(tmp_path):
    import pytest
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from pylibairplay.mfi import MFiCredentials

    cert, _ = _write_creds(tmp_path, ec.generate_private_key(ec.SECP256R1()))
    other = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "other.pem").write_bytes(other.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with pytest.raises(ValueError):
        MFiCredentials.from_pem_files(cert, str(tmp_path / "other.pem")).check()


def test_mfi_check_accepts_pkcs7_container(tmp_path):
    """A PKCS#7 certificates-only blob (leaf first) is what a co-processor returns."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import pkcs7
    from pylibairplay.mfi import MFiCredentials

    cert_path, key_path = _write_creds(tmp_path, ec.generate_private_key(ec.SECP256R1()))
    from cryptography import x509
    leaf = x509.load_pem_x509_certificate(open(cert_path, "rb").read())
    blob = pkcs7.serialize_certificates([leaf], serialization.Encoding.DER)
    base = MFiCredentials.from_pem_files(cert_path, key_path)
    MFiCredentials(certificate=blob, sign=base.sign).check()


def test_mfi_rejects_non_1024_rsa(tmp_path):
    import pytest
    from cryptography.hazmat.primitives.asymmetric import rsa
    from pylibairplay.mfi import MFiCredentials

    with pytest.raises(ValueError):
        MFiCredentials.from_pem_files(*_write_creds(tmp_path, rsa.generate_private_key(65537, 2048)))
