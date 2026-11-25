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
