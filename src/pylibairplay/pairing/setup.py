"""Server-side pair-setup and pair-verify state machines (receiver role).

Implemented from the public HomeKit Accessory Protocol (HAP) specification's
pairing chapter plus RFC 5054 (SRP) and RFC 7748 (X25519). The firmware confirms
AirPlay uses this HAP flow over the ``X-Apple-HKP`` request type with the TLV8
payload in ``X-Apple-PD`` (AirPlayReceiver ``requestProcessPairSetupCoreUtils`` /
``requestProcessPairVerify``), and that a successful pair-verify immediately sets up
the ``Control-Salt`` channel keys.

Scope for v1 screen mirroring:

* **Transient pair-setup** (HAP "Pair Setup with transient flag"): SRP states M1-M4
  only, no long-term key exchange. The SRP shared key ``K`` becomes the pairing
  secret that feeds the control-channel and mirror-stream HKDFs (keys.py).
* **Pair-verify**: X25519 ephemeral exchange with Ed25519 identity signatures, used
  by clients that paired persistently. Session secret feeds the same HKDFs.

State values and TLV types are HAP constants (see tlv8.Tag).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .. import keys
from ..mfi import MFiCredentials
from . import tlv8
from .srp import SrpServer
from .tlv8 import Tag

# HAP pairing method/state constants.
STATE_M1, STATE_M2, STATE_M3, STATE_M4, STATE_M5, STATE_M6 = 1, 2, 3, 4, 5, 6
METHOD_PAIR_SETUP = 0
FLAG_TRANSIENT = 0x00000010  # kPairingFlag_Transient
# AirPlay's fixed transient username and default PIN (no on-screen code path).
SRP_USERNAME = b"Pair-Setup"
DEFAULT_PIN = b"3939"


class PairingError(Exception):
    def __init__(self, tlv_error: int, message: str = "") -> None:
        super().__init__(message or f"pairing error {tlv_error}")
        self.tlv_error = tlv_error  # Tag.ERROR value to return to the client


@dataclass
class PairSetupServer:
    """One pair-setup exchange, transient (M1-M4) or full PIN (M1-M6).

    Transient (flags 0x10): ends at M4; ``pairing_secret`` = SRP session key.
    Full PIN: M5/M6 exchange long-term identities; on success ``controller_id`` and
    ``controller_ltpk`` hold the credential to persist, enabling later pair-verify.
    ``identity`` (accessory Ed25519 LTSK) and ``device_id`` (accessory pairing id)
    are required for the M6 identity reply.
    """

    pin: bytes = DEFAULT_PIN
    identity: Ed25519PrivateKey | None = None
    device_id: bytes = b""
    mfi: MFiCredentials | None = None  # certificate + signer, appended to M4 when set
    _srp: SrpServer | None = None
    _K: bytes = b""
    _client_flags: bytes | None = None  # client's M1 Flags TLV (0x13), echoed in M2
    transient: bool = False
    pairing_secret: bytes | None = None
    controller_id: bytes | None = None  # set after M6 (the credential)
    controller_ltpk: bytes | None = None
    completed: bool = False
    last_A: bytes | None = None  # debug: iOS's public value from M3
    last_proof: bytes | None = None  # debug: iOS's proof from M3

    def handle(self, body: bytes) -> bytes:
        """Process one TLV8 request, return the TLV8 response."""
        tlv = tlv8.decode(body)
        state = tlv.get(Tag.STATE, b"\x00")[0]
        if state == STATE_M1:
            return self._m1_to_m2(tlv)
        if state == STATE_M3:
            return self._m3_to_m4(tlv)
        if state == STATE_M5:
            return self._m5_to_m6(tlv)
        raise PairingError(Tag.ERROR, f"unexpected pair-setup state {state}")

    def _m1_to_m2(self, tlv: dict[int, bytes]) -> bytes:
        self._client_flags = tlv.get(Tag.FLAGS)
        flags = int.from_bytes(self._client_flags or b"\x00", "little")
        self.transient = bool(flags & FLAG_TRANSIENT)
        self._srp = SrpServer(SRP_USERNAME, self.pin)
        m2: dict[int, bytes] = {
            Tag.STATE: bytes((STATE_M2,)),
            Tag.PUBLIC_KEY: self._srp.public,
            Tag.SALT: self._srp.salt,
        }
        # Echo the client's pairing Flags (TLV 0x13) back in M2. The iOS 26 client
        # decides M4->M5 (identity exchange) vs "transient done" by testing bit 9 of
        # (serverM2Flags XOR ownFlags): it proceeds to M5 only when bit 9 agrees. A
        # receiver that omits 0x13 reads as 0, so if the client set bit 9 it skips M5
        # and abandons after M4. Echoing the client's value makes bit 9 agree.
        # Confirmed in CoreUtils _SetupServerExchange/_SetupClientExchange.
        if self._client_flags:
            m2[Tag.FLAGS] = self._client_flags
        return tlv8.encode(m2)

    def _m3_to_m4(self, tlv: dict[int, bytes]) -> bytes:
        assert self._srp is not None, "M3 before M1"
        self.last_A = tlv.get(Tag.PUBLIC_KEY)
        self.last_proof = tlv.get(Tag.PROOF)
        try:
            self._srp.set_A(tlv[Tag.PUBLIC_KEY])
            m2 = self._srp.verify(tlv[Tag.PROOF])
        except (KeyError, ValueError) as e:
            raise PairingError(Tag.ERROR, f"SRP verification failed: {e}") from e
        self._K = self._srp.session_key
        if self.transient:
            # Transient: the SRP session key is the pairing secret; done at M4.
            self.pairing_secret = self._K
            self.completed = True
        m4: dict[int, bytes] = {Tag.STATE: bytes((STATE_M4,)), Tag.PROOF: m2}
        if self.mfi is not None:
            m4[Tag.ENCRYPTED_DATA] = self._mfi_m4_extra()
        return tlv8.encode(m4)

    def _mfi_m4_extra(self) -> bytes:
        """Encrypted M4 sub-TLV {Certificate, Signature} proving the receiver's MFi licence.

        The signature covers a 32-byte challenge derived from the SRP key; the sub-TLV is
        sealed with the pair-setup encryption key under nonce ``PS-Msg04`` (CoreUtils ``_MFiClientVerify`` / ``_ServerEncryptExtra``).
        """
        assert self.mfi is not None
        challenge = keys.hkdf_sha512(self._K, keys.MFI_PAIR_SETUP_SALT, keys.MFI_PAIR_SETUP_INFO, 32)
        sub = tlv8.encode({Tag.CERTIFICATE: self.mfi.certificate, Tag.SIGNATURE: self.mfi.sign(challenge)})
        enc_key = keys.hkdf_sha512(self._K, keys.PAIR_SETUP_SALT, keys.PAIR_SETUP_INFO, 32)
        return ChaCha20Poly1305(enc_key).encrypt(_setup_nonce(b"PS-Msg04"), sub, None)

    def _m5_to_m6(self, tlv: dict[int, bytes]) -> bytes:
        """Exchange long-term identities (HAP pair-setup M5/M6)."""
        if self.identity is None:
            raise PairingError(Tag.ERROR, "no accessory identity for M5/M6")
        enc_key = keys.hkdf_sha512(self._K, keys.PAIR_SETUP_SALT, keys.PAIR_SETUP_INFO, 32)
        try:
            plain = ChaCha20Poly1305(enc_key).decrypt(_setup_nonce(b"PS-Msg05"), tlv[Tag.ENCRYPTED_DATA], None)
        except Exception as e:
            raise PairingError(Tag.ERROR, "pair-setup M5 decryption failed") from e
        sub = tlv8.decode(plain)
        ctrl_id = sub[Tag.IDENTIFIER]
        ctrl_ltpk = sub[Tag.PUBLIC_KEY]
        # Verify the controller's self-signature over controllerX | id | ltpk.
        ctrl_x = keys.hkdf_sha512(
            self._K, keys.PAIR_SETUP_CONTROLLER_SIGN_SALT, keys.PAIR_SETUP_CONTROLLER_SIGN_INFO, 32
        )
        try:
            Ed25519PublicKey.from_public_bytes(ctrl_ltpk).verify(sub[Tag.SIGNATURE], ctrl_x + ctrl_id + ctrl_ltpk)
        except Exception as e:
            raise PairingError(Tag.ERROR, "pair-setup M5 signature invalid") from e
        self.controller_id = ctrl_id
        self.controller_ltpk = ctrl_ltpk
        # M6: send the accessory's identity, signed the same way.
        acc_ltpk = self.identity.public_key().public_bytes_raw()
        acc_x = keys.hkdf_sha512(
            self._K, keys.PAIR_SETUP_ACCESSORY_SIGN_SALT, keys.PAIR_SETUP_ACCESSORY_SIGN_INFO, 32
        )
        acc_sig = self.identity.sign(acc_x + self.device_id + acc_ltpk)
        acc_sub = tlv8.encode(
            {Tag.IDENTIFIER: self.device_id, Tag.PUBLIC_KEY: acc_ltpk, Tag.SIGNATURE: acc_sig}
        )
        acc_enc = ChaCha20Poly1305(enc_key).encrypt(_setup_nonce(b"PS-Msg06"), acc_sub, None)
        self.completed = True
        return tlv8.encode({Tag.STATE: bytes((STATE_M6,)), Tag.ENCRYPTED_DATA: acc_enc})


@dataclass
class PairVerifyServer:
    """One pair-verify exchange. Produces ``shared_secret`` on success.

    ``identity`` is this receiver's long-term Ed25519 key; ``peer_resolver`` maps a
    client pairing identifier to its registered Ed25519 public key (or None to
    accept any, for transient-style setups where identities aren't persisted).
    """

    identity: Ed25519PrivateKey
    device_id: bytes
    peer_resolver: "callable" = field(default=lambda _id: None)
    _eph_priv: X25519PrivateKey | None = None
    _eph_pub: bytes = b""
    _peer_eph_pub: bytes = b""
    _session_key: bytes = b""
    shared_secret: bytes | None = None
    completed: bool = False  # True only after a successful M4

    def handle(self, body: bytes) -> bytes:
        tlv = tlv8.decode(body)
        state = tlv.get(Tag.STATE, b"\x00")[0]
        if state == STATE_M1:
            return self._m1_to_m2(tlv)
        if state == STATE_M3:
            return self._m3_to_m4(tlv)
        raise PairingError(Tag.ERROR, f"unexpected pair-verify state {state}")

    def _m1_to_m2(self, tlv: dict[int, bytes]) -> bytes:
        self._peer_eph_pub = tlv[Tag.PUBLIC_KEY]
        self._eph_priv = X25519PrivateKey.generate()
        self._eph_pub = self._eph_priv.public_key().public_bytes_raw()
        shared = self._eph_priv.exchange(X25519PublicKey.from_public_bytes(self._peer_eph_pub))
        self.shared_secret = shared
        # Session key for encrypting the M2/M3 sub-TLV, HKDF with the verify salt.
        self._session_key = keys.hkdf_sha512(shared, keys.PAIR_VERIFY_SALT, keys.PAIR_VERIFY_INFO, 32)
        # Server proof: sign (serverEph | deviceId | clientEph).
        to_sign = self._eph_pub + self.device_id + self._peer_eph_pub
        signature = self.identity.sign(to_sign)
        sub = tlv8.encode({Tag.IDENTIFIER: self.device_id, Tag.SIGNATURE: signature})
        encrypted = ChaCha20Poly1305(self._session_key).encrypt(_verify_nonce(b"PV-Msg02"), sub, None)
        return tlv8.encode(
            {Tag.STATE: bytes((STATE_M2,)), Tag.PUBLIC_KEY: self._eph_pub, Tag.ENCRYPTED_DATA: encrypted}
        )

    def _m3_to_m4(self, tlv: dict[int, bytes]) -> bytes:
        try:
            plain = ChaCha20Poly1305(self._session_key).decrypt(
                _verify_nonce(b"PV-Msg03"), tlv[Tag.ENCRYPTED_DATA], None
            )
        except Exception as e:
            raise PairingError(Tag.ERROR, "pair-verify M3 decryption failed") from e
        sub = tlv8.decode(plain)
        peer_id = sub[Tag.IDENTIFIER]
        peer_pub = self.peer_resolver(peer_id)
        if peer_pub is not None:
            to_verify = self._peer_eph_pub + peer_id + self._eph_pub
            try:
                Ed25519PublicKey.from_public_bytes(peer_pub).verify(sub[Tag.SIGNATURE], to_verify)
            except Exception as e:
                raise PairingError(Tag.ERROR, "unknown or unauthorized peer") from e
        self.completed = True
        return tlv8.encode({Tag.STATE: bytes((STATE_M4,))})


def _verify_nonce(label: bytes) -> bytes:
    # HAP uses a fixed 8-byte label right-aligned in a 12-byte nonce.
    return b"\x00\x00\x00\x00" + label


def _setup_nonce(label: bytes) -> bytes:
    return b"\x00\x00\x00\x00" + label
