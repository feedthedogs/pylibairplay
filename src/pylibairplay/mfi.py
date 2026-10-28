"""Optional Apple MFi credentials for the AirPlay 2 pairing path.

A third-party AirPlay 2 receiver that offers screen mirroring is expected to prove its
licence at pair-setup M4: it returns an encrypted sub-TLV carrying its MFi **certificate**
(TLV 0x09) and a **signature** (TLV 0x0A) made with the matching private key over a
challenge derived from the pairing session.
The key may live in an authentication co-processor or secure element, so this module takes a
*signer callable*; :meth:`MFiCredentials.from_pem_files` is a convenience for credentials you
hold as files.

The signature scheme below is what the iOS verifier (CoreUtils ``MFiPlatform_VerifySignatureEx``)
implements, recovered from firmware:

* 128-byte signature -> RSA-1024, PKCS#1 v1.5 over ``SHA-1(challenge)``;
* any other length   -> ``SHA-256(challenge)`` signed with ECDSA in **RFC 4754** form, i.e. the
  raw fixed-width ``r || s`` (not X9.62 DER).

pylibairplay ships no certificate and cannot create one: iOS only accepts a certificate that
chains to an Apple accessory CA. Use only credentials you are licensed to use.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

RSA1024_SIGNATURE_LEN = 128


@dataclass(frozen=True)
class MFiCredentials:
    """An MFi certificate plus the means to sign with its private key.

    - ``certificate``: sent to iOS verbatim — either a DER X.509 leaf certificate or a PKCS#7
      certificates-only container with the leaf first (what an MFi authentication
      co-processor returns).
    - ``sign``: maps the 32-byte pairing challenge to the signature bytes, in the scheme
      described in the module docstring. It receives the *challenge*; do the hashing inside.
    """

    certificate: bytes
    sign: Callable[[bytes], bytes]

    @classmethod
    def from_pem_files(cls, certificate_path: str, key_path: str,
                       password: bytes | None = None) -> "MFiCredentials":
        """Load a certificate (PEM or DER) and a private key (PEM) from disk.

        RSA keys must be 1024-bit (the only RSA size iOS verifies). EC keys sign the SHA-256
        of the challenge as raw ``r || s``.
        """
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        raw = Path(certificate_path).read_bytes()
        try:
            der = x509.load_pem_x509_certificate(raw).public_bytes(serialization.Encoding.DER)
        except ValueError:
            der = raw  # already DER X.509 or PKCS#7
        key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password)

        if isinstance(key, rsa.RSAPrivateKey):
            if key.key_size != 1024:
                raise ValueError("iOS only verifies RSA-1024 MFi signatures; use an EC key otherwise")

            def sign(challenge: bytes) -> bytes:
                return key.sign(challenge, padding.PKCS1v15(), hashes.SHA1())
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            width = (key.curve.key_size + 7) // 8

            def sign(challenge: bytes) -> bytes:
                r, s = decode_dss_signature(key.sign(challenge, ec.ECDSA(hashes.SHA256())))
                return r.to_bytes(width, "big") + s.to_bytes(width, "big")
        else:
            raise ValueError(f"unsupported MFi key type: {type(key).__name__}")
        return cls(certificate=der, sign=sign)

    def check(self, challenge: bytes = bytes(32)) -> None:
        """Self-test: sign ``challenge`` and verify it against the certificate's public key
        exactly as iOS does. Raises ``ValueError`` on any mismatch.

        Catches wrong key/cert pairs and wrong signature formats before a phone does. It does
        not (cannot) check that the certificate chains to an Apple anchor.
        """
        if not verify_signature(challenge, self.sign(challenge), self.certificate):
            raise ValueError("signature does not verify against the certificate's public key")


def _leaf_public_key(certificate: bytes):
    """Public key of the leaf in a DER X.509 cert or a PKCS#7 certificates-only container."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import pkcs7

    try:
        return x509.load_der_x509_certificate(certificate).public_key()
    except ValueError:
        return pkcs7.load_der_pkcs7_certificates(certificate)[0].public_key()


def verify_signature(challenge: bytes, signature: bytes, certificate: bytes) -> bool:
    """Replicate iOS's signature check (not its chain validation) for a challenge."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

    key = _leaf_public_key(certificate)
    try:
        if len(signature) == RSA1024_SIGNATURE_LEN:
            if not isinstance(key, rsa.RSAPublicKey):
                return False
            key.verify(signature, hashlib.sha1(challenge).digest(), padding.PKCS1v15(),
                       Prehashed(hashes.SHA1()))
        else:
            if not isinstance(key, ec.EllipticCurvePublicKey) or len(signature) % 2:
                return False
            half = len(signature) // 2
            der = encode_dss_signature(int.from_bytes(signature[:half], "big"),
                                       int.from_bytes(signature[half:], "big"))
            key.verify(der, hashlib.sha256(challenge).digest(), ec.ECDSA(Prehashed(hashes.SHA256())))
    except InvalidSignature:
        return False
    return True
