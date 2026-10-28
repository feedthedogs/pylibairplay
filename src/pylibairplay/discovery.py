"""mDNS advertisement of an AirPlay receiver (``_airplay._tcp``).

Field names and the required TXT keys come from the public openairplay airplay-spec
"service discovery" page. For the working screen path we advertise the legacy AirPlay-1
feature set (:data:`LEGACY_FEATURES`) so iOS takes the ``/fp-setup`` FairPlay route;
:data:`DEFAULT_FEATURES` is the AP2 set kept for the pairing path.

Requires the ``net`` extra (``zeroconf``).
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

from .features import format_features

# Feature bits a mirroring receiver advertises. Modeled on an observed working
# AirPlay-2 screen-mirroring receiver (a licensed third-party TV:
# features=0x7F8AD0,0x38BCF46), high-word bit 48 (transient) + bit 51 (CoreUtils).
#
# EXPERIMENT (device test 2026-10-24):
# with transient advertised AND OneTimePairingRequired (statusFlags bit 9) set, the
# iPhone chose MFi pair-setup (Method=1) and aborted after M4 because we can't
# produce an MFi signature. The sender only takes the MFi branch when transient
# pairing is *also* supported (`apsession_tryAPPairSetupAndVerify` bVar14 clause
# `(... || PINRequired) && transientSupported`); with transient OFF it falls to a
# Method=0 CoreUtils PIN pair-setup — the path we implement and validated vs
# cidermill (M5/M6 identity -> pair-verify -> encrypted SETUP). So we clear
# transient (bit 48) here and OneTimePairingRequired (bit 9) in the flags below.
# Revert FULL_AP2_FEATURES/flags if iOS stops offering mirroring.
FULL_AP2_FEATURES = (0x38BCF46 << 32) | 0x7F8AD0  # transient pairing on
DEFAULT_FEATURES = FULL_AP2_FEATURES & ~(1 << 48)  # transient off -> aim for Method=0

# Legacy AirPlay-1 feature set. Advertising this steers iOS to
# the legacy FairPlay (`/fp-setup`) screen path instead of AP2 CoreUtils/MFi pairing.
# 0x527FFEE6 is the well-known AirPlay-1 receiver low word; the high
# word is small (no AP2/CoreUtils bits). Used by the fp-setup capture mode to make the
# iPhone send a real `/fp-setup` request we can feed to the whitebox emulator.
LEGACY_FEATURES = (0x1E << 32) | 0x527FFEE6


@dataclass
class ReceiverInfo:
    name: str
    device_id: str  # "AA:BB:CC:DD:EE:FF" style, stable per receiver
    public_key: bytes  # Ed25519 accessory long-term public key
    port: int
    model: str = "AppleTV3,2"
    features: int = int(DEFAULT_FEATURES)
    source_version: str = "377.40.00"
    pin_required: bool = False
    legacy: bool = False  # AirPlay-1 fp-setup path (see LEGACY_FEATURES)
    mfi: bool = False  # AP2 path with an MFi certificate: advertise transient pairing
    extra_txt: dict[str, str] = field(default_factory=dict)

    def txt_records(self) -> dict[bytes, bytes]:
        """Build the ``_airplay._tcp`` TXT dictionary.

        Keys and shape follow a real AirPlay-2 mirroring receiver (see
        DEFAULT_FEATURES). ``protovers=1.1`` and ``acl``/``rsf``/``gid`` are the
        standard keys; ``flags`` has OneTimePairingRequired (bit 9) cleared per the
        Method=0 experiment (see DEFAULT_FEATURES note).
        """
        txt: dict[str, str] = {
            "acl": "0",
            "deviceid": self.device_id,
            "features": format_features(self.features),
            "rsf": "0x0",
            # bit 9 (0x200)=OneTimePairingRequired cleared: it steered iOS to the
            # MFi one-time PIN flow (Method=1). See DEFAULT_FEATURES note. Legacy mode
            # uses the minimal AirPlay-1 flags.
            "flags": "0x4" if (self.pin_required or self.legacy) else "0x44",
            "model": self.model,
            "manufacturer": "pylibairplay",
            "protovers": "1.1",
            "srcvers": self.source_version,
            "pi": self.device_id,
            "gid": self.device_id,
            "gcgl": "0",
            "pk": self.public_key.hex(),
        }
        txt.update(self.extra_txt)
        return {k.encode(): v.encode() for k, v in txt.items()}


class Advertiser:
    """Registers (and unregisters) the AirPlay service with Zeroconf."""

    def __init__(self, info: ReceiverInfo, address: str | None = None) -> None:
        self.info = info
        self._address = address
        self._zc = None
        self._service = None

    async def start(self) -> None:
        from zeroconf import ServiceInfo
        from zeroconf.asyncio import AsyncZeroconf

        addr = self._address or _primary_ipv4()
        self._zc = AsyncZeroconf()
        self._service = ServiceInfo(
            "_airplay._tcp.local.",
            f"{self.info.name}._airplay._tcp.local.",
            addresses=[socket.inet_aton(addr)],
            port=self.info.port,
            properties=self.info.txt_records(),
            server=f"{self.info.name.replace(' ', '-')}.local.",
        )
        # allow_name_change avoids a crash when a stale registration of the same name is
        # still cached on the network (e.g. after an unclean previous exit); zeroconf
        # appends a suffix instead. We always send the goodbye in stop() so clean exits
        # don't leave a stale entry behind in the first place.
        await self._zc.async_register_service(self._service, allow_name_change=True)

    async def stop(self) -> None:
        if self._zc is not None:
            try:
                if self._service is not None:
                    await self._zc.async_unregister_service(self._service)
            finally:
                await self._zc.async_close()
                self._zc = None


def _primary_ipv4() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no packets sent; just picks the egress NIC
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()
