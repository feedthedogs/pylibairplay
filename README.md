# pylibairplay

An AirPlay **screen-mirroring receiver** in pure Python.
No GStreamer, no external receiver app, no C build step. It advertises itself over mDNS,
pairs with an iPhone or iPad, decrypts the mirror stream and hands your code H.264 access
units to decode however you like.

```python
import asyncio
from pylibairplay import Receiver

async def main():
    rx = Receiver(name="My Screen")
    rx.on_video = lambda au: ...   # au.data: Annex-B bytes; au.codec, au.pts, au.keyframe
    rx.on_session = lambda info: print("connected:", info.device_name, info.width, info.height)
    rx.on_end = lambda reason: print("ended:", reason)
    await rx.serve()

asyncio.run(main())
```

`au.data` is an Annex-B H.264 access unit (SPS/PPS prepended on keyframes), ready for any
decoder such as PyAV.

## Install

```sh
uv add "pylibairplay[net]"      # or: pip install "pylibairplay[net]"
```

The `net` extra pulls in `zeroconf` (mDNS) and `cryptography`. Decoding is left to you, which
keeps the core dependency-light. To mirror from a modern iPhone with route B below, also add the
`fairplay` extra (`unicorn`, `lief`, `capstone`): `pylibairplay[net,fairplay]`.

## Authentication: pick a route

Modern iOS only mirrors to a receiver that can prove it is licensed. pylibairplay supports two
ways to satisfy that, and which one you use is the main decision when adopting the library.

| | **A. Your own MFi certificate** | **B. FairPlay emulation** |
|---|---|---|
| Protocol | AirPlay 2 (transient / PIN pairing) | Legacy AirPlay 1 `/fp-setup` |
| You supply | An Apple MFi certificate **and** a way to sign with its key | Apple FairPlay binaries extracted from firmware **you** obtained |
| Redistributable | Yes — nothing Apple-owned ships | No — machine-local interop tooling |
| Startup | Instant | ~35 s emulator warm-up |
| Status | Implemented, **not yet validated on a device** | Working end-to-end on iOS 26 |

### A. MFi certificate

If you are a licensed MFi developer, hand the receiver your certificate and a signer:

```python
from pylibairplay import MFiCredentials, Receiver

creds = MFiCredentials.from_pem_files("mfi_cert.pem", "mfi_key.pem")   # RSA-1024 or EC key
# or, if the key lives in an authentication chip / HSM:
creds = MFiCredentials(certificate=cert_der, sign=lambda challenge: chip.sign(challenge))

rx = Receiver(name="My Screen", mfi=creds)
```

From the command line: `python -m pylibairplay.receiver --mfi-cert cert.pem --mfi-key key.pem`.
pylibairplay does not provide or generate certificates.

### B. FairPlay emulation

FairPlay is a whitebox that can't be reimplemented in portable code, so this route runs Apple's own code from
**your own device firmware** under a local emulator. Nothing from Apple is shipped or committed.

```sh
# Extract the four dylibs for your device model with ipsw (https://github.com/blacktop/ipsw):
ipsw download ipsw --device <your-model> --latest
ipsw extract --dyld --dyld-arch arm64e <ipsw file> -o fw
ipsw dyld extract fw/*/dyld_shared_cache_arm64e -o fpdir \
    AirPlayReceiver AirPlaySupport CoreUtils AirPlaySender

# The emulator ships with the package; the `fairplay` extra installs what it needs
# (unicorn, lief, capstone).
uv run --extra net --extra fairplay python examples/dump_frames.py --name "Test Screen" \
    --fp-emu-dir fpdir --save-frame frame.png
```

```python
Receiver(name="My Screen", legacy=True, fp_emu_dir="fpdir")
# fp_emu_python="<interpreter>" runs the emulator under a different Python
```

On the phone: **Control Centre → Screen Mirroring → your receiver's name** (PIN `3939` if
asked). After the emulator warms up, `frame.png` tracks the phone screen.

## Scope

- **Done:** discovery, pairing (transient and PIN), screen-mirroring video (H.264 access
  units), FairPlay-gated SETUP and stream decryption, optional MFi proof at pair-setup.
- **Not done:** mirrored audio (dropped), HLS video casting, AirPlay 2 multi-room.

## Development

```sh
uv run --extra net pytest
```

The scripts under `tools/re/` run Ghidra against a firmware image you supply; their output is
never committed.

## License

See [`LICENSE`](LICENSE).
