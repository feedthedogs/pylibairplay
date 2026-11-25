# pylibairplay

An AirPlay **screen-mirroring receiver** in pure Python.
No GStreamer, no external receiver app, no C build step, no firmware extraction. It advertises itself over mDNS,
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
keeps the core dependency-light. FairPlay is handled in pure Python with no additional dependencies.

## Quick start

```sh
uv run --extra net python examples/dump_frames.py --name "Test Screen" --save-frame frame.png
```

On the phone: **Control Centre → Screen Mirroring → "Test Screen"** (PIN `3939` if asked).
`frame.png` tracks the phone screen.

## Scope

- **Done:** discovery, pairing (transient and PIN), screen-mirroring video (H.264 access
  units), FairPlay-gated SETUP and stream decryption (pure Python).
- **Not done:** mirrored audio (dropped), HLS video casting, AirPlay 2 multi-room.

## Development

```sh
uv run --extra net pytest
```

## License

See [`LICENSE`](LICENSE).
