"""AirPlay control-channel message framing (RTSP/HTTP-1.1 hybrid).

AirPlay's control connection speaks an RTSP-shaped message: a request line
``<METHOD> <URI> RTSP/1.0`` (or ``HTTP/1.1``), CRLF headers, and a body sized by
``Content-Length``. Responses mirror it with a status line and ``CSeq`` echoed back.
After pair-setup/verify, each message is wrapped in the encrypted framing from
``rtsp/secure.py``; this module handles only the plaintext message structure.

Parsing is incremental so it can sit behind a stream (raw socket, or the decrypted
output of a SecureChannel).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Request:
    method: str
    uri: str
    protocol: str
    headers: dict[str, str]
    body: bytes

    @property
    def cseq(self) -> str | None:
        return self.headers.get("cseq")

    @property
    def content_type(self) -> str | None:
        return self.headers.get("content-type")


@dataclass
class Response:
    status: int = 200
    reason: str = "OK"
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    protocol: str = "RTSP/1.0"

    def encode(self, cseq: str | None = None) -> bytes:
        headers = dict(self.headers)
        if cseq is not None and "CSeq" not in headers:
            headers["CSeq"] = cseq
        if self.body and "Content-Length" not in headers:
            headers["Content-Length"] = str(len(self.body))
        head = f"{self.protocol} {self.status} {self.reason}\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        return head.encode("utf-8") + b"\r\n" + self.body


class MessageParser:
    """Incremental parser yielding complete :class:`Request` objects."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[Request]:
        self._buf += data
        out: list[Request] = []
        while True:
            req = self._try_one()
            if req is None:
                return out
            out.append(req)

    def _try_one(self) -> Request | None:
        sep = self._buf.find(b"\r\n\r\n")
        if sep == -1:
            return None
        head = bytes(self._buf[:sep]).decode("utf-8", "replace")
        lines = head.split("\r\n")
        method, uri, protocol = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        length = int(headers.get("content-length", "0"))
        body_start = sep + 4
        if len(self._buf) < body_start + length:
            return None  # await full body
        body = bytes(self._buf[body_start : body_start + length])
        del self._buf[: body_start + length]
        return Request(method, uri, protocol, headers, body)
