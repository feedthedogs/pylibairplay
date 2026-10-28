import os
from pylibairplay.rtsp.secure import SecureChannel


def test_two_channels_interop():
    k1, k2 = os.urandom(32), os.urandom(32)
    # Alice writes with k1, reads with k2; Bob mirrors.
    alice = SecureChannel(read_key=k2, write_key=k1)
    bob = SecureChannel(read_key=k1, write_key=k2)
    msg = b"RTSP/1.0 200 OK\r\n\r\n" * 10
    assert b"".join(bob.feed(alice.encrypt(msg))) == msg
    # counters advance: second message still decrypts
    assert b"".join(bob.feed(alice.encrypt(b"second"))) == b"second"


def test_partial_frame_buffering():
    k1, k2 = os.urandom(32), os.urandom(32)
    a = SecureChannel(read_key=k2, write_key=k1)
    b = SecureChannel(read_key=k1, write_key=k2)
    framed = a.encrypt(b"hello world")
    assert b.feed(framed[:5]) == []          # not enough yet
    assert b"".join(b.feed(framed[5:])) == b"hello world"
