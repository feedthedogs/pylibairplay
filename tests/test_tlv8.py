from pylibairplay.pairing import tlv8
from pylibairplay.pairing.tlv8 import Tag


def test_roundtrip_simple():
    items = {Tag.STATE: b"\x01", Tag.IDENTIFIER: b"ABCD"}
    assert tlv8.decode(tlv8.encode(items)) == items


def test_long_value_is_fragmented_and_rejoined():
    value = bytes(range(256)) * 3  # 768 bytes -> 4 fragments
    enc = tlv8.encode({Tag.PUBLIC_KEY: value})
    # Each fragment header caps at 255; expect the value split across fragments.
    assert enc.count(bytes((Tag.PUBLIC_KEY, 255))) == 3
    assert tlv8.decode(enc)[Tag.PUBLIC_KEY] == value


def test_separator_breaks_a_run():
    data = tlv8.encode([(Tag.IDENTIFIER, b"AA"), (Tag.SEPARATOR, b""), (Tag.IDENTIFIER, b"BB")])
    ordered = tlv8.decode_ordered(data)
    assert ordered == [(Tag.IDENTIFIER, b"AA"), (Tag.SEPARATOR, b""), (Tag.IDENTIFIER, b"BB")]


def test_zero_length_item():
    assert tlv8.decode(tlv8.encode({Tag.ERROR: b""})) == {Tag.ERROR: b""}
