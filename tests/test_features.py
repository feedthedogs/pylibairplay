from pylibairplay.features import Feature, format_features, parse_features


def test_roundtrip_two_part_hex():
    v = int(Feature.SCREEN | Feature.SUPPORTS_TRANSIENT_PAIRING | Feature.VIDEO)
    assert parse_features(format_features(v)) == v


def test_parse_known_form():
    # low half has bit 0 (VIDEO) and bit 7 (SCREEN); high half has bit 48-32=16
    v = parse_features("0x81,0x10000")
    assert v & Feature.VIDEO and v & Feature.SCREEN
    assert v & Feature.SUPPORTS_TRANSIENT_PAIRING


def test_single_value():
    assert parse_features("0x89") == 0x89
