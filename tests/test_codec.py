from pylibairplay.codec import avcc_to_annexb, avcc_config_to_annexb, annexb_nalus, START_CODE


def test_avcc_to_annexb_two_nals():
    nal1, nal2 = b"\x67\xAA\xBB", b"\x68\xCC"
    avcc = len(nal1).to_bytes(4, "big") + nal1 + len(nal2).to_bytes(4, "big") + nal2
    out = avcc_to_annexb(avcc)
    assert out == START_CODE + nal1 + START_CODE + nal2


def test_avcc_to_annexb_stops_on_bad_length():
    avcc = (999).to_bytes(4, "big") + b"\x67\xAA"  # claims 999 bytes, only 2 present
    assert avcc_to_annexb(avcc) == b""


def test_avcc_config_parsed():
    sps, pps = b"\x67\x42\x00\x0a", b"\x68\xce"
    cfg = bytes([1, 0x42, 0x00, 0x0A, 0xFF, 0xE1]) + len(sps).to_bytes(2, "big") + sps
    cfg += bytes([1]) + len(pps).to_bytes(2, "big") + pps
    annexb, length_size = avcc_config_to_annexb(cfg)
    assert length_size == 4
    assert annexb == START_CODE + sps + START_CODE + pps
    assert list(annexb_nalus(annexb)) == [sps, pps]
