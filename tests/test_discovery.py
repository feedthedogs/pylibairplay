from pylibairplay.discovery import ReceiverInfo


def test_txt_records_shape():
    info = ReceiverInfo(name="AI Screen", device_id="AA:BB:CC:DD:EE:FF",
                        public_key=bytes(range(32)), port=7000)
    txt = info.txt_records()
    assert txt[b"deviceid"] == b"AA:BB:CC:DD:EE:FF"
    assert txt[b"pk"] == bytes(range(32)).hex().encode()
    assert b"," in txt[b"features"]  # two-part hex
    assert txt[b"model"] == b"AppleTV3,2"
