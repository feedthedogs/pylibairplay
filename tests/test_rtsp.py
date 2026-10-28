from pylibairplay.rtsp.server import MessageParser, Response


def test_parse_request_with_body():
    p = MessageParser()
    raw = b"POST /pair-setup RTSP/1.0\r\nCSeq: 3\r\nContent-Length: 4\r\nContent-Type: application/octet-stream\r\n\r\nABCD"
    reqs = p.feed(raw)
    assert len(reqs) == 1
    r = reqs[0]
    assert r.method == "POST" and r.uri == "/pair-setup" and r.cseq == "3"
    assert r.body == b"ABCD"


def test_parse_split_across_feeds():
    p = MessageParser()
    assert p.feed(b"GET /info RTSP/1.0\r\nCSeq: 1\r\n") == []
    reqs = p.feed(b"Content-Length: 0\r\n\r\n")
    assert len(reqs) == 1 and reqs[0].uri == "/info"


def test_response_encode_echoes_cseq():
    out = Response(200, "OK", body=b"xx").encode(cseq="7")
    assert out.startswith(b"RTSP/1.0 200 OK\r\n")
    assert b"CSeq: 7\r\n" in out and b"Content-Length: 2\r\n" in out and out.endswith(b"\r\nxx")
