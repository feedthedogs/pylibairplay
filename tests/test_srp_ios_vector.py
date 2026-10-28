"""iOS-26 AirPlay transient SRP regression vector.

Captured from the cidermill-airplay IOS26 transient controller (a known-good
AirPlay-2 implementation) used purely as a black-box oracle; the values below are
observed protocol data, not copied code. Guards the AirPlay-specific SRP
convention (k uses PADDED g; the proof's H(g) uses minimal g), which differs from
HomeKit/pysrp and was the cause of every real-iPhone pair-setup proof mismatch.
"""
from pylibairplay.pairing.srp import SrpServer

# A real iOS-26-style transient pair-setup exchange (username "Pair-Setup", PIN 3939).
SALT = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
B_PRIV = int("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16)
CLIENT_A = bytes.fromhex("4604fbb8f303a06155d5de3fa55fb4167ee435e91f38e38629b83d600293eae22d2d723f69f2fa442f759efaa82d3eae15815d40cc21767efdfc3e857b078fa8e8f776596b7b407d025d5ac0f29562920d69d83613ddf27bfb7d3dc45aff30ad16768674104f1c5c89ec4f5377199df9f30942aab88338a7249085957988c7ab2cff0d9d751e91793fd54eb04d65545c849cdaf2e245729ba007560570445adb56365f12643a437996e3afb3a57f865ab9aae72793bed05d8ff2c767b6269b2bec480c5acc3bd4fbb07299b537be6aea118993052a4d37b6f66d2eaec13633e3368ff532f30ab216696562cadf1842d32fc01172d082d383b76b63422fcf289bf7464b4e27466739f59b3f9c7ab084c308c63399927ac4f31b916786d51736797effda418236cbeb41ac6c924ec9cce86de35540d548f7825321d7d499bc998c7041032594a2671162be5695e4213fd88fd05aa94dbc7607ffd07ebd37a03a6629faf76373d44041144b68f463ac68760132b45ea51998b9e87779d393df0faf")
CLIENT_PROOF = bytes.fromhex("92fbb1184814ed62f4aad43c0c42c560a53ce35e68b20fbcfad610cc08aa32308453ca16b7f4af54bfc17e88fd8aecfd9cc771f491c8862a9266b93c4ce5d5cc")
SESSION_KEY = bytes.fromhex("36dc624bc909d509d7b07dfcc5cf95250d42a6aa9ac35ef32342b49939a7c58a1c6edc44ed39b55018d27455dbca749d54fed67e6ae98b726532dbd008cdec62")


def test_ios26_transient_vector():
    srv = SrpServer(b"Pair-Setup", b"3939", salt=SALT, b=B_PRIV)
    srv.set_A(CLIENT_A)
    m2 = srv.verify(CLIENT_PROOF)  # raises if our SRP rejects the iOS-style proof
    assert srv.session_key == SESSION_KEY
    assert len(m2) == 64
