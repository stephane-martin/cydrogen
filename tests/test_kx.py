import pytest

import cydrogen

PAIR_BYTES = b"\x82P\xef\x19f\x18p\x82\xd4WU$q\xd35\xe3]-<P\xb0?w\x19\xfa9\x8f\x0c)A\xd9Q\xa7\x97\xa8\xa9\xcd\x11\xc7\x99\xb3X\xaf\x9a\xccQTNx\x12\xd1a\xc3\xcb\xd5\xb4P\xf2\xe2+1\xf5R3"
PUBLIC_BYTES = b"\x82P\xef\x19f\x18p\x82\xd4WU$q\xd35\xe3]-<P\xb0?w\x19\xfa9\x8f\x0c)A\xd9Q"
PRIVATE_BYTES = b"\xa7\x97\xa8\xa9\xcd\x11\xc7\x99\xb3X\xaf\x9a\xccQTNx\x12\xd1a\xc3\xcb\xd5\xb4P\xf2\xe2+1\xf5R3"


def test_gen_kx_pair():
    pair = cydrogen.KxPair.gen()
    assert bool(pair)
    assert len(pair) == 64


def test_create_kx_pair_from_bytes():
    pair = cydrogen.KxPair(PAIR_BYTES)
    assert bytes(pair) == PAIR_BYTES
    assert bool(pair)
    assert bytes(pair.public_key()) == PUBLIC_BYTES
    assert bytes(pair.secret_key()) == PRIVATE_BYTES


def test_create_zero_key():
    with pytest.raises(TypeError):
        cydrogen.KxPair()
    with pytest.raises(ValueError):
        cydrogen.KxPair(None)
    with pytest.raises(ValueError):
        cydrogen.KxPair(b"")


def test_kx_n():
    pair = cydrogen.KxPair(PAIR_BYTES)
    session, pkt = cydrogen.kx_n_gen_session_and_packet(pair.public_key())
    session_peer = cydrogen.kx_n_gen_session_from_packet(pair, pkt)
    assert session.rx == session_peer.tx
    assert session.tx == session_peer.rx
