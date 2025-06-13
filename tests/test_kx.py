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


def test_keys_equality():
    pk1 = cydrogen.KxPublicKey(PUBLIC_BYTES)
    sk1 = cydrogen.KxSecretKey(PRIVATE_BYTES)
    kp = cydrogen.KxPair(PAIR_BYTES)
    assert pk1 == kp.public_key()
    assert sk1 == kp.secret_key()

    kp2 = cydrogen.KxPair.gen()
    assert pk1 != kp2.public_key()
    assert sk1 != kp2.secret_key()

    kp3 = cydrogen.KxPair.from_keys(pk1, sk1)
    assert kp3 == kp


def test_create_zero_key():
    with pytest.raises(TypeError):
        cydrogen.KxPair()
    with pytest.raises(ValueError):
        cydrogen.KxPair(None)
    with pytest.raises(ValueError):
        cydrogen.KxPair(b"")


def test_kx_n():
    pair = cydrogen.KxPair(PAIR_BYTES)
    session, pkt = cydrogen.client_init_kx_n(pair.public_key())
    session_peer = cydrogen.server_finish_kx_n(pair, pkt)
    assert session.rx == session_peer.tx
    assert session.tx == session_peer.rx


def test_kx_kk() -> None:
    client_pair: cydrogen.KxPair = cydrogen.KxPair.gen()
    server_pair: cydrogen.KxPair = cydrogen.KxPair.gen()
    s = client_pair.client_init_kx_kk(server_pair.public_key())
    server_session_pair, packet2 = server_pair.server_process_kx_kk(client_pair.public_key(), s.packet1)
    client_session_pair = s.client_finish_kx_kk(packet2)
    assert client_session_pair.rx == server_session_pair.tx
    assert client_session_pair.tx == server_session_pair.rx
