import cydrogen


def test_create_zero_master_key():
    key = cydrogen.MasterKey()
    assert bytes(key) == 32 * b"\x00"
    assert key.is_zero()
    assert not bool(key)
