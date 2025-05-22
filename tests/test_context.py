import cydrogen


def test_create_empty_context():
    ctx = cydrogen.Context()
    assert ctx.is_empty()
    assert not bool(ctx)
    assert len(bytes(ctx)) == 8
    assert bytes(ctx) == 8 * b" "
    assert str(ctx) == 8 * " "


def test_create_context():
    ctx = cydrogen.Context(b"EXAMPLES")
    ctx2 = cydrogen.Context("EXAMPLES")
    assert ctx == ctx2
    assert bytes(ctx) == b"EXAMPLES"
    assert str(ctx) == "EXAMPLES"


def test_copy_context():
    ctx1 = cydrogen.Context(b"EXAMPLES")
    ctx2 = cydrogen.Context(ctx1)
    assert ctx1 == ctx2
