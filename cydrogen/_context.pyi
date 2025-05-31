from collections.abc import Buffer
from typing import Self

class Context:
    """
    A context is composed of exactly 8 bytes and is used to separate different domains in the library.

    Multiple features of this library require a context. Contexts help to avoid mistakes by separating different domains.
    The same crypto feature working in different contexts will produce different results.

    A context must be a valid ASCII string, and it must be exactly 8 bytes long (it is padded with spaces if shorter).

    A context is not a secret.

    Context implements the buffer protocol, acting as a bytes-like object of length 8.

    Examples:
        >>> ctx = Context("domain1")                            # from ascii string
        >>> ctx2 = Context(b"another")                          # from bytes
        >>> ctx3 = Context(ctx)                                 # from another context
        >>> empty_ctx = Context()                               # creates an empty context (8 spaces)
        >>> assert(Context("short") == Context("short   "))     # shorter strings are padded with spaces
    """
    def __init__(self, ctx: str | bytes | Self | Buffer | None = None):
        """
        Initializes a new context.

        Args:
            ctx: The context to use. If None, an empty context (8 spaces) is created.

        Raises:
            ValueError: If the passed context is too long or not a valid ASCII string.
        """
        ...

    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def __eq__(self, other: object) -> bool: ...
    def __bool__(self) -> bool: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...
    def is_empty(self) -> bool:
        """
        Checks if the context is empty.

        Returns:
            True if the context is empty (8 spaces), False otherwise.
        """
        ...

    @classmethod
    def empty(cls) -> Self:
        """
        Returns an empty context, which is a context of 8 spaces.

        Returns:
            An empty context (8 spaces).
        """
        ...
