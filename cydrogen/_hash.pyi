from collections.abc import Buffer
from os import PathLike
from typing import BinaryIO, Self

from ._basekey import BaseKey
from ._context import Context

class HashKey(BaseKey):
    def __init__(self, key: str | bytes | BaseKey | Self | Buffer | None = None): ...
    def __eq__(self, other: object) -> bool: ...
    def __repr__(self): ...
    def hasher(self, data: bytes | Buffer | None = None, ctx: Context | str | bytes | Buffer | None = None, digest_size: int = ...): ...

class Hash:
    ctx: Context
    key: HashKey
    digest_size: int
    block_size: int

    def __init__(
        self,
        data: bytes | Buffer | None = None,
        *,
        ctx: str | bytes | Context | Buffer | None = None,
        digest_size: int = 16,
        key: str | bytes | BaseKey | HashKey | Buffer | None = None,
    ): ...
    def update(self, data: bytes | Buffer) -> None: ...
    def write(self, data: bytes | Buffer) -> int: ...
    def update_from(self, fileobj: str | PathLike | BinaryIO, chunk_size: int = ...): ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...

def hash_file(
    fileobj: str | PathLike | BinaryIO,
    ctx: str | bytes | Context | Buffer | None = None,
    digest_size: int = 16,
    key: str | bytes | BaseKey | HashKey | Buffer | None = None,
    chunk_size: int = ...,
): ...
