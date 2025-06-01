from collections.abc import Buffer

from ._basekey import BaseKey
from ._context import Context
from ._sign import SignKeyPair

class MasterKey(BaseKey):
    """
    A MasterKey can be used to derive subkeys, derive a key from a password, or hash passwords for storage.
    """
    def __init__(self, key: str | bytes | MasterKey | BaseKey | Buffer | None = None):
        """
        Initialize a MasterKey.

        Args:
            key: A bytes-like object, a base64 encoded string, or another MasterKey. If None, initializes a zero MasterKey.

        Raises:
            TypeError: If the key is of an unsupported type.
            ValueError: If the key is empty or invalid.
        """
        ...

    def derive_key_from_password(
        self, password: bytes | Buffer, ctx: bytes | str | Context | Buffer | None = None, opslimit: int = 10000
    ) -> BaseKey:
        """
        Derive a high entropy key from a password, using the master key.

        The derived key is returned as a BaseKey. You can then convert the derived key to a specific key type if needed.

        Args:
            password: The password to derive the key from.
            ctx: Optional context for the derivation.
            opslimit: The number of operations limit for the derivation.

        Returns:
            The derived key as a BaseKey.

        Raises:
            ValueError: If the password is None or empty.
            DeriveException: If the derivation fails.
        """
        ...

    def derive_key_from_password_with_length(
        self, password: bytes | Buffer, length: int = 32, ctx: bytes | str | Context | Buffer | None = None, opslimit: int = 10000
    ) -> bytes:
        """
        Derive a high entropy key from a password using the master key.

        You can choose the length of the derived key. It is returned as bytes.

        Args:
            password: The password to derive the key from.
            length: The length of the derived key in bytes (default is 32).
            ctx: Optional context for the derivation.
            opslimit: The number of operations limit for the derivation.

        Returns:
            The derived key as bytes.

        Raises:
            ValueError: If the password is None, empty, or if length is 0.
            DeriveException: If the derivation fails.
        """
        ...

    def derive_subkey(self, subkey_id: int, ctx: bytes | str | Context | Buffer | None = None) -> BaseKey:
        """
        Derive a subkey from the master key using the subkey_id.

        The derived key is returned as a BaseKey. You can then convert the derived key to a specific key type if needed.

        Args:
            subkey_id: The identifier for the subkey to derive.
            ctx: Optional context for the derivation.

        Returns:
            The derived subkey as a BaseKey.

        Raises:
            ValueError: If the master key is zero.
            DeriveException: If the derivation fails.
        """
        ...

    def derive_subkey_with_length(self, subkey_id: int, length: int = 32, ctx: bytes | str | Context | Buffer | None = None) -> bytes:
        """
        Derive a subkey from the master key using the subkey_id.

        You can choose the length of the derived subkey. It is returned as bytes.

        Args:
            subkey_id: The identifier for the subkey to derive.
            length: The length of the derived subkey in bytes (default is 32).
            ctx: Optional context for the derivation.

        Returns:
            The derived subkey as bytes.

        Raises:
            ValueError: If the master key is zero, or if length is not in the valid range (16 to 65535).
            DeriveException: If the derivation fails.
        """
        ...

    def derive_sign_keypair(self) -> SignKeyPair:
        """
        Derive a sign keypair from the master key.

        Returns:
            A SignKeyPair derived from the master key.
        """
        ...

    def hash_password(self, password: bytes | Buffer, opslimit: int = 10000) -> bytes:
        """
        Returns a representation of the password suitable for storage.

        This method hashes the password using the master key and returns a 128 byte long bytes.

        Args:
            password: The password to hash.
            opslimit: The number of operations limit for the hashing.

        Returns:
            A bytes object containing the hashed password (128 bytes).

        Raises:
            ValueError: If the password is None or empty.
            DeriveException: If the hashing fails.
        """
        ...

    def verify_password(self, password: bytes | Buffer, stored: bytes | Buffer, opslimit: int = 10000) -> bool:
        """
        Verify a password against a stored hash.

        The stored hash should have been previously created using the `hash_password` method.

        Args:
            password: The password to verify.
            stored: The stored hash to verify against (should be 128 bytes long).
            opslimit: The number of operations limit for the verification.

        Returns:
            True if the password matches the stored hash, False otherwise.

        Raises:
            ValueError: If the password or stored hash is None, empty, or if the stored hash is not 128 bytes long.
        """
        ...

    def __eq__(self, other: object) -> bool: ...
    def __repr__(self) -> str: ...
