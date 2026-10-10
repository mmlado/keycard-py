from enum import IntEnum
from typing import Protocol

from ..apdu import APDUResponse


class SecureChannelVersion(IntEnum):
    V1 = 1
    V2 = 2


def channel_version(app_version: tuple[int, int]) -> SecureChannelVersion:
    """
    Returns the secure channel version used by an applet version.

    Args:
        app_version (tuple[int, int]): Applet major and minor version.

    Returns:
        SecureChannelVersion: V2 from applet 4.0, V1 before.
    """
    if app_version >= (4, 0):
        return SecureChannelVersion.V2
    return SecureChannelVersion.V1


class SecureChannel(Protocol):
    """An open encrypted session with the card."""

    @property
    def version(self) -> SecureChannelVersion: ...

    @property
    def is_open(self) -> bool: ...

    def wrap(self, ins: int, p1: int, p2: int, data: bytes) -> bytes:
        """
        Protects a command for sending.

        Returns:
            bytes: The complete command APDU.
        """
        ...

    def unwrap(self, response: APDUResponse) -> bytes:
        """
        Verifies and decrypts a response.

        Returns:
            bytes: The response data.

        Raises:
            APDUError: If the card returned a failure status word.
        """
        ...
