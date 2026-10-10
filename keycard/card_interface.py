from typing import Optional, Protocol, runtime_checkable

from .apdu import APDUResponse
from .pairing import Pairing


@runtime_checkable
class CardInterface(Protocol):
    '''
    Abstract base class representing a Keycard interface for command functions.
    '''
    card_public_key: Optional[bytes]
    pairing: Optional[Pairing]
    ca_public_keys: list[bytes]
    trusted_identity_keys: list[bytes]

    @property
    def is_initialized(self) -> bool: ...

    @property
    def is_secure_channel_open(self) -> bool: ...

    @property
    def is_pin_verified(self) -> bool: ...

    @property
    def is_selected(self) -> bool: ...

    @property
    def version(self) -> tuple[int, int]: ...

    @property
    def identity_certificate(self) -> Optional[bytes]: ...

    def open_secure_channel(self) -> None: ...

    def send_raw_apdu(self, apdu: bytes) -> APDUResponse: ...

    def send_apdu(
        self,
        ins: int,
        p1: int = 0x00,
        p2: int = 0x00,
        data: bytes = b'',
        cla: Optional[int] = None
    ) -> bytes: ...

    def send_secure_apdu(
        self,
        ins: int,
        p1: int = 0x00,
        p2: int = 0x00,
        data: bytes = b''
    ) -> bytes: ...
