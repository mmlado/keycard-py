from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class CardInterface(Protocol):
    '''
    Abstract base class representing a Keycard interface for command functions.
    '''
    card_public_key: Optional[bytes] = None

    @property
    def is_initialized(self) -> bool:
        '''
        Returns True if the card is initialized, False otherwise.
        '''
        pass

    @property
    def is_secure_channel_open(self) -> bool:
        '''
        Returns True if a secure channel is open, False otherwise.
        '''
        pass

    @property
    def is_pin_verified(self) -> bool:
        '''
        Returns True if the PIN is verified, False otherwise.
        '''
        pass

    @property
    def is_selected(self) -> bool:
        '''
        Returns True if the card is selected, False otherwise.
        '''
        pass

    def send_apdu(
        self,
        ins: int,
        p1: int = 0x00,
        p2: int = 0x00,
        data: bytes = b'',
        cla: Optional[int] = None
    ) -> bytes:
        '''
        Send an APDU command to the card.
        Raises APDUError on failure.
        '''
        pass

    def send_secure_apdu(
        self,
        ins: int,
        p1: int = 0x00,
        p2: int = 0x00,
        data: bytes = b''
    ) -> bytes:
        '''
        Send a secure APDU to the card.
        Raises APDUError on failure.
        '''
        pass
