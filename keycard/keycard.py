"""
This module provides the KeyCard class, which implements an interface for
interacting with Keycard-compliant smart cards.
"""
from typing import Optional


from . import commands
from .parsing.identity import Identity
from .parsing.application_info import ApplicationInfo
from .secure_channel import SecureSession
from .transport import Transport


class KeyCard:
    """
    Represents a Keycard smart card interface.

    This class provides methods to interact with a Keycard-compliant smart
    card.

    Attributes:
        transport (Transport): The transport interface used to communicate
            with the smart card.
    """
    def __init__(self, transport: Transport) -> None:
        if not transport:
            raise ValueError("Transport not initialized")

        self.transport: Transport = transport
        self._card_public_key: Optional[bytes] = None
        self.secure_session: Optional[SecureSession] = None

    def select(self) -> ApplicationInfo:
        info = commands.select(self.transport)
        self._card_public_key = info.ecc_public_key
        return info

    def init(self, pin: bytes, puk: bytes, pairing_secret: bytes) -> None:
        commands.init(
            self.transport,
            self._card_public_key,
            pin,
            puk,
            pairing_secret
        )

    def ident(self, challenge: bytes) -> Identity:
        return commands.ident(self.transport, challenge)

    def open_secure_channel(
        self,
        pairing_index: int,
        pairing_key: bytes
    ) -> None:
        self.secure_session = commands.open_secure_channel(
            self.transport,
            self._card_public_key,
            pairing_index,
            pairing_key
        )

    def mutually_authenticate(self) -> None:
        commands.mutually_authenticate(self.transport, self.secure_session)

    def pair(self, shared_secret: bytes) -> tuple[int, bytes]:
        return commands.pair(self.transport, shared_secret)

    def verify_pin(self, pin: str) -> bool:
        commands.verify_pin(self.transport, self.secure_session, pin)

    def unpair(self, index: int) -> None:
        commands.unpair(
            transport=self.transport,
            session=self.secure_session,
            index=index
        )
