"""
This module provides the KeyCard class, which implements an interface for
interacting with Keycard-compliant smart cards.
"""
from typing import Optional

from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, SHA512

from ecdsa import SigningKey, SECP256k1


from . import constants
from .apdu import APDUResponse
from . import commands
from .crypto.ecc import (
    derive_shared_secret,
)
from .exceptions import (
    APDUError,
    InvalidResponseError,
    NotSelectedError
)
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
        """
        Selects the Keycard application on the smart card and retrieves
        application information.

        Sends a SELECT APDU command using the Keycard AID, checks for a
        successful response, parses the returned application information, and
        stores the card's public key.

        Returns:
            ApplicationInfo: Parsed information about the selected application.
        Return type:
            ApplicationInfo

        Raises:
            APDUError: If the card returns a status word indicating failure.
        """
        
        info = commands.select(self.transport)
        self._card_public_key = info.ecc_public_key


    def init(self, pin: bytes, puk: bytes, pairing_secret: bytes) -> None:
        commands.init(
            self.transport, 
            self._card_public_key, 
            pin, 
            puk, 
            pairing_secret
        )

    def ident(self, challenge: bytes) -> Identity:
        """
        Sends an identification challenge to the card and returns the parsed
        card identity.

        Args:
            challenge (bytes): A byte sequence representing the challenge to
                send to the card.

        Returns:
            Identity: The parsed identity information returned by the card.

        Raises:
            APDUError: If the card responds with a status word other than
                0x9000.
        """
        apdu = (
            bytes([
                constants.CLA_PROPRIETARY,
                constants.INS_IDENT,
                0x00,
                0x00,
                len(challenge)
            ]) + challenge
        )
        response = self.transport.send_apdu(apdu)

        if response.status_word != 0x9000:
            raise APDUError(response.status_word)

        return Identity.parse(bytes(response.data))

    def open_secure_channel(
        self,
        pairing_index: int,
        pairing_key: bytes
    ) -> None:
        """
        Establishes a secure communication channel with the card using an
        ephemeral ECDH key exchange.

        Args:
            pairing_index (int): The index of the pairing to use for the
                secure channel.
            pairing_key (bytes): The secret key associated with the pairing
                index.

        Raises:
            NotSelectedError: If the card is not selected or the public
                key is missing.
        """
        self.secure_session = commands.open_secure_channel(self.transport, self._card_public_key, pairing_index, pairing_key)

    def mutually_authenticate(self) -> None:
        commands.mutually_authenticate(self.transport, self.secure_session)

    def pair(self, shared_secret: bytes) -> tuple[int, bytes]:
        return commands.pair(self.transport, shared_secret)

    def verify_pin(self, pin: str) -> bool:
        commands.verify_pin(self.transport, self.secure_session, pin)

    def unpair(self, index: int) -> None:
        """
        Unpairs a device or key at the specified index.

        This method removes the pairing information for the device or key
        identified by the given index. It requires that a secure channel
        is established and authenticated before proceeding.

        Args:
            index (int): The index of the device or key to unpair.

        Raises:
            InvalidResponseError: If the secure channel is not established
                or not authenticated.
        """
        if not self.secure_session or not self.secure_channel_authenticated:
            raise InvalidResponseError(
                "Secure channel not established or not authenticated")

        commands.unpair(
            transport=self.transport,
            session=self.secure_session,
            index=index
        )
