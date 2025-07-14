from . import commands
from .transport import Transport


class KeyCard:
    """
    High-level interface for interacting with a Keycard device.

    This class provides convenient methods to manage pairing, secure channels,
    and card operations.
    """

    def __init__(self, transport: Transport):
        """
        Initializes the KeyCard interface.

        Args:
            transport (Transport): Instance used for APDU communication.

        Raises:
            ValueError: If transport is None.
        """
        if not transport:
            raise ValueError("Transport not initialized")

        self.transport = transport
        self._card_public_key = None
        self.secure_session = None

    def select(self):
        """
        Selects the Keycard applet and retrieves application metadata.

        Returns:
            ApplicationInfo: Object containing ECC public key and card info.
        """
        info = commands.select(self.transport)
        self._card_public_key = info.ecc_public_key
        return info

    def init(self, pin: bytes, puk: bytes, pairing_secret: bytes):
        """
        Initializes the card with security credentials.

        Args:
            pin (bytes): The PIN code in bytes.
            puk (bytes): The PUK code in bytes.
            pairing_secret (bytes): The shared secret for pairing.
        """
        commands.init(
            self.transport,
            self._card_public_key,
            pin,
            puk,
            pairing_secret,
        )

    def ident(self, challenge: bytes) -> bytes:
        """
        Sends an identity challenge to the card.

        Args:
            challenge (bytes): Challenge data to sign.

        Returns:
            bytes: Response data (e.g., signature or proof).
        """
        return commands.ident(self.transport, challenge)

    def open_secure_channel(self, pairing_index: int, pairing_key: bytes):
        """
        Opens a secure session with the card.

        Args:
            pairing_index (int): Index of the pairing slot to use.
            pairing_key (bytes): The shared pairing key (32 bytes).
        """
        self.secure_session = commands.open_secure_channel(
            self.transport,
            self._card_public_key,
            pairing_index,
            pairing_key,
        )

    def mutually_authenticate(self):
        """
        Performs mutual authentication between host and card.

        Raises:
            APDUError: If the authentication fails.
        """
        commands.mutually_authenticate(
            self.transport,
            self.secure_session,
        )

    def pair(self, shared_secret: bytes) -> tuple[int, bytes]:
        """
        Pairs with the card using an ECDH-derived shared secret.

        Args:
            shared_secret (bytes): 32-byte ECDH shared secret.

        Returns:
            tuple[int, bytes]: The pairing index and client cryptogram.
        """
        return commands.pair(self.transport, shared_secret)

    def verify_pin(self, pin: str) -> bool:
        """
        Verifies the user PIN with the card.

        Args:
            pin (str): The user-entered PIN.

        Returns:
            bool: True if PIN is valid, otherwise False.
        """
        return commands.verify_pin(self.transport, self.secure_session, pin)

    def unpair(self, index: int):
        """
        Removes a pairing slot from the card.

        Args:
            index (int): Index of the pairing slot to remove.
        """
        commands.unpair(
            transport=self.transport,
            session=self.secure_session,
            index=index,
        )
