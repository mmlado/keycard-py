from . import constants
from . import commands
from .apdu import APDUResponse
from .exceptions import APDUError
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
        self.card_public_key = None
        self.session = None

    def select(self):
        """
        Selects the Keycard applet and retrieves application metadata.

        Returns:
            ApplicationInfo: Object containing ECC public key and card info.
        """
        info = commands.select(self)
        self.card_public_key = info.ecc_public_key
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
            self,
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
        return commands.ident(self, challenge)

    def open_secure_channel(self, pairing_index: int, pairing_key: bytes):
        """
        Opens a secure session with the card.

        Args:
            pairing_index (int): Index of the pairing slot to use.
            pairing_key (bytes): The shared pairing key (32 bytes).
        """
        self.session = commands.open_secure_channel(
            self,
            pairing_index,
            pairing_key,
        )

    def mutually_authenticate(self):
        """
        Performs mutual authentication between host and card.

        Raises:
            APDUError: If the authentication fails.
        """
        commands.mutually_authenticate(self)

    def pair(self, shared_secret: bytes) -> tuple[int, bytes]:
        """
        Pairs with the card using an ECDH-derived shared secret.

        Args:
            shared_secret (bytes): 32-byte ECDH shared secret.

        Returns:
            tuple[int, bytes]: The pairing index and client cryptogram.
        """
        return commands.pair(self, shared_secret)

    def verify_pin(self, pin: str) -> bool:
        """
        Verifies the user PIN with the card.

        Args:
            pin (str): The user-entered PIN.

        Returns:
            bool: True if PIN is valid, otherwise False.
        """
        return commands.verify_pin(self, pin)

    @property
    def status(self):
        """
        Retrieves the application status using the secure session.

        Returns:
            dict: A dictionary with:
                - pin_retry_count (int)
                - puk_retry_count (int)
                - initialized (bool)

        Raises:
            RuntimeError: If the secure session is not open.
        """
        if self.session is None:
            raise RuntimeError("Secure session not established")

        return commands.get_status(self)

    @property
    def get_key_path(self):
        """
        Returns the current key derivation path from the card.

        Returns:
            list of int: List of 32-bit integers representing the key path.

        Raises:
            RuntimeError: If the secure session is not open.
        """
        if self.session is None:
            raise RuntimeError("Secure session not established")

        return commands.get_status(self, key_path=True)


    def unpair(self, index: int):
        """
        Removes a pairing slot from the card.

        Args:
            index (int): Index of the pairing slot to remove.
        """
        commands.unpair(self, index)

    def factory_reset(self):
        """
        Sends the FACTORY_RESET command to the card.

        Raises:
            APDUError: If the card returns a failure status word.
        """
        commands.factory_reset(self)
        
    def generate_key(self) -> bytes:
        """
        Generates a new key on the card and returns the key UID.

        Returns:
            bytes: Key UID (SHA-256 of the public key)

        Raises:
            APDUError: If the response status word is not 0x9000
        """
        return commands.generate_key(self)
    
    
    def send_apdu(
        self,
        ins: int,
        p1: int=0x00,
        p2: int=0x00,
        data: bytes=b'',
        cla: int=None
    ) -> bytes:
        if cla == None:
            cla = constants.CLA_PROPRIETARY

        response: APDUResponse = self.transport.send_apdu(
            bytes([cla, ins, p1, p2, len(data)]) + data
        )
        
        if response.status_word != constants.SW_SUCCESS:
            raise APDUError(response.status_word)
        
        return bytes(response.data)
    
    def send_secure_apdu(
        self,
        ins: int,
        p1: int=0x00,
        p2: int=0x00,
        data: bytes=b''
    ) -> bytes:
        encrypted = self.session.wrap_apdu(
            cla=constants.CLA_PROPRIETARY,
            ins=ins,
            p1=p1,
            p2=p2,
            data=data
        )

        response: APDUResponse = self.transport.send_apdu(
            bytes([constants.CLA_PROPRIETARY, ins, p1, p2, len(encrypted)]) + encrypted
        )

        if response.status_word != 0x9000:
            raise APDUError(response.status_word)

        plaintext, sw = self.session.unwrap_response(response)

        if sw != 0x9000:
            raise APDUError(sw)
        
        return plaintext