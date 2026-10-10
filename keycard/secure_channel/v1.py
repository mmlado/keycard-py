from dataclasses import dataclass
from hashlib import sha512

from .. import constants
from ..apdu import APDUResponse
from ..crypto.aes import aes_cbc_encrypt, aes_cbc_decrypt
from ..exceptions import APDUError
from .base import SecureChannelVersion


@dataclass
class SecureChannelV1:
    """
    Secure Channel V1 (applet 3.x): AES-CBC encryption with AES-CBC-MAC,
    keyed from a pairing.

    Attributes:
        enc_key (bytes): The AES encryption key for the session.
        mac_key (bytes): The AES MAC key for message authentication.
        iv (bytes): The initialization vector for AES operations.
        authenticated (bool): Indicates if the session is authenticated.
    """
    enc_key: bytes
    mac_key: bytes
    iv: bytes
    authenticated: bool = False

    @classmethod
    def from_handshake(
        cls,
        shared_secret: bytes,
        pairing_key: bytes,
        salt: bytes,
        seed_iv: bytes
    ) -> "SecureChannelV1":
        """
        Derives the session keys from the handshake.

        Args:
            shared_secret (bytes): The shared secret used for key derivation.
            pairing_key (bytes): The pairing key used for key derivation.
            salt (bytes): The salt value used in the key derivation process.
            seed_iv (bytes): The initialization vector (IV) to seed the
                session.

        Returns:
            SecureChannelV1: A channel initialized with derived encryption
                and MAC keys, and the provided IV.
        """
        digest = sha512(shared_secret + pairing_key + salt).digest()
        enc_key, mac_key = digest[:32], digest[32:]
        return cls(
            enc_key=enc_key,
            mac_key=mac_key,
            iv=seed_iv,
            authenticated=True
        )

    @property
    def version(self) -> SecureChannelVersion:
        return SecureChannelVersion.V1

    @property
    def is_open(self) -> bool:
        return self.authenticated

    def wrap(self, ins: int, p1: int, p2: int, data: bytes) -> bytes:
        """
        Protects a command for sending.

        Returns:
            bytes: The complete command APDU.
        """
        cla = constants.CLA_PROPRIETARY
        payload = self.wrap_apdu(cla=cla, ins=ins, p1=p1, p2=p2, data=data)
        return bytes([cla, ins, p1, p2, len(payload)]) + payload

    def unwrap(self, response: APDUResponse) -> bytes:
        """
        Verifies and decrypts a response.

        Returns:
            bytes: The response data.

        Raises:
            APDUError: If the card returned a failure status word.
        """
        if response.status_word != constants.SW_SUCCESS:
            raise APDUError(response.status_word)

        plaintext, sw = self.unwrap_response(response)
        if sw != constants.SW_SUCCESS:
            raise APDUError(sw)

        return plaintext

    def wrap_apdu(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes
    ) -> bytes:
        """
        Wraps an APDU command with secure channel encryption and MAC.

        Args:
            cla (int): The APDU class byte.
            ins (int): The APDU instruction byte.
            p1 (int): The APDU parameter 1 byte.
            p2 (int): The APDU parameter 2 byte.
            data (bytes): The APDU data field to be encrypted.

        Returns:
            tuple[int, int, int, int, bytes]: The wrapped APDU as a tuple
                containing the class, instruction, parameter 1, parameter 2,
                and the concatenated MAC and encrypted data.

        Raises:
            ValueError: If the secure channel is not authenticated and the
                instruction is not 0x11.
        """
        if not self.authenticated and ins != 0x11:
            raise ValueError("Secure channel not authenticated")

        encrypted = aes_cbc_encrypt(self.enc_key, self.iv, data)

        lc = 16 + len(encrypted)
        mac_input = bytes([cla, ins, p1, p2, lc]) + bytes(11) + encrypted

        enc_data = aes_cbc_encrypt(
            self.mac_key, bytes(16), mac_input, padding=False)

        self.iv = enc_data[-16:]

        return self.iv + encrypted

    def unwrap_response(self, response: APDUResponse) -> tuple[bytes, int]:
        """
        Unwraps and verifies a secure channel response.

        Args:
            response (bytes): The encrypted response bytes to unwrap.

        Returns:
            tuple[bytes, int]: A tuple containing the decrypted plaintext
                (excluding the status word) and the status word as an integer.

        Raises:
            ValueError: If the secure channel is not authenticated.
            ValueError: If the response length is invalid.
            ValueError: If the MAC verification fails.
            ValueError: If the decrypted plaintext is too short to contain a
                status word.
        """
        if not self.authenticated:
            raise ValueError("Secure channel not authenticated")

        if len(response.data) < 18:
            raise ValueError("Invalid secure response length")

        received_mac = bytes(response.data[:16])
        encrypted = bytes(response.data[16:])

        # The card MACs only the low byte; a full response is 256 bytes.
        lr = len(response.data) & 0xFF
        mac_input = bytes([lr]) + bytes(15) + bytes(encrypted)
        expected_mac = aes_cbc_encrypt(
            self.mac_key, bytes(16), mac_input, padding=False)[-16:]
        if received_mac != expected_mac:
            raise ValueError("Invalid MAC")

        plaintext = aes_cbc_decrypt(self.enc_key, self.iv, encrypted)

        self.iv = received_mac

        if len(plaintext) < 2:
            raise ValueError("Missing status word in response")

        return plaintext[:-2], int.from_bytes(plaintext[-2:], "big")
