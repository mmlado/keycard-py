from hashlib import sha256

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .. import constants
from ..apdu import APDUResponse
from ..exceptions import APDUError, InvalidResponseError, InvalidStateError
from .base import SecureChannelVersion

PROTOCOL_LABEL = b'sc_v2_ccm'
NONCE_SIZE = 13
TAG_SIZE = 8
MAX_COMMAND_PLAINTEXT = 247
SW_SECURE_CHANNEL_FAILURE = 0x6982


def transcript_digest(
    salt: bytes,
    client_public_key: bytes,
    card_public_key: bytes
) -> bytes:
    """
    SHA-256 of the handshake transcript the card signs.

    Returns:
        bytes: SHA-256("sc_v2_ccm" || salt || client key || card key).
    """
    return sha256(
        PROTOCOL_LABEL + salt + client_public_key + card_public_key
    ).digest()


class SecureChannelV2:
    """
    Secure Channel V2 (applet 4.x): AES-128-CCM with keys from an ECDHE
    handshake authenticated by the card's Identity Key.
    """

    def __init__(self, key_h2c: bytes, key_c2h: bytes) -> None:
        self._h2c = AESCCM(key_h2c, tag_length=TAG_SIZE)
        self._c2h = AESCCM(key_c2h, tag_length=TAG_SIZE)
        self._counter = 0
        self._open = True

    @classmethod
    def from_handshake(cls, salt: bytes, shared_x: bytes) -> 'SecureChannelV2':
        """
        Derives the session keys from the handshake.

        Args:
            salt (bytes): The 32-byte HKDF salt sent by the client.
            shared_x (bytes): X coordinate of the ECDH shared point.

        Returns:
            SecureChannelV2: An open channel.
        """
        okm = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=PROTOCOL_LABEL,
        ).derive(shared_x)
        return cls(okm[:16], okm[16:])

    @property
    def version(self) -> SecureChannelVersion:
        return SecureChannelVersion.V2

    @property
    def is_open(self) -> bool:
        return self._open

    def close(self) -> None:
        self._open = False

    def _nonce(self) -> bytes:
        return self._counter.to_bytes(NONCE_SIZE, 'big')

    def wrap(self, ins: int, p1: int, p2: int, data: bytes) -> bytes:
        """
        Encrypts a command as a SECURED APDU.

        Returns:
            bytes: The complete SECURED APDU.

        Raises:
            InvalidStateError: If the channel is closed.
            ValueError: If the command is too long for the channel.
        """
        if not self._open:
            raise InvalidStateError('Secure channel is closed')

        inner = bytes([
            constants.CLA_PROPRIETARY, ins, p1, p2, len(data)]) + data
        if len(inner) > MAX_COMMAND_PLAINTEXT:
            raise ValueError(
                f'Command too long for Secure Channel V2: {len(inner)} '
                f'bytes, maximum {MAX_COMMAND_PLAINTEXT}')

        payload = self._h2c.encrypt(self._nonce(), inner, None)
        return bytes([
            constants.CLA_PROPRIETARY,
            constants.INS_SECURED_APDU,
            0x00,
            0x00,
            len(payload),
        ]) + payload

    def unwrap(self, response: APDUResponse) -> bytes:
        """
        Verifies and decrypts a SECURED APDU response.

        Returns:
            bytes: The response data.

        Raises:
            APDUError: If the card returned a failure status word. A failure
                of the channel itself also closes it.
            InvalidResponseError: If the response does not verify; the
                channel is closed.
        """
        if response.status_word != constants.SW_SUCCESS:
            self.close()
            raise APDUError(response.status_word)

        try:
            plaintext = self._c2h.decrypt(
                self._nonce(), bytes(response.data), None)
        except InvalidTag as e:
            self.close()
            raise InvalidResponseError(
                'Secure channel response failed authentication') from e

        self._counter += 1

        if len(plaintext) < 2:
            self.close()
            raise InvalidResponseError(
                'Secure channel response has no status word')

        sw = int.from_bytes(plaintext[-2:], 'big')
        if sw != constants.SW_SUCCESS:
            raise APDUError(sw)
        return plaintext[:-2]
