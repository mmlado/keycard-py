"""
This module provides the KeyCard class, which implements an interface for
interacting with Keycard-compliant smart cards.
"""
from typing import Optional

from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Util.Padding import pad

from . import constants
from .apdu import APDUResponse, encode_lv
from .crypto.aes import aes_cbc_encrypt, derive_aes_key

from .crypto.ecc import (
    derive_shared_secret,
    export_uncompressed_public_key,
    generate_ephemeral_keypair,
    parse_uncompressed_public_key
)
from .exceptions import (
    APDUError,
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
        self.transport: Transport = transport
        self._card_public_key: Optional[bytes] = None

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
        P1: int = 0x04
        P2: int = 0x00
        aid: bytes = constants.KEYCARD_AID
        apdu: bytes = (
            bytes([constants.CLAISO7816, constants.INS_SELECT, P1, P2]) + aid
        )
        response: APDUResponse = self.transport.send_apdu(apdu)

        if response.status_word != constants.SW_SUCCESS:
            raise APDUError(response.status_word)

        info: ApplicationInfo = ApplicationInfo.parse(response.data)
        self._card_public_key = info.ecc_public_key

        return info

    def init(self, pin: bytes, puk: bytes, pairing_secret: bytes) -> None:
        """
        Initializes the card with the provided PIN, PUK, and pairing secret.

        This method performs the following steps:
        1. Checks if the card is selected.
        2. Generates an ephemeral ECC key pair.
        3. Derives a shared secret using ECDH with the card's public key.
        4. Derives an AES key from the shared secret.
        5. Concatenates and pads the PIN, PUK, and pairing secret.
        6. Encrypts the padded data using AES-CBC with a random IV.
        7. Constructs the APDU command with the public key, IV, and ciphertext.
        8. Sends the APDU to the card and checks the response status.

        Args:
            pin (bytes): The PIN code to initialize the card with.
            puk (bytes): The PUK code to initialize the card with.
            pairing_secret (bytes): The pairing secret for secure
            communication.

        Raises:
            NotSelectedError: If the card is not selected.
            ValueError: If the data to be sent exceeds the APDU size limit.
            APDUError: If the card returns an error status word.
        """
        if self._card_public_key is None:
            raise NotSelectedError("Card not selected. Call select() first.")

        ephemeral_key: ECC.EccKey = generate_ephemeral_keypair()
        our_pubkey_bytes: bytes = export_uncompressed_public_key(ephemeral_key)
        card_pubkey: ECC.EccKey = parse_uncompressed_public_key(
            self._card_public_key)
        shared_secret: bytes = derive_shared_secret(ephemeral_key, card_pubkey)
        aes_key: bytes = derive_aes_key(shared_secret)
        plaintext: bytes = pin + puk + pairing_secret
        plaintext_padded: bytes = pad(plaintext, 16, style="iso7816")
        iv: bytes = get_random_bytes(16)
        ciphertext: bytes = aes_cbc_encrypt(aes_key, iv, plaintext_padded)
        data: bytes = encode_lv(our_pubkey_bytes) + iv + ciphertext
        if len(data) > 255:
            raise ValueError("Data too long for single APDU")

        apdu: bytes = (
            bytes(
                [
                    constants.CLA_PROPRIETARY,
                    constants.INS_INIT,
                    0x00,
                    0x00,
                    len(data),
                ]
            )
            + data
        )

        response: APDUResponse = self.transport.send_apdu(apdu)

        if response.status_word != constants.SW_SUCCESS:
            raise APDUError(response.status_word)

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

        return Identity.parse(response.data)

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
        if not self.public_key:
            raise NotSelectedError("Card not selected or missing public key")

        ephemeral_key = ECC.generate(curve="secp256k1")
        eph_pub_bytes = ephemeral_key.public_key().export_key(
            format='DER')[27:]

        response: APDUResponse = self.transport.send_apdu(
            bytes([
                constants.CLA_PROPRIETARY,
                constants.INS_OPEN_SECURE_CHANNEL,
                pairing_index,
                0x00,
                len(eph_pub_bytes)
            ]) + eph_pub_bytes
        )

        salt = response.data[:32]
        seed_iv = response.data[32:]

        shared_secret = derive_shared_secret(ephemeral_key, self.public_key)

        digest = SHA512.new()
        digest.update(shared_secret + pairing_key + salt)
        session_bytes = digest.digest()

        enc_key = session_bytes[:32]
        mac_key = session_bytes[32:]

        self.secure_session = SecureSession(
            enc_key=enc_key,
            mac_key=mac_key,
            iv=seed_iv
        )
