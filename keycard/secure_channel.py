# keycard/secure_channel.py

from hashlib import sha512

from .apdu import APDUResponse

from .crypto.aes import aes_cbc_encrypt, aes_cbc_decrypt
from .crypto.padding import iso7816_pad, iso7816_unpad

from dataclasses import dataclass


@dataclass
class SecureSession:
    """
    SecureSession manages a secure communication channel using AES encryption
    and MAC authentication.

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

    @staticmethod
    def derive_keys(
        shared_secret: bytes,
        pairing_key: bytes,
        salt: bytes
    ) -> tuple[bytes, bytes]:
        """
        Derives two cryptographic keys from the given shared secret,
        pairing key, and salt.

        Args:
            shared_secret (bytes): The shared secret used as input for key
                derivation.
            pairing_key (bytes): The pairing key used as input for key
                derivation.
            salt (bytes): The salt value used as input for key derivation.

        Returns:
            tuple[bytes, bytes]: A tuple containing two derived keys, each
                32 bytes in length.
        """


    @classmethod
    def open(
        cls,
        shared_secret: bytes,
        pairing_key: bytes,
        salt: bytes,
        seed_iv: bytes
    ) -> "SecureSession":
        """
        Opens a new SecureSession using the provided cryptographic parameters.

        Args:
            shared_secret (bytes): The shared secret used for key derivation.
            pairing_key (bytes): The pairing key used for key derivation.
            salt (bytes): The salt value used in the key derivation process.
            seed_iv (bytes): The initialization vector (IV) to seed the
                session.

        Returns:
            SecureSession: An instance of SecureSession initialized with
                derived encryption and MAC keys, and the provided IV.
        """
        digest = sha512(shared_secret + pairing_key + salt).digest()
        enc_key, mac_key = digest[:32], digest[32:]
        print(f"{enc_key.hex()=}")
        print(f"{mac_key.hex()=}")
        return cls(enc_key=enc_key, mac_key=mac_key, iv=seed_iv, authenticated=True)

    def wrap_apdu(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes
    ) -> tuple[int, int, int, int, bytes]:
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
        # self.enc_key = bytes.fromhex("f56582c3fdbe479ca208c4d453a68d5c0c9714355868360b320f667383bd4c77")
        # self.mac_key = bytes.fromhex("cee375c7285b3728854d870094cc20e4d1a2df0b9e5a0fee6b284c266fb7f07b")
        print(f"{self.enc_key.hex()=}")
        # self.iv = bytes.fromhex("84a0b0f6b779c28a0800cb3bc1dfbcfb")
        print(f"{self.iv.hex()=}")
        # data = bytes.fromhex("313233343536")
        print(f"{data.hex()=}")
        encrypted = aes_cbc_encrypt(self.enc_key, self.iv, data)
        print(f"{encrypted.hex()=}", len(encrypted))
        lc = 16 + len(encrypted)
        mac_input = bytes([cla, ins, p1, p2, lc]) + bytes(11) + encrypted
        print(f"{mac_input.hex()=}")
        print(f"{self.mac_key.hex()=}")
        enc_data = aes_cbc_encrypt(self.mac_key, bytes(16), mac_input, padding=False)
        print(f"{enc_data.hex()=}")
        self.iv = enc_data[-16:]
        print(f"{self.iv.hex()=}")

        return cla, ins, p1, p2, self.iv + encrypted

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

        received_mac = bytes(response[:16])
        encrypted = bytes(response[16:])

        lr = len(encrypted)
        mac_input = bytes([lr]) + b"\x00" * 15 + encrypted
        expected_mac = aes_cbc_encrypt(self.mac_key, bytes(16), mac_input)[-16:]

        if received_mac != expected_mac:
            raise ValueError("Invalid MAC")

        plaintext = aes_cbc_decrypt(self.enc_key, self.iv, encrypted)

        self.iv = received_mac

        if len(plaintext) < 2:
            raise ValueError("Missing status word in response")

        return plaintext[:-2], int.from_bytes(plaintext[-2:], "big")
