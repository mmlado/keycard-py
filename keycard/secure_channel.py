# keycard/secure_channel.py

from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Util.Padding import pad, unpad

from dataclasses import dataclass


@dataclass
class SecureSession:
    enc_key: bytes
    mac_key: bytes
    iv: bytes

    @staticmethod
    def derive_keys(
        shared_secret: bytes,
        pairing_key: bytes,
        salt: bytes
    ) -> tuple[bytes, bytes]:
        material = shared_secret + pairing_key + salt
        digest = SHA512.new(material).digest()
        return digest[:32], digest[32:]

    @classmethod
    def open(
        cls,
        shared_secret: bytes,
        pairing_key: bytes,
        salt: bytes,
        seed_iv: bytes
    ) -> "SecureSession":
        enc_key, mac_key = cls.derive_keys(shared_secret, pairing_key, salt)
        return cls(enc_key=enc_key, mac_key=mac_key, iv=seed_iv)

    def wrap_apdu(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes
    ) -> tuple[int, int, int, int, bytes]:
        from Crypto.Cipher import AES

        # Padding
        padded_data = pad(data, 16, style="iso7816")

        # Encrypt
        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv=self.iv)
        encrypted = cipher.encrypt(padded_data)

        # MAC input
        lc = len(encrypted)
        mac_input = bytes([cla, ins, p1, p2, lc]) + b"\x00" * 11 + encrypted

        # MAC
        mac_cipher = AES.new(self.mac_key, AES.MODE_CBC, iv=bytes(16))
        mac = mac_cipher.encrypt(mac_input)[-16:]

        # Update IV
        self.iv = mac

        # Construct final payload
        return cla, ins, p1, p2, mac + encrypted

    def unwrap_response(self, response: bytes) -> tuple[bytes, int]:
        # Split MAC and encrypted data
        if len(response) < 18:
            raise ValueError("Invalid secure response length")

        received_mac = response[:16]
        encrypted = response[16:]

        # Verify MAC
        lr = len(encrypted)
        mac_input = bytes([lr]) + b"\x00" * 15 + encrypted
        mac_cipher = AES.new(self.mac_key, AES.MODE_CBC, iv=bytes(16))
        expected_mac = mac_cipher.encrypt(mac_input)[-16:]

        if received_mac != expected_mac:
            raise ValueError("Invalid MAC")

        # Decrypt
        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv=self.iv)
        plaintext = unpad(cipher.decrypt(encrypted), 16, style="iso7816")

        # Update IV
        self.iv = received_mac

        # Extract SW
        if len(plaintext) < 2:
            raise ValueError("Missing status word in response")
        return plaintext[:-2], int.from_bytes(plaintext[-2:], "big")
