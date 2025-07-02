from Crypto.Hash import SHA512


def derive_session_keys(
    shared_secret: bytes,
    pairing_key: bytes,
    salt: bytes
) -> tuple[bytes, bytes]:
    """
    Derives session encryption and MAC keys from the given shared secret,
    pairing key, and salt.

    Args:
        shared_secret (bytes): The shared secret established between parties.
        pairing_key (bytes): The pairing key used for additional key material.
        salt (bytes): A salt value to ensure uniqueness of the derived keys.

    Returns:
        tuple[bytes, bytes]: A tuple containing the encryption key and MAC
            key, each 32 bytes long.
    """
    concat = shared_secret + pairing_key + salt
    h = SHA512.new(concat).digest()
    return h[:32], h[32:]  # (encryption_key, mac_key)
