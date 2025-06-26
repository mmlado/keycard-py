"""
Provides ISO/IEC 9797-1 Padding Method 2 (ISO9797 M2) functions for block
cipher operations.
"""


def iso9797_m2_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Pads the input data according to ISO/IEC 9797-1 Padding Method 2 (also
    known as ISO/IEC 9797-1 Padding Method 2 or ISO 7816-4 padding).

    This method appends a single byte with the value 0x80 to the data,
    followed by zero or more bytes with the value 0x00, so that the total
    length of the padded data is a multiple of the block size.

    Args:
        data (bytes): The input data to be padded.
        block_size (int, optional): The block size to pad to. Defaults to 16.

    Returns:
        bytes: The padded data.
    """
    padding_len: int = block_size - (len(data) % block_size)
    padding: bytes = b'\x80' + b'\x00' * (padding_len - 1)

    return data + padding


def iso9797_m2_unpad(padded: bytes) -> bytes:
    """
    Remove ISO/IEC 9797-1 Padding Method 2 (ISO9797 M2) from the given byte
    sequence.

    This padding method appends a single byte 0x80 followed by zero or more
    0x00 bytes.
    The function locates the last occurrence of 0x80 and removes it along
    with any trailing 0x00 bytes.

    Args:
        padded (bytes): The padded byte sequence.

    Returns:
        bytes: The original unpadded byte sequence.

    Raises:
        ValueError: If the padding is invalid (i.e., 0x80 byte not found).
    """
    index: int = padded.rfind(b'\x80')
    if index == -1:
        raise ValueError("Invalid padding")

    return padded[:index]
