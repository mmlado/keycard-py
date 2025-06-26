def iso9797_m2_pad(data: bytes, block_size: int = 16) -> bytes:
    padding_len: int = block_size - (len(data) % block_size)
    padding: bytes = b'\x80' + b'\x00' * (padding_len - 1)

    return data + padding


def iso9797_m2_unpad(padded: bytes) -> bytes:
    index: int = padded.rfind(b'\x80')
    if index == -1:
        raise ValueError("Invalid padding")

    return padded[:index]
