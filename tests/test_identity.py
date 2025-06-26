import os
import sys

import binascii

from keycard.exceptions import InvalidResponseError
from keycard.parsing.identity import Identity


sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


def test_parse_card_identity_valid():
    # Your known-good identity response
    cert = (
        '02cf86373c304339c1bf8c4bc4d9fd4c7b8b9cb8f1efc90d9d1668aa0bccb9794e'
        '36a89f6edf7dd38a205d977f995fd6226e5dfc6c54b1b83b7a7a3c5229df4da6'
        'e9104eec7c470a4ac4a5e264414f2752c6ead32ab607a82823520fc5cd9ad04d'
        '00'
    )

    # Signature: DER SEQUENCE of R + S
    sig = (
        '30'
        '44'
        '022036a89f6edf7dd38a205d977f995fd6226e5dfc6c54b1b83b7a7a3c5229df4da6'
        '0220e9104eec7c470a4ac4a5e264414f2752c6ead32ab607a82823520fc5cd9ad04d'
    )

    tlv = (
        '8a' + f"{len(cert)//2:02x}" + cert +
        '30' + sig[2:]  # skip the first byte (tag) as it’s already added
    )

    parsed = Identity.parse(binascii.unhexlify(tlv))

    assert isinstance(parsed, Identity)
    assert parsed.certificate[:1] == b'\x02'
    assert len(parsed.certificate) == 98
    assert parsed.signature[0] == 0x02


def test_parse_card_identity_missing_fields():
    bad_data = b'\x30\x02\x01\x02'  # No 0x8A tag
    try:
        Identity.parse(bad_data)
    except InvalidResponseError:
        assert True
    else:
        assert False, "Expected InvalidResponseError"
