from unittest.mock import MagicMock

from keycard import constants
from keycard.apdu import APDUResponse
from keycard.commands.get_status import get_status


def test_get_application_status():
    # TLV: A3 06 02 01 03 02 01 02 01 01
    response_data = bytes.fromhex("A309020103020102010101")
    response = APDUResponse(response_data, 0x9000)

    transport = MagicMock()
    transport.send_apdu.return_value = response

    session = MagicMock()
    session.wrap_apdu.return_value = (
        constants.CLA_PROPRIETARY,
        constants.INS_GET_STATUS,
        0x00,
        0x00,
        b''
    )
    session.unwrap_response.return_value = response_data, 0x9000

    result = get_status(transport, session)

    assert result['pin_retry_count'] == 3
    assert result['puk_retry_count'] == 2
    assert result['initialized'] is True


def test_get_key_path_status():
    key_path = [0x8000002C, 0x8000003C]
    raw_data = b"".join(i.to_bytes(4, "big") for i in key_path)
    response = APDUResponse(raw_data, 0x9000)

    transport = MagicMock()
    transport.send_apdu.return_value = response

    session = MagicMock()
    session.wrap_apdu.return_value = (
        constants.CLA_PROPRIETARY,
        constants.INS_GET_STATUS,
        0x01,
        0x00,
        b''
    )
    session.unwrap_response.return_value = raw_data, 0x9000

    result = get_status(transport, session, key_path=True)

    assert result == key_path
