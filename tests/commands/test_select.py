import pytest
from unittest.mock import MagicMock, patch
from keycard.commands.select import select
from keycard.apdu import APDUResponse
from keycard.exceptions import APDUError
from keycard import constants


def test_select_success():
    dummy_info = MagicMock()
    response_data = b"\x01\x02\x03\x04"

    transport = MagicMock()
    transport.send_apdu.return_value = APDUResponse(response_data, constants.SW_SUCCESS)

    with patch("keycard.commands.select.ApplicationInfo.parse", return_value=dummy_info) as mock_parse:
        result = select(transport)

    expected_apdu = (
        bytes([
            constants.CLAISO7816,
            constants.INS_SELECT,
            0x04,
            0x00,
            len(constants.KEYCARD_AID)
        ]) + constants.KEYCARD_AID
    )

    transport.send_apdu.assert_called_once_with(expected_apdu)
    mock_parse.assert_called_once_with(response_data)
    assert result == dummy_info


def test_select_apdu_error():
    transport = MagicMock()
    transport.send_apdu.return_value = APDUResponse(b"", 0x6A82)

    with pytest.raises(APDUError) as excinfo:
        select(transport)

    assert excinfo.value.sw == 0x6A82
