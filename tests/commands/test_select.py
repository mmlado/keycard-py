import pytest
from unittest.mock import MagicMock, patch
from keycard.commands.select import select
from keycard.apdu import APDUResponse
from keycard.exceptions import APDUError
from keycard import constants


def test_select_success():
    dummy_info = MagicMock()
    response_data = b"\x01\x02\x03\x04"

    card = MagicMock()
    card.send_apdu.return_value = response_data

    with patch(
        "keycard.commands.select.ApplicationInfo.parse",
        return_value=dummy_info
    ) as mock_parse:
        result = select(card)

    card.send_apdu.assert_called_once_with(
        cla=constants.CLAISO7816,
        ins=constants.INS_SELECT,
        p1=0x04,
        p2=0x00,
        data=constants.KEYCARD_AID
    )
    mock_parse.assert_called_once_with(response_data)
    assert result == dummy_info


def test_select_apdu_error():
    card = MagicMock()
    card.send_apdu.side_effect = APDUError(0x6A82)

    with pytest.raises(APDUError) as excinfo:
        select(card)

    assert excinfo.value.sw == 0x6A82
