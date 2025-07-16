from keycard.commands.factory_reset import factory_reset
from keycard.exceptions import APDUError
from unittest.mock import Mock

def test_factory_reset_success():
    mock_transport = Mock()
    mock_response = Mock()
    mock_response.status_word = 0x9000
    mock_transport.send_apdu.return_value = mock_response

    factory_reset(mock_transport)
    mock_transport.send_apdu.assert_called_once_with(
        bytes([0x80, 0xFD, 0xAA, 0x55])
    )

def test_factory_reset_failure():
    mock_transport = Mock()
    mock_response = Mock()
    mock_response.status_word = 0x6A80
    mock_transport.send_apdu.return_value = mock_response

    try:
        factory_reset(mock_transport)
        assert False, "Expected APDUError"
    except APDUError as e:
        assert e.sw == 0x6A80
