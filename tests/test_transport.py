import pytest
from unittest.mock import MagicMock, patch
from keycard.transport import Transport
from keycard.apdu import APDUResponse
from keycard.exceptions import TransportError


@patch("keycard.transport.readers")
def test_transport_connect_success(mock_readers):
    mock_connection = MagicMock()
    mock_reader = MagicMock()
    mock_reader.createConnection.return_value = mock_connection
    mock_readers.return_value = [mock_reader]

    transport = Transport()
    transport.connect()

    mock_readers.assert_called_once()
    mock_connection.connect.assert_called_once()
    assert transport.connection == mock_connection


@patch("keycard.transport.readers", return_value=[])
def test_transport_connect_no_reader(mock_readers):
    transport = Transport()
    with pytest.raises(TransportError, match="No smart card readers found"):
        transport.connect()


@patch("keycard.transport.readers")
def test_send_apdu_success(mock_readers):
    mock_connection = MagicMock()
    mock_connection.transmit.return_value = ([1, 2, 3], 0x90, 0x00)

    mock_reader = MagicMock()
    mock_reader.createConnection.return_value = mock_connection
    mock_readers.return_value = [mock_reader]

    transport = Transport()
    transport.connection = mock_connection

    apdu = b"\x00\xA4\x04\x00"
    response = transport.send_apdu(apdu)

    mock_connection.transmit.assert_called_once_with(list(apdu))
    assert isinstance(response, APDUResponse)
    assert response.data == [1, 2, 3]
    assert response.status_word == 0x9000


@patch("keycard.transport.readers")
def test_transport_context_manager(mock_readers):
    mock_connection = MagicMock()
    mock_reader = MagicMock()
    mock_reader.createConnection.return_value = mock_connection
    mock_readers.return_value = [mock_reader]

    with Transport() as transport:
        assert transport.connection == mock_connection

    mock_connection.disconnect.assert_called_once()
    assert transport.connection is None
