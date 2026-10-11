from unittest.mock import call

import pytest
from keycard.commands.get_data import get_data
from keycard import constants
from keycard.exceptions import InvalidResponseError


def test_get_data_secure_channel(card):
    card.is_secure_channel_open = True
    card.send_secure_apdu.return_value = b"secure_data"
    result = get_data(card, slot=constants.StorageSlot.PUBLIC)
    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_GET_DATA,
        p1=constants.StorageSlot.PUBLIC,
        p2=0,
    )
    assert result == card.send_secure_apdu.return_value


def test_get_data_proprietary_channel(card):
    card.is_secure_channel_open = False
    card.version = (3, 2)
    card.send_apdu.return_value = b"proprietary_data"
    result = get_data(card, slot=constants.StorageSlot.NDEF)
    card.send_apdu.assert_called_once_with(
        ins=constants.INS_GET_DATA,
        p1=constants.StorageSlot.NDEF.value,
        p2=0,
        cla=constants.CLA_PROPRIETARY
    )
    assert result == card.send_apdu.return_value


def test_get_data_invalid_slot(card):
    with pytest.raises(AttributeError):
        get_data(card, slot="INVALID_SLOT")


def test_get_ndef_segmented(card):
    card.is_secure_channel_open = True
    card.version = (4, 0)
    ndef = (298).to_bytes(2, 'big') + bytes(range(256)) + bytes(42)
    card.send_secure_apdu.side_effect = [ndef[:244], ndef[244:]]

    result = get_data(card, slot=constants.StorageSlot.NDEF)

    assert result == ndef
    assert card.send_secure_apdu.call_args_list == [
        call(ins=constants.INS_GET_DATA, p1=constants.StorageSlot.NDEF, p2=0),
        call(ins=constants.INS_GET_DATA, p1=constants.StorageSlot.NDEF, p2=61),
    ]


def test_get_ndef_single_segment(card):
    card.is_secure_channel_open = True
    card.version = (4, 0)
    card.send_secure_apdu.return_value = b'\x00\x03abc'

    assert get_data(card, slot=constants.StorageSlot.NDEF) == b'\x00\x03abc'
    card.send_secure_apdu.assert_called_once()


def test_get_ndef_before_4_0_reads_once(card):
    card.is_secure_channel_open = True
    card.version = (3, 2)
    first = (298).to_bytes(2, 'big') + bytes(221)
    card.send_secure_apdu.return_value = first

    assert get_data(card, slot=constants.StorageSlot.NDEF) == first
    card.send_secure_apdu.assert_called_once()


def test_get_ndef_missing_length_header(card):
    card.is_secure_channel_open = True
    card.version = (4, 0)
    card.send_secure_apdu.return_value = b'\x00'

    with pytest.raises(InvalidResponseError, match="length header"):
        get_data(card, slot=constants.StorageSlot.NDEF)


def test_get_ndef_empty_segment(card):
    card.is_secure_channel_open = True
    card.version = (4, 0)
    card.send_secure_apdu.side_effect = [b'\x01\x00' + bytes(2), b'']

    with pytest.raises(InvalidResponseError, match="empty NDEF segment"):
        get_data(card, slot=constants.StorageSlot.NDEF)


def test_get_ndef_unaligned_segment(card):
    card.is_secure_channel_open = True
    card.version = (4, 0)
    card.send_secure_apdu.return_value = b'\x01\x00' + bytes(3)

    with pytest.raises(InvalidResponseError, match="not aligned"):
        get_data(card, slot=constants.StorageSlot.NDEF)
