from unittest.mock import call

import pytest

from keycard.commands import store_data
from keycard import constants


def test_store_data_calls_send_secure_apdu_with_correct_args(card):
    store_data(card, b"hello", constants.StorageSlot.PUBLIC)

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_STORE_DATA,
        p1=constants.StorageSlot.PUBLIC.value,
        data=b'hello'
    )


def test_store_data_uses_default_slot(card):
    store_data(card, b'world')

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_STORE_DATA,
        p1=constants.StorageSlot.PUBLIC,
        data=b'world'
    )


def test_store_data_raises_value_error_on_too_long_data(card):
    with pytest.raises(ValueError, match="Data too long"):
        store_data(card, b'a' * 128, constants.StorageSlot.PUBLIC)


@pytest.mark.parametrize('version', [(3, 2), (3, 5), (4, 0), (4, 1)])
def test_store_ndef_in_chunks(card, version):
    card.version = version
    data = bytes(range(256)) * 2

    store_data(card, data[:300], constants.StorageSlot.NDEF)

    assert card.send_secure_apdu.call_args_list == [
        call(
            ins=constants.INS_STORE_DATA,
            p1=constants.StorageSlot.NDEF,
            p2=0,
            data=data[:220]
        ),
        call(
            ins=constants.INS_STORE_DATA,
            p1=constants.StorageSlot.NDEF,
            p2=55,
            data=data[220:300]
        ),
    ]


def test_store_ndef_single_chunk(card):
    card.version = (3, 2)

    store_data(card, b'\x00\x03abc', constants.StorageSlot.NDEF)

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_STORE_DATA,
        p1=constants.StorageSlot.NDEF,
        p2=0,
        data=b'\x00\x03abc'
    )


def test_store_ndef_too_long_sends_nothing(card):
    card.version = (3, 2)

    with pytest.raises(ValueError, match="NDEF data too long"):
        store_data(card, b'a' * 513, constants.StorageSlot.NDEF)

    card.send_secure_apdu.assert_not_called()


def test_store_ndef_before_3_2_is_single_apdu(card):
    card.version = (3, 1)

    store_data(card, b'\x00\x03abc', constants.StorageSlot.NDEF)

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_STORE_DATA,
        p1=constants.StorageSlot.NDEF.value,
        data=b'\x00\x03abc'
    )
