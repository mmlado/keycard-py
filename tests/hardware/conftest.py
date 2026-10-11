"""
Hardware tests, run against a real card only when asked:

    KEYCARD_READER=0 pytest tests/hardware

KEYCARD_READER is the index of the PC/SC reader. Tests marked
``destructive`` factory-reset and initialize the card, and also need
KEYCARD_DESTRUCTIVE=1. Development cards must carry a Test CA certificate
(see tools/load_test_identity.py).
"""
import os

import pytest

from keycard import constants
from keycard.keycard import KeyCard
from keycard.secure_channel import SecureChannelVersion
from keycard.transport import Transport

READER = os.environ.get('KEYCARD_READER')
DESTRUCTIVE = os.environ.get('KEYCARD_DESTRUCTIVE')

PIN = '123456'
PUK = '987654321098'
PAIRING_SECRET = 'KeycardTest'


def pytest_collection_modifyitems(config, items):
    for item in items:
        if 'card' in item.keywords and READER is None:
            item.add_marker(pytest.mark.skip(
                reason='set KEYCARD_READER to run hardware tests'))
        elif 'destructive' in item.keywords and not DESTRUCTIVE:
            item.add_marker(pytest.mark.skip(
                reason='set KEYCARD_DESTRUCTIVE=1 to reset the card'))


@pytest.fixture
def keycard():
    transport = Transport()
    transport.connect(int(READER))
    card = KeyCard(
        transport,
        ca_public_keys=[
            constants.OFFICIAL_CA_PUBLIC_KEY,
            constants.TEST_CA_PUBLIC_KEY,
        ],
    )
    card.select()
    yield card
    transport.disconnect()


@pytest.fixture
def reset_keycard(keycard):
    # An uninitialized 3.x card accepts only INIT, so it is already reset.
    if keycard.is_initialized:
        keycard.factory_reset()
    keycard.select()
    return keycard


@pytest.fixture
def verified_keycard(reset_keycard):
    keycard = reset_keycard
    if keycard.secure_channel_version == SecureChannelVersion.V2:
        keycard.init(PIN, PUK)
    else:
        keycard.init(PIN, PUK, PAIRING_SECRET)
        keycard.select()
        keycard.pair(PAIRING_SECRET)
        keycard.open_secure_channel()
    keycard.verify_pin(PIN)
    return keycard
