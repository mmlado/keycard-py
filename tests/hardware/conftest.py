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
from keycard.transport import Transport

READER = os.environ.get('KEYCARD_READER')
DESTRUCTIVE = os.environ.get('KEYCARD_DESTRUCTIVE')


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
