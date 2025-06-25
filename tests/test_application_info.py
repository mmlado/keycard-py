import os
import sys

import pytest

from keycard.exceptions import InvalidResponseError
from keycard.parsing.application_info import ApplicationInfo


sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


def test_parse_application_info_invalid_tlv():
    # No top-level 0xA4 tag
    with pytest.raises(InvalidResponseError):
        ApplicationInfo.parse(b'\xAA\x05\xBB\xCC\xDD')
