"""
This module defines constants used for communication with the Keycard applet
via APDU commands.
"""

# Applet AID
KEYCARD_AID: bytes = bytes.fromhex('A000000804000101')

CLAISO7816: int = 0x00
CLA_PROPRIETARY: int = 0x80

# APDU instructions
INS_SELECT: int = 0xA4
INS_INIT: int = 0xFE
INS_IDENT: int = 0x14
INS_OPEN_SECURE_CHANNEL: int = 0x10
INS_MUTUALLY_AUTHENTICATE: int = 0x11
INS_PAIR: int = 0x12

# Status words
SW_SUCCESS: int = 0x9000
